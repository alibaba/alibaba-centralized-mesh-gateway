package acmggen

import (
	"fmt"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	routerfilter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httpconn "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"istio.io/istio/pilot/pkg/acmg"
	"istio.io/istio/pilot/pkg/model"
	core2 "istio.io/istio/pilot/pkg/networking/core"
	"istio.io/istio/pilot/pkg/networking/core/v1alpha3"
	"istio.io/istio/pilot/pkg/networking/util"
	istiomatcher "istio.io/istio/pilot/pkg/security/authz/matcher"
	"istio.io/istio/pilot/pkg/util/protoconv"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/proto"
	"istio.io/istio/pkg/util/sets"
	"time"
)

type CoreProxyGenerator struct {
	ConfigGenerator core2.ConfigGenerator
}

func (p *CoreProxyGenerator) Generate(proxy *model.Proxy, w *model.WatchedResource, req *model.PushRequest) (model.Resources, model.XdsLogDetails, error) {
	var out model.Resources
	switch w.TypeUrl {
	case v3.ListenerType:
		sidecarListeners := p.ConfigGenerator.BuildListeners(proxy, req.Push)
		resources := model.Resources{}
		for _, c := range sidecarListeners {
			resources = append(resources, &discovery.Resource{
				Name:     c.Name,
				Resource: protoconv.MessageToAny(c),
			})
		}
		// build sidecar scope egress, useless
		out = append(p.buildCoreProxyListeners(proxy, req.Push), resources...)
		// coreproxy outbound, useless
		out = append(out, outboundTunnelListener("tunnel", proxy.Metadata.ServiceAccount))
	case v3.ClusterType:
		sidecarClusters, _ := p.ConfigGenerator.BuildClusters(proxy, req)
		coreproxyClusters := p.buildClusters(proxy, req.Push)
		out = append(coreproxyClusters, sidecarClusters...)
	}
	return out, model.DefaultXdsLogDetails, nil
}

func getActualWildcardAndLocalHost(node *model.Proxy) string {
	if node.SupportsIPv4() {
		return v1alpha3.WildcardAddress // , v1alpha3.LocalhostAddress
	}
	return v1alpha3.WildcardIPv6Address //, v1alpha3.LocalhostIPv6Address
}

// 关于sidecar scope，暂时不考虑
func (p *CoreProxyGenerator) buildCoreProxyListeners(proxy *model.Proxy, push *model.PushContext) model.Resources {
	saWorkloads := push.AcmgIndex.Workloads.ByIdentity[proxy.VerifiedIdentity.String()]
	if len(saWorkloads) == 0 {
		log.Warnf("no workloads for sa %s (proxy %s)", proxy.VerifiedIdentity.String(), proxy.ID)
		return nil
	}
	wildcard := getActualWildcardAndLocalHost(proxy)
	vhost := &route.VirtualHost{
		Name:    "connect",
		Domains: []string{"*"},
	}
	for _, egressListener := range proxy.SidecarScope.EgressListeners {
		for _, service := range egressListener.Services() {
			for _, port := range service.Ports {
				if port.Protocol == protocol.UDP {
					continue
				}
				bind := wildcard
				if !port.Protocol.IsHTTP() {
					// TODO: this is not 100% accurate for custom cases
					bind = service.GetAddressForProxy(proxy)
				}

				// This essentially mirrors the sidecar case for serviceEntries have no VIP.  In the waypoint proxy, we
				// don't know the ServiceEntry's VIP, so instead we search for a matching ServiceEntry host
				// for any remaining unmatched outbund to *:<port>
				authorityHost := service.GetAddressForProxy(proxy)
				if authorityHost == "0.0.0.0" {
					authorityHost = "*"
				}
				name := fmt.Sprintf("%s_%d", bind, port.Port)
				vhost.Routes = append(vhost.Routes, &route.Route{
					Match: &route.RouteMatch{
						PathSpecifier: &route.RouteMatch_ConnectMatcher_{ConnectMatcher: &route.RouteMatch_ConnectMatcher{}},
						Headers: []*route.HeaderMatcher{
							istiomatcher.HeaderMatcher(":authority", fmt.Sprintf("%s:%d", authorityHost, port.Port)),
						},
					},
					Action: &route.Route_Route{Route: &route.RouteAction{
						UpgradeConfigs: []*route.RouteAction_UpgradeConfig{{
							UpgradeType:   "CONNECT",
							ConnectConfig: &route.RouteAction_UpgradeConfig_ConnectConfig{},
						}},

						ClusterSpecifier: &route.RouteAction_Cluster{Cluster: name},
					}},
				})
			}
		}
	}
	l := &listener.Listener{
		Name:    "waypoint_outbound l",
		Address: ipPortAddress("0.0.0.0", NodeProxyOutboundCapturePort),

		AccessLog: accessLogString("waypoint_outbound"),
		FilterChains: []*listener.FilterChain{
			{
				Name: "waypoint_outbound fc",

				TransportSocket: &core.TransportSocket{
					Name: "envoy.transport_sockets.tls",
					ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&tls.DownstreamTlsContext{
						CommonTlsContext: buildCommonTLSContext(proxy, nil, push, true),
					})},
				},
				Filters: []*listener.Filter{{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &listener.Filter_TypedConfig{
						TypedConfig: protoconv.MessageToAny(&httpconn.HttpConnectionManager{
							AccessLog:  accessLogString("waypoint hcm"),
							StatPrefix: "outbound_hcm",
							RouteSpecifier: &httpconn.HttpConnectionManager_RouteConfig{
								RouteConfig: &route.RouteConfiguration{
									Name:             "local_route",
									VirtualHosts:     []*route.VirtualHost{vhost},
									ValidateClusters: proto.BoolFalse,
								},
							},
							HttpFilters: []*httpconn.HttpFilter{{
								Name:       "envoy.filters.http.router",
								ConfigType: &httpconn.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(&routerfilter.Router{})},
							}},
							Http2ProtocolOptions: &core.Http2ProtocolOptions{
								AllowConnect: true,
							},
							UpgradeConfigs: []*httpconn.HttpConnectionManager_UpgradeConfig{{
								UpgradeType: "CONNECT",
							}},
						}),
					},
				}},
			},
		},
	}
	var out model.Resources
	for _, l := range []*listener.Listener{l} {
		out = append(out, &discovery.Resource{
			Name:     l.Name,
			Resource: protoconv.MessageToAny(l),
		})
	}
	return out
}

func (p *CoreProxyGenerator) buildClusters(node *model.Proxy, push *model.PushContext) model.Resources {
	// TODO passthrough and blackhole
	var clusters []*cluster.Cluster
	wildcard := getActualWildcardAndLocalHost(node)
	seen := sets.String{}
	// TODO，暂时不考虑SidecarScope的情况
	for _, egressListener := range node.SidecarScope.EgressListeners {
		for _, service := range egressListener.Services() {
			for _, port := range service.Ports {
				if port.Protocol == protocol.UDP {
					continue
				}
				bind := wildcard
				if !port.Protocol.IsHTTP() {
					// TODO: this is not 100% accurate for custom cases
					bind = service.GetAddressForProxy(node)
				}
				name := fmt.Sprintf("%s_%d", bind, port.Port)
				if seen.Contains(name) {
					continue
				}
				seen.Insert(name)
				clusters = append(clusters, &cluster.Cluster{
					Name:                 name,
					ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STATIC},
					LoadAssignment: &endpoint.ClusterLoadAssignment{
						ClusterName: name,
						Endpoints: []*endpoint.LocalityLbEndpoints{{
							LbEndpoints: []*endpoint.LbEndpoint{{
								HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{Address: util.BuildInternalAddress(name)}},
								Metadata:       nil, // TODO metadata for passthrough
							}},
						}},
					},
				})
			}
		}
	}

	clusters = append(clusters, outboundTunnelCluster(node, push, node.Metadata.ServiceAccount, nil))
	var out model.Resources
	for _, c := range clusters {
		out = append(out, &discovery.Resource{Name: c.Name, Resource: protoconv.MessageToAny(c)})
	}
	return out
}

// outboundTunnelCluster is per-workload SA, but requires one workload that uses that SA so we can send the Pod UID
func outboundTunnelCluster(proxy *model.Proxy, push *model.PushContext, sa string, workload *acmg.Workload) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 outboundTunnelClusterName(sa),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_ORIGINAL_DST},
		LbPolicy:             cluster.Cluster_CLUSTER_PROVIDED,
		ConnectTimeout:       durationpb.New(2 * time.Second),
		CleanupInterval:      durationpb.New(60 * time.Second),
		LbConfig: &cluster.Cluster_OriginalDstLbConfig_{
			OriginalDstLbConfig: &cluster.Cluster_OriginalDstLbConfig{UseHttpHeader: true},
		},
		TypedExtensionProtocolOptions: h2connectUpgrade(),
		TransportSocket: &core.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&tls.UpstreamTlsContext{
				CommonTlsContext: buildCommonTLSContext(proxy, workload, push, false),
			})},
		},
	}
}
