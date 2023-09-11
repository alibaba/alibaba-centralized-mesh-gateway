package acmggen

import (
	"fmt"
	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fileaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	routerfilter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	originaldst "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/original_dst/v3"
	originalsrc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/original_src/v3"
	httpconn "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	http "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	any "google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	wrappers "google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/acmg"
	"istio.io/istio/pilot/pkg/model"
	istionetworking "istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pilot/pkg/networking/core/v1alpha3/match"
	"istio.io/istio/pilot/pkg/networking/plugin/authn"
	"istio.io/istio/pilot/pkg/networking/util"
	security "istio.io/istio/pilot/pkg/security/model"
	"istio.io/istio/pilot/pkg/util/protoconv"
	xdsfilters "istio.io/istio/pilot/pkg/xds/filters"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/util/sets"
	istiolog "istio.io/pkg/log"
	"strconv"
	"strings"
	"time"
)

var log = istiolog.RegisterScope("acmggen", "xDS Generator for acmg clients")

type NodeProxyConfigGenerator struct {
	EndpointIndex *model.EndpointIndex
	Workloads     acmg.AcmgCache
}

const (
	NodeProxyOutboundCapturePort         uint32 = 15001
	NodeProxyInbound2CapturePort         uint32 = 15006
	NodeProxyInboundNodeLocalCapturePort uint32 = 15088
	NodeProxyInboundCapturePort          uint32 = 15008

	// OriginalSrcMark TODO: this needs to match the mark in the iptables rules.
	// And also not clash with any other mark on the host level.
	// either figure out a way to not hardcode it, or a way to not use it.
	// i think the best solution is to have this mark configurable and run the
	// iptables rules from the code, so we are sure the mark matches.
	OriginalSrcMark = 0x4d2
	OutboundMark    = 0x401
	InboundMark     = 0x402
)

// these exist on syscall package, but only on linux.
// copy these here so this file can build on any platform
const (
	SolSocket = 0x1
	SoMark    = 0x24
)

func (g *NodeProxyConfigGenerator) Generate(
	proxy *model.Proxy,
	w *model.WatchedResource,
	req *model.PushRequest,
) (model.Resources, model.XdsLogDetails, error) {
	push := req.Push
	switch w.TypeUrl {
	case v3.ListenerType:
		return g.BuildListeners(proxy, push, w.ResourceNames), model.DefaultXdsLogDetails, nil
	case v3.ClusterType:
		return g.BuildClusters(proxy, push, w.ResourceNames), model.DefaultXdsLogDetails, nil
	case v3.EndpointType:
		return g.BuildEndpoints(proxy, push, w.ResourceNames), model.DefaultXdsLogDetails, nil
	}

	return nil, model.DefaultXdsLogDetails, nil
}

// parseToCoreProxyClusterName parses cluster names, in the format {%s_to_coreproxy, sa} where src are identities
func parseToCoreProxyClusterName(name string) (src string, ok bool) {
	p := strings.Split(name, "_")
	if len(p) != 3 || p[1] != "to" || p[2] != "coreproxy" {
		return "", false
	}
	return p[0], true
}

func (g *NodeProxyConfigGenerator) BuildEndpoints(proxy *model.Proxy, push *model.PushContext, names []string) model.Resources {
	out := model.Resources{}
	// nodeproxy to coreproxy
	for _, clusterName := range names {
		src, ok := parseToCoreProxyClusterName(clusterName)
		log.Infof("Build cluster for %v to coreproxy", src)
		if !ok {
			continue
		}
		out = append(out, &discovery.Resource{
			Name: clusterName,
			Resource: protoconv.MessageToAny(&endpoint.ClusterLoadAssignment{
				ClusterName: clusterName,
				Endpoints:   buildCoreProxyLbEndpoints(push),
			}),
		})
	}
	return out
}

func (g *NodeProxyConfigGenerator) buildVirtualInboundCluster() *discovery.Resource {
	c := &cluster.Cluster{
		Name:                 "virtual_inbound",
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_ORIGINAL_DST},
		LbPolicy:             cluster.Cluster_CLUSTER_PROVIDED,
		LbConfig: &cluster.Cluster_OriginalDstLbConfig_{
			OriginalDstLbConfig: &cluster.Cluster_OriginalDstLbConfig{
				UseHttpHeader: true,
			},
		},
	}
	return &discovery.Resource{
		Name:     c.Name,
		Resource: protoconv.MessageToAny(c),
	}
}

func (g *NodeProxyConfigGenerator) buildVirtualInboundClusterHBONE() *discovery.Resource {
	c := &cluster.Cluster{
		Name:                 "virtual_inbound_hbone",
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_ORIGINAL_DST},
		LbPolicy:             cluster.Cluster_CLUSTER_PROVIDED,
		LbConfig: &cluster.Cluster_OriginalDstLbConfig_{
			OriginalDstLbConfig: &cluster.Cluster_OriginalDstLbConfig{
				UseHttpHeader:        true,
				UpstreamPortOverride: &wrappers.UInt32Value{Value: NodeProxyInboundCapturePort},
			},
		},
	}
	return &discovery.Resource{
		Name:     c.Name,
		Resource: protoconv.MessageToAny(c),
	}
}

func blackholeCluster(push *model.PushContext) *discovery.Resource {
	c := &cluster.Cluster{
		Name:                 util.BlackHoleCluster,
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STATIC},
		ConnectTimeout:       push.Mesh.ConnectTimeout,
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
	}
	return &discovery.Resource{
		Name:     c.Name,
		Resource: protoconv.MessageToAny(c),
	}
}

func passthroughCluster(push *model.PushContext) *discovery.Resource {
	c := &cluster.Cluster{
		Name:                 util.PassthroughCluster,
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_ORIGINAL_DST},
		ConnectTimeout:       push.Mesh.ConnectTimeout,
		LbPolicy:             cluster.Cluster_CLUSTER_PROVIDED,
		// TODO protocol options are copy-paste from v1alpha3 package
		TypedExtensionProtocolOptions: map[string]*any.Any{
			v3.HttpProtocolOptionsType: protoconv.MessageToAny(&http.HttpProtocolOptions{
				UpstreamProtocolOptions: &http.HttpProtocolOptions_UseDownstreamProtocolConfig{
					UseDownstreamProtocolConfig: &http.HttpProtocolOptions_UseDownstreamHttpConfig{
						HttpProtocolOptions: &core.Http1ProtocolOptions{},
						Http2ProtocolOptions: &core.Http2ProtocolOptions{
							// Envoy default value of 100 is too low for data path.
							MaxConcurrentStreams: &wrappers.UInt32Value{
								Value: 1073741824,
							},
						},
					},
				},
			}),
		},
	}
	return &discovery.Resource{Name: c.Name, Resource: protoconv.MessageToAny(c)}
}

func (g *NodeProxyConfigGenerator) BuildClusters(proxy *model.Proxy, push *model.PushContext, names []string) model.Resources {
	var out model.Resources
	var clusters []*cluster.Cluster
	seen := sets.String{}
	for _, sourceWl := range push.AcmgIndex.Workloads.NodeLocal(proxy.Metadata.NodeName) {
		clusterName := toCoreProxyClusterName(sourceWl.Identity())
		if !seen.InsertContains(clusterName) {
			clusters = append(clusters, &cluster.Cluster{
				Name:                 clusterName,
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
				LbPolicy:             cluster.Cluster_ROUND_ROBIN,
				ConnectTimeout:       durationpb.New(2 * time.Second),
				//LbConfig: &cluster.Cluster_OriginalDstLbConfig_{
				//	OriginalDstLbConfig: &cluster.Cluster_OriginalDstLbConfig{
				//		UpstreamPortOverride: NodeProxyInboundCapturePort,
				//	},
				//},
				TypedExtensionProtocolOptions: h2connectUpgrade(),
				TransportSocket: &core.TransportSocket{
					Name: "envoy.transport_sockets.tls",
					ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&tls.UpstreamTlsContext{
						CommonTlsContext: buildCommonTLSContext(proxy, &sourceWl, push, false),
					})},
				},
				EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{
					EdsConfig: &core.ConfigSource{
						ConfigSourceSpecifier: &core.ConfigSource_Ads{
							Ads: &core.AggregatedConfigSource{},
						},
						InitialFetchTimeout: durationpb.New(0),
						ResourceApiVersion:  core.ApiVersion_V3,
					},
				},
			})
		}
	}
	for _, c := range clusters {
		out = append(out, &discovery.Resource{
			Name:     c.Name,
			Resource: protoconv.MessageToAny(c),
		})
	}
	out = append(out,
		g.buildVirtualInboundCluster(),
		g.buildVirtualInboundClusterHBONE(),
		passthroughCluster(push),
		blackholeCluster(push))
	return out
}

func (g *NodeProxyConfigGenerator) BuildListeners(proxy *model.Proxy, push *model.PushContext, names []string) (out model.Resources) {
	out = append(out,
		g.buildPodOutboundCaptureListener(proxy, push),
		g.buildInboundCaptureListener(proxy, push),
		g.buildInboundPlaintextCaptureListener(proxy, push),
	)

	return out
}

func (g *NodeProxyConfigGenerator) buildInboundPlaintextCaptureListener(proxy *model.Proxy, push *model.PushContext) *discovery.Resource {
	// TODO L7 stuff (deny at l4 for l7 auth if there is a waypoint proxy for the dest workload)
	l := &listener.Listener{
		Name:           "nodeproxy_inbound_plaintext",
		UseOriginalDst: wrappers.Bool(true),
		ListenerFilters: []*listener.ListenerFilter{
			{
				Name: wellknown.OriginalDestination,
				ConfigType: &listener.ListenerFilter_TypedConfig{
					TypedConfig: protoconv.MessageToAny(&originaldst.OriginalDst{}),
				},
			},
			{
				Name: wellknown.OriginalSource,
				ConfigType: &listener.ListenerFilter_TypedConfig{
					TypedConfig: protoconv.MessageToAny(&originalsrc.OriginalSrc{
						Mark: OriginalSrcMark,
					}),
				},
			},
		},
		AccessLog: accessLogString("capture inbound listener plaintext"),
		SocketOptions: []*core.SocketOption{{
			Description: "Set socket mark to packets coming back from inbound listener",
			Level:       SolSocket,
			Name:        SoMark,
			Value: &core.SocketOption_IntValue{
				IntValue: InboundMark,
			},
			State: core.SocketOption_STATE_PREBIND,
		}},
		Address: &core.Address{Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				// TODO because of the port 15088 workaround, we need to use a redirect rule,
				// which means we can't bind to localhost. once we remove that workaround,
				// this can be changed back to 127.0.0.1
				Address: "0.0.0.0",
				PortSpecifier: &core.SocketAddress_PortValue{
					PortValue: NodeProxyInbound2CapturePort,
				},
			},
		}},
		Transparent: wrappers.Bool(true),
	}

	for _, workload := range push.AcmgIndex.Workloads.NodeLocal(proxy.Metadata.NodeName) {
		var filters []*listener.Filter
		filters = append(filters, &listener.Filter{
			Name: wellknown.TCPProxy,
			ConfigType: &listener.Filter_TypedConfig{
				TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
					StatPrefix:       util.BlackHoleCluster,
					ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: "virtual_inbound"},
				}),
			},
		})
		l.FilterChains = append(l.FilterChains, &listener.FilterChain{
			Name:             "inbound_" + workload.PodIP,
			FilterChainMatch: &listener.FilterChainMatch{PrefixRanges: matchIP(workload.PodIP)},
			Filters:          filters,
		})
	}
	// TODO cases where we passthrough
	l.FilterChains = append(l.FilterChains, blackholeFilterChain("inbound plaintext"))

	return &discovery.Resource{
		Name:     l.Name,
		Resource: protoconv.MessageToAny(l),
	}
}

func matchIP(addr string) []*core.CidrRange {
	return []*core.CidrRange{{
		AddressPrefix: addr,
		PrefixLen:     wrappers.UInt32(32),
	}}
}

func (g *NodeProxyConfigGenerator) buildInboundCaptureListener(proxy *model.Proxy, push *model.PushContext) *discovery.Resource {
	// TODO L7 stuff (deny at l4 for l7 auth if there is a waypoint proxy for the dest workload)

	l := &listener.Listener{
		Name:           "nodeproxy_inbound",
		UseOriginalDst: wrappers.Bool(true),
		ListenerFilters: []*listener.ListenerFilter{
			{
				Name: wellknown.OriginalDestination,
				ConfigType: &listener.ListenerFilter_TypedConfig{
					TypedConfig: protoconv.MessageToAny(&originaldst.OriginalDst{}),
				},
			},
			{
				Name: wellknown.OriginalSource,
				ConfigType: &listener.ListenerFilter_TypedConfig{
					TypedConfig: protoconv.MessageToAny(&originalsrc.OriginalSrc{
						Mark: OriginalSrcMark,
					}),
				},
			},
		},
		Transparent: wrappers.Bool(true),
		AccessLog:   accessLogString("capture inbound listener"),
		SocketOptions: []*core.SocketOption{{
			Description: "Set socket mark to packets coming back from inbound listener",
			Level:       SolSocket,
			Name:        SoMark,
			Value: &core.SocketOption_IntValue{
				IntValue: InboundMark,
			},
			State: core.SocketOption_STATE_PREBIND,
		}},
		Address: &core.Address{Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				// TODO because of the port 15088 workaround, we need to use a redirect rule,
				// which means we can't bind to localhost. once we remove that workaround,
				// this can be changed back to 127.0.0.1
				Address: "0.0.0.0",
				PortSpecifier: &core.SocketAddress_PortValue{
					PortValue: NodeProxyInboundCapturePort,
				},
			},
		}},
	}

	for _, workload := range push.AcmgIndex.Workloads.NodeLocal(proxy.Metadata.NodeName) {
		if workload.Labels[model.TunnelLabel] != model.TunnelH2 {
			var filters []*listener.Filter
			var httpConnFilters []*httpconn.HttpFilter
			httpConnFilters = append(httpConnFilters, push.Telemetry.HTTPFilters(proxy, istionetworking.ListenerClassSidecarInbound)...)
			httpConnFilters = append(httpConnFilters, &httpconn.HttpFilter{
				Name:       "envoy.filters.http.router",
				ConfigType: &httpconn.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(&routerfilter.Router{})},
			})
			filters = append(filters, &listener.Filter{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: protoconv.MessageToAny(&httpconn.HttpConnectionManager{
						AccessLog:  accessLogString("inbound hcm"),
						CodecType:  0,
						StatPrefix: "inbound_hcm_" + workload.PodIP,
						RouteSpecifier: &httpconn.HttpConnectionManager_RouteConfig{
							RouteConfig: &route.RouteConfiguration{
								Name: "local_route",
								VirtualHosts: []*route.VirtualHost{{
									Name:    "local_service",
									Domains: []string{"*"},
									Routes: []*route.Route{{
										Match: &route.RouteMatch{PathSpecifier: &route.RouteMatch_ConnectMatcher_{
											ConnectMatcher: &route.RouteMatch_ConnectMatcher{},
										}},
										Action: &route.Route_Route{
											Route: &route.RouteAction{
												UpgradeConfigs: []*route.RouteAction_UpgradeConfig{{
													UpgradeType:   "CONNECT",
													ConnectConfig: &route.RouteAction_UpgradeConfig_ConnectConfig{},
												}},
												ClusterSpecifier: &route.RouteAction_Cluster{
													Cluster: "virtual_inbound",
												},
											},
										},
									}},
								}},
							},
						},
						// TODO rewrite destination port to original_dest port
						HttpFilters: httpConnFilters,
						Http2ProtocolOptions: &core.Http2ProtocolOptions{
							AllowConnect: true,
						},
						UpgradeConfigs: []*httpconn.HttpConnectionManager_UpgradeConfig{{
							UpgradeType: "CONNECT",
						}},
					}),
				},
			})
			l.FilterChains = append(l.FilterChains, &listener.FilterChain{
				Name:             "inbound_" + workload.PodIP,
				FilterChainMatch: &listener.FilterChainMatch{PrefixRanges: matchIP(workload.PodIP)},
				TransportSocket: &core.TransportSocket{
					Name: "envoy.transport_sockets.tls",
					ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&tls.DownstreamTlsContext{
						CommonTlsContext: buildCommonTLSContext(proxy, &workload, push, true),
					})},
				},
				Filters: filters,
			})
		} else {
			// Pod is already handling HBONE, and this is an HBONE request. Pass it through directly.
			l.FilterChains = append(l.FilterChains, &listener.FilterChain{
				Name:             "inbound_" + workload.PodIP,
				FilterChainMatch: &listener.FilterChainMatch{PrefixRanges: matchIP(workload.PodIP)},
				Filters: []*listener.Filter{{
					Name: wellknown.TCPProxy,
					ConfigType: &listener.Filter_TypedConfig{
						TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
							StatPrefix: "virtual_inbound_hbone",
							AccessLog:  accessLogString("inbound passthrough"),
							ClusterSpecifier: &tcp.TcpProxy_Cluster{
								Cluster: "virtual_inbound_hbone",
							},
						}),
					},
				}},
			})
		}
	}
	// TODO cases where we passthrough
	l.FilterChains = append(l.FilterChains, blackholeFilterChain("inbound"))

	return &discovery.Resource{
		Name:     l.Name,
		Resource: protoconv.MessageToAny(l),
	}
}

func buildCommonTLSContext(proxy *model.Proxy, workload *acmg.Workload, push *model.PushContext, inbound bool) *tls.CommonTlsContext {
	ctx := &tls.CommonTlsContext{}
	// TODO san match
	security.ApplyToCommonTLSContext(ctx, proxy, nil, authn.TrustDomainsForValidation(push.Mesh), inbound)

	// TODO always use the below flow, always specify which workload
	if workload != nil {
		// present the workload cert if possible
		workloadSecret := workload.Identity()
		if workload.UID != "" {
			workloadSecret += "~" + workload.Name + "~" + workload.UID
		}
		ctx.TlsCertificateSdsSecretConfigs = []*tls.SdsSecretConfig{
			security.ConstructSdsSecretConfig(workloadSecret),
		}
	}
	ctx.AlpnProtocols = []string{"h2"}

	ctx.TlsParams = &tls.TlsParameters{
		// Ensure TLS 1.3 is used everywhere
		TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
		TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_3,
	}

	return ctx
}

func h2connectUpgrade() map[string]*any.Any {
	return map[string]*any.Any{
		v3.HttpProtocolOptionsType: protoconv.MessageToAny(&http.HttpProtocolOptions{
			UpstreamProtocolOptions: &http.HttpProtocolOptions_ExplicitHttpConfig_{ExplicitHttpConfig: &http.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &http.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
					Http2ProtocolOptions: &core.Http2ProtocolOptions{
						AllowConnect: true,
					},
				},
			}},
		}),
	}
}

func ipPortAddress(ip string, port uint32) *core.Address {
	return &core.Address{Address: &core.Address_SocketAddress{
		SocketAddress: &core.SocketAddress{
			Address: ip,
			PortSpecifier: &core.SocketAddress_PortValue{
				PortValue: port,
			},
		},
	}}
}

const EnvoyTextLogFormat = "[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% " +
	"%PROTOCOL%\" %RESPONSE_CODE% %RESPONSE_FLAGS% " +
	"%RESPONSE_CODE_DETAILS% %CONNECTION_TERMINATION_DETAILS% " +
	"\"%UPSTREAM_TRANSPORT_FAILURE_REASON%\" %BYTES_RECEIVED% %BYTES_SENT% " +
	"%DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQ(X-FORWARDED-FOR)%\" " +
	"\"%REQ(USER-AGENT)%\" \"%REQ(X-REQUEST-ID)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\" " +
	"%UPSTREAM_CLUSTER% %UPSTREAM_LOCAL_ADDRESS% %DOWNSTREAM_LOCAL_ADDRESS% " +
	"%DOWNSTREAM_REMOTE_ADDRESS% %REQUESTED_SERVER_NAME% %ROUTE_NAME% "

func accessLogString(prefix string) []*accesslog.AccessLog {
	inlineString := EnvoyTextLogFormat + prefix + "\n"
	return []*accesslog.AccessLog{{
		Name: "envoy.access_loggers.file",
		ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: protoconv.MessageToAny(&fileaccesslog.FileAccessLog{
			Path: "/dev/stdout",
			AccessLogFormat: &fileaccesslog.FileAccessLog_LogFormat{LogFormat: &core.SubstitutionFormatString{
				Format: &core.SubstitutionFormatString_TextFormatSource{TextFormatSource: &core.DataSource{Specifier: &core.DataSource_InlineString{
					InlineString: inlineString,
				}}},
			}},
		})},
	}}
}

func outboundTunnelClusterName(sa string) string {
	return "outbound_tunnel_clus_" + sa
}

// outboundTunnelListener is built for each ServiceAccount from pods on the node.
// This listener adds the original destination headers from the dynamic EDS metadata pass through.
// We build the listener per-service account so that it can point to the corresponding cluster that presents the correct cert.
func outboundTunnelListener(name string, sa string) *discovery.Resource {
	l := &listener.Listener{
		Name:              name,
		UseOriginalDst:    wrappers.Bool(false),
		ListenerSpecifier: &listener.Listener_InternalListener{InternalListener: &listener.Listener_InternalListenerConfig{}},
		ListenerFilters:   []*listener.ListenerFilter{xdsfilters.SetDstAddress},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: wellknown.TCPProxy,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
						StatPrefix:       name,
						AccessLog:        accessLogString("outbound tunnel"),
						ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: outboundTunnelClusterName(sa)},
						TunnelingConfig: &tcp.TcpProxy_TunnelingConfig{
							Hostname: "%DYNAMIC_METADATA(tunnel:destination)%",
							HeadersToAdd: []*core.HeaderValueOption{
								{Header: &core.HeaderValue{Key: "x-envoy-original-dst-host", Value: "%DYNAMIC_METADATA([\"tunnel\", \"destination\"])%"}},
							},
						},
					}),
				},
			}},
		}},
	}
	return &discovery.Resource{
		Name:     name,
		Resource: protoconv.MessageToAny(l),
	}
}

func passthroughFilterChain() *listener.FilterChain {
	return &listener.FilterChain{
		Name: util.PassthroughFilterChain,
		/// TODO no match – add one to make it so we only passthrough if strict mTLS to the destination is allowed
		Filters: []*listener.Filter{{
			Name: wellknown.TCPProxy,
			ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
				AccessLog:        accessLogString("passthrough"),
				StatPrefix:       util.PassthroughCluster,
				ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: util.PassthroughCluster},
			})},
		}},
	}
}

func buildCoreProxyLbEndpoints(push *model.PushContext) []*endpoint.LocalityLbEndpoints {
	port := NodeProxyInbound2CapturePort

	lbEndpoints := &endpoint.LocalityLbEndpoints{
		LbEndpoints: []*endpoint.LbEndpoint{},
	}
	for _, coreproxy := range push.AcmgIndex.CoreProxy.ByNamespacedName {
		lbEndpoints.LbEndpoints = append(lbEndpoints.LbEndpoints, &endpoint.LbEndpoint{
			HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{
				Address: &core.Address{
					Address: &core.Address_SocketAddress{
						SocketAddress: &core.SocketAddress{
							Address:       coreproxy.PodIP,
							PortSpecifier: &core.SocketAddress_PortValue{PortValue: port},
						},
					},
				},
			}},
		})
	}
	return []*endpoint.LocalityLbEndpoints{lbEndpoints}
}

func buildToCoreProxyChain(push *model.PushContext, proxy *model.Proxy, workload acmg.Workload) *listener.FilterChain {
	var filters []*listener.Filter

	filters = append(filters, push.Telemetry.TCPFilters(proxy, istionetworking.ListenerClassSidecarInbound)...)
	toCoreProxyCluster := toCoreProxyClusterName(workload.Identity())
	filters = append(filters, &listener.Filter{
		Name: wellknown.TCPProxy,
		ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
			AccessLog:        accessLogString(fmt.Sprintf("capture outbound (%v to core proxy)", workload.Identity())),
			StatPrefix:       toCoreProxyCluster,
			ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: toCoreProxyCluster},
			TunnelingConfig: &tcp.TcpProxy_TunnelingConfig{
				Hostname: "%DOWNSTREAM_LOCAL_ADDRESS%", // (unused, per extended connect)
				HeadersToAdd: []*core.HeaderValueOption{
					// This is for server ztunnel - not really needed for waypoint proxy
					{Header: &core.HeaderValue{Key: "x-envoy-original-dst-host", Value: "%DOWNSTREAM_LOCAL_ADDRESS%"}},

					// This is for metadata propagation
					// TODO: should we just set the baggage directly, as we have access to the Pod here (instead of using the filter)?
					{Header: &core.HeaderValue{Key: "baggage", Value: "%DYNAMIC_METADATA([\"envoy.filters.listener.workload_metadata\", \"baggage\"])%"}},
				},
			},
		},
		)},
	})

	return &listener.FilterChain{
		Name:    toCoreProxyCluster,
		Filters: filters,
	}
}

func blackholeFilterChain(t string) *listener.FilterChain {
	return &listener.FilterChain{
		Name: "blackhole " + t,
		Filters: []*listener.Filter{{
			Name: wellknown.TCPProxy,
			ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
				AccessLog:        accessLogString("blackhole " + t),
				StatPrefix:       util.BlackHoleCluster,
				ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: "blackhole " + t},
			})},
		}},
	}
}

func toCoreProxyClusterName(workloadIdentity string) string {
	return fmt.Sprintf("%s_to_coreproxy", workloadIdentity)
}

// buildPodOutboundCaptureListener creates a single listener with a FilterChain for each combination
// of ServiceAccount from pods on the node and Service VIP in the cluster.
func (g *NodeProxyConfigGenerator) buildPodOutboundCaptureListener(proxy *model.Proxy, push *model.PushContext) *discovery.Resource {
	l := &listener.Listener{
		Name:           "nodeproxy_outbound",
		UseOriginalDst: wrappers.Bool(true),
		Transparent:    wrappers.Bool(true),
		AccessLog:      accessLogString("outbound capture listener"),
		SocketOptions: []*core.SocketOption{{
			Description: "Set socket mark to packets coming back from outbound listener",
			Level:       SolSocket,
			Name:        SoMark,
			Value: &core.SocketOption_IntValue{
				IntValue: OutboundMark,
			},
			State: core.SocketOption_STATE_PREBIND,
		}},
		ListenerFilters: []*listener.ListenerFilter{
			{
				Name: wellknown.OriginalDestination,
				ConfigType: &listener.ListenerFilter_TypedConfig{
					TypedConfig: protoconv.MessageToAny(&originaldst.OriginalDst{}),
				},
			},
		},
		Address: &core.Address{Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Address: "0.0.0.0",
				PortSpecifier: &core.SocketAddress_PortValue{
					PortValue: NodeProxyOutboundCapturePort,
				},
			},
		}},
	}
	if push.Mesh.GetOutboundTrafficPolicy().GetMode() == v1alpha1.MeshConfig_OutboundTrafficPolicy_ALLOW_ANY {
		l.DefaultFilterChain = passthroughFilterChain()
	}
	// nolint: gocritic
	// if features.SidecarlessCapture == model.VariantIptables {
	l.ListenerFilters = append(l.ListenerFilters, &listener.ListenerFilter{
		Name: wellknown.OriginalSource,
		ConfigType: &listener.ListenerFilter_TypedConfig{
			TypedConfig: protoconv.MessageToAny(&originalsrc.OriginalSrc{
				Mark: OriginalSrcMark,
			}),
		},
	})
	//}

	l.ListenerFilters = append(l.ListenerFilters, &listener.ListenerFilter{
		Name: WorkloadMetadataListenerFilterName,
		ConfigType: &listener.ListenerFilter_ConfigDiscovery{
			ConfigDiscovery: &core.ExtensionConfigSource{
				ConfigSource: &core.ConfigSource{
					ConfigSourceSpecifier: &core.ConfigSource_Ads{Ads: &core.AggregatedConfigSource{}},
					InitialFetchTimeout:   durationpb.New(30 * time.Second),
				},
				TypeUrls: []string{WorkloadMetadataResourcesTypeURL},
			},
		},
	})

	// match logic:
	// dest port == 15001 -> blackhole
	// source unknown -> passthrough
	// source known, -> coreproxy
	sourceMatch := match.NewSourceIP()
	sourceMatch.OnNoMatch = match.ToChain(util.PassthroughFilterChain)

	destPortMatch := match.NewDestinationPort()
	destPortMatch.OnNoMatch = match.ToMatcher(sourceMatch.Matcher)
	destPortMatch.Map[strconv.Itoa(int(l.GetAddress().GetSocketAddress().GetPortValue()))] = match.ToChain(util.BlackHoleCluster)

	seen := sets.String{}
	// 这里从workload cache中取出的workload确保了全部是acmg范围内的
	for _, sourceWl := range push.AcmgIndex.Workloads.NodeLocal(proxy.Metadata.NodeName) {
		chain := buildToCoreProxyChain(push, proxy, sourceWl)
		sourceMatch.Map[sourceWl.PodIP] = match.ToChain(chain.Name)
		if !seen.InsertContains(chain.Name) {
			l.FilterChains = append(l.FilterChains, chain)
		}
	}

	l.FilterChainMatcher = destPortMatch.BuildMatcher()
	l.FilterChains = append(l.FilterChains, passthroughFilterChain(), blackholeFilterChain("outbound"))
	return &discovery.Resource{
		Name:     l.Name,
		Resource: protoconv.MessageToAny(l),
	}
}
