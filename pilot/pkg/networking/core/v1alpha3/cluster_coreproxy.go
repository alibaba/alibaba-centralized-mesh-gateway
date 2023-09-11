package v1alpha3

import (
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	internalupstream "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/internal_upstream/v3"
	rawbuffer "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/raw_buffer/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	metadata "github.com/envoyproxy/go-control-plane/envoy/type/metadata/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/acmg"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/plugin/authn"
	"istio.io/istio/pilot/pkg/networking/util"
	security "istio.io/istio/pilot/pkg/security/model"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/pkg/log"
	"time"
)

func (configgen *ConfigGeneratorImpl) buildCoreProxyInboundClusters(cb *ClusterBuilder, proxy *model.Proxy, push *model.PushContext) []*cluster.Cluster {
	clusters := make([]*cluster.Cluster, 0)
	wls, svcs := FindAllResources(push)

	// We create 4 types of clusters:
	// 1. `inbound-vip|internal|hostname|port`. Will send to internal listener of the same name.
	// 2. `inbound-vip|protocol|hostname|port`. EDS routing to the internal listener for each pod in the VIP.
	// 3. `inbound-pod||podip|port`. Points to inbound_CONNECT_originate with tunnel metadata set to hit the pod
	// 4. inbound_CONNECT_originate. original dst with TLS added

	clusters = append(clusters, cb.buildCoreProxyInboundVIPInternal(svcs)...)
	clusters = append(clusters, cb.buildCoreProxyInboundVIP(svcs)...)
	clusters = append(clusters, cb.buildCoreProxyInboundPod(wls, configgen.Discovery)...)
	clusters = append(clusters, cb.buildCoreProxyInboundConnect(proxy, push))

	for _, c := range clusters {
		if c.TransportSocket != nil && c.TransportSocketMatches != nil {
			log.Errorf("invalid cluster, multiple matches: %v", c.Name)
		}
	}
	return clusters
}

var BaggagePassthroughTransportSocket = &core.TransportSocket{
	Name: "envoy.transport_sockets.internal_upstream",
	ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&internalupstream.InternalUpstreamTransport{
		PassthroughMetadata: []*internalupstream.InternalUpstreamTransport_MetadataValueSource{
			{
				Kind: &metadata.MetadataKind{Kind: &metadata.MetadataKind_Cluster_{
					Cluster: &metadata.MetadataKind_Cluster{},
				}},
				Name: "istio",
			},
		},
		TransportSocket: &core.TransportSocket{
			Name:       "envoy.transport_sockets.raw_buffer",
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&rawbuffer.RawBuffer{})},
		},
	})},
}

// `inbound-vip|internal|hostname|port`. Will send to internal listener of the same name (without internal subset)
func (cb *ClusterBuilder) buildCoreProxyInboundVIPInternalCluster(svc *model.Service, port model.Port) *MutableCluster {
	clusterName := model.BuildSubsetKey(model.TrafficDirectionInboundVIP, "internal", svc.Hostname, port.Port)
	destinationName := model.BuildSubsetKey(model.TrafficDirectionInboundVIP, "", svc.Hostname, port.Port)

	clusterType := cluster.Cluster_STATIC
	llb := util.BuildInternalEndpoint(destinationName, nil)
	localCluster := cb.buildDefaultCluster(clusterName, clusterType, llb,
		model.TrafficDirectionInbound, &port, nil, nil)
	// no TLS
	localCluster.cluster.TransportSocketMatches = nil
	localCluster.cluster.TransportSocket = BaggagePassthroughTransportSocket
	return localCluster
}

// `inbound-vip|internal|hostname|port`. Will send to internal listener of the same name.
func (cb *ClusterBuilder) buildCoreProxyInboundVIPInternal(svcs map[host.Name]*model.Service) []*cluster.Cluster {
	clusters := []*cluster.Cluster{}
	for _, svc := range svcs {
		for _, port := range svc.Ports {
			if port.Protocol == protocol.UDP {
				continue
			}
			clusters = append(clusters, cb.buildCoreProxyInboundVIPInternalCluster(svc, *port).build())
		}
	}
	return clusters
}

// `inbound-vip||hostname|port`. EDS routing to the internal listener for each pod in the VIP.
func (cb *ClusterBuilder) buildCoreProxyInboundVIPCluster(svc *model.Service, port model.Port, subset string) *MutableCluster {
	clusterName := model.BuildSubsetKey(model.TrafficDirectionInboundVIP, subset, svc.Hostname, port.Port)

	clusterType := cluster.Cluster_EDS
	localCluster := cb.buildDefaultCluster(clusterName, clusterType, nil,
		model.TrafficDirectionInbound, &port, nil, nil)

	// Ensure VIP cluster has services metadata for stats filter usage
	im := getOrCreateIstioMetadata(localCluster.cluster)
	im.Fields["services"] = &structpb.Value{
		Kind: &structpb.Value_ListValue{
			ListValue: &structpb.ListValue{
				Values: []*structpb.Value{},
			},
		},
	}
	svcMetaList := im.Fields["services"].GetListValue()
	svcMetaList.Values = append(svcMetaList.Values, buildServiceMetadata(svc))

	// no TLS, we are just going to internal address
	localCluster.cluster.TransportSocket = &core.TransportSocket{
		Name: "envoy.transport_sockets.internal_upstream",
		ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&internalupstream.InternalUpstreamTransport{
			TransportSocket: &core.TransportSocket{
				Name:       "envoy.transport_sockets.raw_buffer",
				ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&rawbuffer.RawBuffer{})},
			},
		})},
	}
	localCluster.cluster.TransportSocketMatches = nil
	maybeApplyEdsConfig(localCluster.cluster)
	return localCluster
}

// `inbound-vip|protocol|hostname|port`. EDS routing to the internal listener for each pod in the VIP.
func (cb *ClusterBuilder) buildCoreProxyInboundVIP(svcs map[host.Name]*model.Service) []*cluster.Cluster {
	clusters := []*cluster.Cluster{}

	for _, svc := range svcs {
		for _, port := range svc.Ports {
			if port.Protocol == protocol.UDP {
				continue
			}
			if port.Protocol.IsUnsupported() || port.Protocol.IsTCP() {
				clusters = append(clusters, cb.buildCoreProxyInboundVIPCluster(svc, *port, "tcp").build())
			}
			if port.Protocol.IsUnsupported() || port.Protocol.IsHTTP() {
				clusters = append(clusters, cb.buildCoreProxyInboundVIPCluster(svc, *port, "http").build())
			}
			cfg := cb.unsafeWaypointOnlyProxy.SidecarScope.DestinationRule(model.TrafficDirectionInbound, cb.unsafeWaypointOnlyProxy, svc.Hostname).GetRule()
			if cfg != nil {
				destinationRule := cfg.Spec.(*networking.DestinationRule)
				for _, ss := range destinationRule.Subsets {
					if port.Protocol.IsUnsupported() || port.Protocol.IsTCP() {
						clusters = append(clusters, cb.buildCoreProxyInboundVIPCluster(svc, *port, "tcp/"+ss.Name).build())
					}
					if port.Protocol.IsUnsupported() || port.Protocol.IsHTTP() {
						clusters = append(clusters, cb.buildCoreProxyInboundVIPCluster(svc, *port, "http/"+ss.Name).build())
					}
				}
			}
		}
	}
	return clusters
}

var InternalUpstreamSocketMatch = []*cluster.Cluster_TransportSocketMatch{
	{
		Name: "internal_upstream",
		Match: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				model.TunnelLabelShortName: {Kind: &structpb.Value_StringValue{StringValue: model.TunnelH2}},
			},
		},
		TransportSocket: &core.TransportSocket{
			Name: "envoy.transport_sockets.internal_upstream",
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&internalupstream.InternalUpstreamTransport{
				PassthroughMetadata: []*internalupstream.InternalUpstreamTransport_MetadataValueSource{
					{
						Kind: &metadata.MetadataKind{Kind: &metadata.MetadataKind_Host_{}},
						Name: "tunnel",
					},
					{
						Kind: &metadata.MetadataKind{Kind: &metadata.MetadataKind_Host_{
							Host: &metadata.MetadataKind_Host{},
						}},
						Name: "istio",
					},
				},
				TransportSocket: &core.TransportSocket{
					Name:       "envoy.transport_sockets.raw_buffer",
					ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&rawbuffer.RawBuffer{})},
				},
			})},
		},
	},
	defaultTransportSocketMatch(),
}

// build podCluster
func (cb *ClusterBuilder) buildCoreProxyInboundPodCluster(wl acmg.Workload, port model.Port) *MutableCluster {
	clusterName := model.BuildSubsetKey(model.TrafficDirectionInboundPod, "", host.Name(wl.PodIP), port.Port)
	address := wl.PodIP
	tunnelPort := 15008
	// We will connect to inbound_CONNECT_originate internal listener, telling it to tunnel to ip:15008,
	// and add some detunnel metadata that had the original port.
	tunnelOrigLis := "inbound_CONNECT_originate"
	llb := util.BuildInternalEndpoint(tunnelOrigLis, util.BuildTunnelMetadata(address, port.Port, tunnelPort))
	clusterType := cluster.Cluster_STATIC
	localCluster := cb.buildDefaultCluster(clusterName, clusterType, llb,
		model.TrafficDirectionInbound, &port, nil, nil)

	// Apply internal_upstream, since we need to pass our the pod dest address in the metadata
	localCluster.cluster.TransportSocketMatches = nil
	localCluster.cluster.TransportSocket = InternalUpstreamSocketMatch[0].TransportSocket
	return localCluster
}

// Cluster to forward to the inbound-pod listener. This is similar to the inbound-vip internal cluster, but has a single endpoint.
// TODO: in the future maybe we could share the VIP cluster and just pre-select the IP.
func (cb *ClusterBuilder) buildCoreProxyInboundInternalPodCluster(wl acmg.Workload, port model.Port) *MutableCluster {
	clusterName := model.BuildSubsetKey(model.TrafficDirectionInboundPod, "internal", host.Name(wl.PodIP), port.Port)
	destName := model.BuildSubsetKey(model.TrafficDirectionInboundPod, "", host.Name(wl.PodIP), port.Port)
	// We will connect to inbound_CONNECT_originate internal listener, telling it to tunnel to ip:15008,
	// and add some detunnel metadata that had the original port.
	llb := util.BuildInternalEndpoint(destName, nil)
	clusterType := cluster.Cluster_STATIC
	localCluster := cb.buildDefaultCluster(clusterName, clusterType, llb,
		model.TrafficDirectionInbound, &port, nil, nil)
	// Apply internal_upstream, since we need to pass our the pod dest address in the metadata
	localCluster.cluster.TransportSocketMatches = nil
	localCluster.cluster.TransportSocket = InternalUpstreamSocketMatch[0].TransportSocket
	return localCluster
}

// `inbound-pod||podip|port`. Points to inbound_CONNECT_originate with tunnel metadata set to hit the pod
func (cb *ClusterBuilder) buildCoreProxyInboundPod(wls []LabeledWorkloadAndServices, discovery model.ServiceDiscovery) []*cluster.Cluster {
	clusters := []*cluster.Cluster{}
	for _, wlx := range wls {
		wl := wlx.WorkloadInfo
		instances := discovery.GetProxyServiceInstances(&model.Proxy{
			Type:            model.SidecarProxy,
			IPAddresses:     []string{wl.PodIP},
			ConfigNamespace: wl.Namespace,
			Metadata: &model.NodeMetadata{
				Namespace: wl.Namespace,
				Labels:    wl.Labels,
			},
		})
		for _, port := range getPorts(instances) {
			if port.Protocol == protocol.UDP {
				continue
			}
			clusters = append(clusters,
				cb.buildCoreProxyInboundPodCluster(wl, port).build(),
				cb.buildCoreProxyInboundInternalPodCluster(wl, port).build())
		}
	}
	return clusters
}

// inbound_CONNECT_originate. original dst with TLS added
func (cb *ClusterBuilder) buildCoreProxyInboundConnect(proxy *model.Proxy, push *model.PushContext) *cluster.Cluster {
	ctx := &tls.CommonTlsContext{}
	security.ApplyToCommonTLSContext(ctx, proxy, nil, authn.TrustDomainsForValidation(push.Mesh), true)

	ctx.AlpnProtocols = []string{"h2"}

	ctx.TlsParams = &tls.TlsParameters{
		// Ensure TLS 1.3 is used everywhere
		TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
		TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_3,
	}
	return &cluster.Cluster{
		Name:                          "inbound_CONNECT_originate",
		ClusterDiscoveryType:          &cluster.Cluster_Type{Type: cluster.Cluster_ORIGINAL_DST},
		LbPolicy:                      cluster.Cluster_CLUSTER_PROVIDED,
		ConnectTimeout:                durationpb.New(2 * time.Second),
		CleanupInterval:               durationpb.New(60 * time.Second),
		TypedExtensionProtocolOptions: h2connectUpgrade(),
		TransportSocket: &core.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&tls.UpstreamTlsContext{
				CommonTlsContext: ctx,
			})},
		},
	}
}
