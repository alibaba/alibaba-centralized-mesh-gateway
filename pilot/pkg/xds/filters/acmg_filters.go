package filters

import (
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"istio.io/istio/pilot/pkg/util/protoconv"
)

var (
	CaptureTLSFilter = &listener.Filter{
		Name: "capture_tls",
		ConfigType: &listener.Filter_TypedConfig{
			TypedConfig: protoconv.TypedStruct("type.googleapis.com/istio.tls_passthrough.v1.CaptureTLS"),
		},
	}

	RestoreTLSFilter = &listener.Filter{
		Name: "restore_tls",
		ConfigType: &listener.Filter_TypedConfig{
			TypedConfig: protoconv.TypedStruct("type.googleapis.com/istio.tls_passthrough.v1.RestoreTLS"),
		},
	}

	BaggageFilter = &hcm.HttpFilter{
		Name: "istio.filters.http.baggage_handler",
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: protoconv.TypedStruct("type.googleapis.com/istio.telemetry.baggagehandler.v1.Config"),
		},
	}
)
