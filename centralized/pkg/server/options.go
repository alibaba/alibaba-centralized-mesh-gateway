package server

import (
	"istio.io/client-go/pkg/apis/networking/v1alpha3"
	"istio.io/pkg/env"
)

var (
	IstioGatewayName       = env.RegisterStringVar("GATEWAY_NAME", "istio-gateway", "").Get()
	GatewayServiceName     = env.RegisterStringVar("GATEWAY_SERVICE_NAME", "acmg-gateway", "").Get()
	GatewayNamespace       = env.RegisterStringVar("GATEWAY_NAMESPACE", "istio-system", "").Get()
	CentralizedGateWayName = env.RegisterStringVar("CENTRALIZED_GATEWAYNAME", "traffix-gateway", "").Get()
)

type CoreDnsHijackArgs struct {
	GatewayNamespace       string
	KubeConfig             string
	GateWayName            string
	GatewayServiceName     string
	CentralizedGateWayName string
}

type OperationType uint8

const (
	UpdateVS OperationType = 0
	AddVS    OperationType = 1
	DeleteVS OperationType = 2
)

type EventItem struct {
	Name          string
	OperationType OperationType
	Value         *v1alpha3.VirtualService
	OldValue      *v1alpha3.VirtualService
}

type GatewayData struct {
	istioGatewayName       string
	centralizedGateWayName string
	gatewayServiceName     string
	gatewayNamespace       string
	gatewayDns             string
}
