package acmg

import (
	ipsetlib "istio.io/istio/cni/pkg/ipset"
	"istio.io/istio/pkg/config/constants"
	"istio.io/pkg/env"
)

var (
	PodNamespace = env.RegisterStringVar("SYSTEM_NAMESPACE", constants.IstioSystemNamespace, "pod's namespace").Get()
	PodName      = env.RegisterStringVar("POD_NAME", "", "").Get()
	NodeName     = env.RegisterStringVar("NODE_NAME", "", "").Get()
	Revision     = env.RegisterStringVar("REVISION", "", "").Get()
	HostIP       = env.RegisterStringVar("HOST_IP", "", "").Get()
)

var Ipset = &ipsetlib.IPSet{
	Name: "nodeproxy-pods-ips",
}

type AcmgArgs struct {
	SystemNamespace string
	Revision        string
	KubeConfig      string
	RedirectMode    RedirectMode
	LogLevel        string
}

type RedirectMode int

const (
	IptablesMode RedirectMode = iota
	EbpfMode
)

func (v RedirectMode) String() string {
	switch v {
	case IptablesMode:
		return "iptables"
	case EbpfMode:
		return "ebpf"
	}
	return ""
}
