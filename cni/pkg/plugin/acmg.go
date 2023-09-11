package plugin

import (
	"context"
	"fmt"
	"istio.io/istio/cni/pkg/acmg"
	"istio.io/istio/cni/pkg/ambient"
	ebpf "istio.io/istio/cni/pkg/ebpf-acmg/server"
	"istio.io/istio/pilot/pkg/acmg/acmgpod"
	"istio.io/pkg/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"net/netip"
)

func checkAcmg(conf Config, acmgConfig acmg.AcmgConfigFile, podName, podNamespace, podIfName, podNetNs string, podIPs []net.IPNet) (bool, error) {
	if !acmgConfig.NodeProxyReady {
		return false, fmt.Errorf("nodeproxy not ready")
	}

	client, err := newKubeClient(conf)
	if err != nil {
		return false, err
	}

	if client == nil {
		return false, nil
	}

	pod, err := client.CoreV1().Pods(podNamespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	ns, err := client.CoreV1().Namespaces().Get(context.Background(), podNamespace, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	if acmgpod.PodNodeProxyEnabled(ns, pod) {
		if acmgConfig.RedirectMode == acmg.EbpfMode.String() {
			ifIndex, mac, err := ambient.GetIndexAndPeerMac(podIfName, podNetNs)
			if err != nil {
				return false, err
			}
			ips := []netip.Addr{}
			for _, ip := range podIPs {
				if v, err := netip.ParseAddr(ip.IP.String()); err == nil {
					ips = append(ips, v)
				}
			}
			err = ebpf.AddPodToMesh(uint32(ifIndex), mac, ips)
			if err != nil {
				return false, err
			}
			if err := acmg.AnnotateEnrolledPod(client, pod); err != nil {
				log.Errorf("failed to annotate pod enrollment: %v", err)
			}
		} else {
			acmg.NodeName = pod.Spec.NodeName

			acmg.HostIP, err = acmg.GetHostIP(client)
			if err != nil || acmg.HostIP == "" {
				return false, fmt.Errorf("error getting host IP: %v", err)
			}

			// Can't set this on GKE, but needed in AWS.. so silently ignore failures
			_ = acmg.SetProc("/proc/sys/net/ipv4/conf/"+podIfName+"/rp_filter", "0")

			for _, ip := range podIPs {
				acmg.AddPodToMesh(client, pod, ip.IP.String())
			}
			return true, nil
		}
	}

	return false, nil
}
