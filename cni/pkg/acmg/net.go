// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package acmg

import (
	"context"
	"errors"
	"fmt"
	netns "github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
	pconstants "istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/kube/kclient"
	"k8s.io/apimachinery/pkg/types"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"istio.io/istio/cni/pkg/acmg/constants"
	istiolog "istio.io/pkg/log"
)

var log = istiolog.RegisterScope("acmg", "acmg controller")

func IsPodInIpset(pod *corev1.Pod) bool {
	ipset, err := Ipset.List()
	if err != nil {
		log.Errorf("Failed to list ipset entries: %v", err)
		return false
	}

	// Since not all kernels support comments in ipset, we should also try and
	// match against the IP
	for _, ip := range ipset {
		if ip.Comment == string(pod.UID) {
			return true
		}
		if ip.IP.String() == pod.Status.PodIP {
			return true
		}
	}

	return false
}

func RouteExists(rte []string) bool {
	output, err := executeOutput(
		"bash", "-c",
		fmt.Sprintf("ip route show %s | wc -l", strings.Join(rte, " ")),
	)
	if err != nil {
		return false
	}

	log.Debugf("RouteExists(%s): %s", strings.Join(rte, " "), output)

	return output == "1"
}

func buildRouteFromPod(pod *corev1.Pod, ip string) ([]string, error) {
	if ip == "" {
		ip = pod.Status.PodIP
	}

	if ip == "" {
		return nil, errors.New("no ip found")
	}

	return []string{
		"table",
		fmt.Sprintf("%d", constants.RouteTableInbound),
		fmt.Sprintf("%s/32", ip),
		"via",
		constants.NodeProxyInboundTunIP,
		"dev",
		constants.InboundTun,
		"src",
		HostIP,
	}, nil
}

func (s *Server) routesAdd(routes []*netlink.Route) error {
	for _, route := range routes {
		log.Debugf("Adding route: %+v", route)
		err := netlink.RouteAdd(route)
		if err != nil {
			return err
		}
	}

	return nil
}

func getDeviceWithDestinationOf(ip string) (string, error) {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Dst: &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(32, 32)}},
		netlink.RT_FILTER_DST)
	if err != nil {
		return "", err
	}

	if len(routes) == 0 {
		return "", errors.New("no routes found")
	}

	linkIndex := routes[0].LinkIndex
	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
}

func GetHostIP(kubeClient kubernetes.Interface) (string, error) {
	var ip string
	// Get the node from the Kubernetes API
	node, err := kubeClient.CoreV1().Nodes().Get(context.TODO(), NodeName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting node: %v", err)
	}

	ip = node.Spec.PodCIDR

	// This needs to be done as in Kind, the node internal IP is not the one we want.
	if ip == "" {
		// PodCIDR is not set, try to get the IP from the node internal IP
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeInternalIP {
				return address.Address, nil
			}
		}
	} else {
		network, err := netip.ParsePrefix(ip)
		if err != nil {
			return "", fmt.Errorf("error parsing node IP: %v", err)
		}
		log.Infof("network is %v", network)

		ifaces, err := net.Interfaces()
		if err != nil {
			return "", fmt.Errorf("error getting interfaces: %v", err)
		}

		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			log.Infof("iface is %v %v", iface.Name, addrs)

			if err != nil {
				return "", fmt.Errorf("error getting addresses: %v", err)
			}

			for _, addr := range addrs {
				a, err := netip.ParseAddr(strings.Split(addr.String(), "/")[0])
				if err != nil {
					return "", fmt.Errorf("error parsing address: %v", err)
				}
				if network.Contains(a) {
					return a.String(), nil
				}
			}
		}
	}

	return "", nil
}

// CreateRulesOnNode initializes the routing, firewall and ipset rules on the node.
// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh
func (s *Server) CreateRulesOnNode(nodeproxyVeth, nodeproxyIP string, captureDNS bool) error {
	var err error

	log.Debugf("CreateRulesOnNode: nodeproxyVeth=%s, nodeproxyIP=%s", nodeproxyVeth, nodeproxyIP)

	// Check if chain exists, if it exists flush.. otherwise initialize
	// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L28
	err = execute(s.IptablesCmd(), "-t", "mangle", "-C", "OUTPUT", "-j", constants.ChainNodeProxyOutput)
	if err == nil {
		log.Debugf("Chain %s already exists, flushing", constants.ChainOutput)
		s.flushLists()
	} else {
		log.Debugf("Initializing lists")
		err = s.initializeLists()
		if err != nil {
			return err
		}
	}

	// Create ipset of pod members.
	// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L85
	log.Debug("Creating ipset")
	err = Ipset.CreateSet()
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("error creating ipset: %v", err)
	}

	appendRules := []*iptablesRule{
		// Skip things that come from the tunnels, but don't apply the conn skip mark
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L88
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-i", constants.InboundTun,
			"-j", "MARK",
			"--set-mark", constants.SkipMark,
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L89
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-i", constants.InboundTun,
			"-j", "RETURN",
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L90
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-i", constants.OutboundTun,
			"-j", "MARK",
			"--set-mark", constants.SkipMark,
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L91
		newIptableRule(constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-i", constants.OutboundTun,
			"-j", "RETURN",
		),

		// Make sure that whatever is skipped is also skipped for returning packets.
		// If we have a skip mark, save it to conn mark.
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L95
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyForward,
			"-m", "mark",
			"--mark", constants.ConnSkipMark,
			"-j", "CONNMARK",
			"--save-mark",
			"--nfmask", constants.ConnSkipMask,
			"--ctmask", constants.ConnSkipMask,
		),
		// Input chain might be needed for things in host namespace that are skipped.
		// Place the mark here after routing was done, not sure if conn-tracking will figure
		// it out if I do it before, as NAT might change the connection tuple.
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L99
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyInput,
			"-m", "mark",
			"--mark", constants.ConnSkipMark,
			"-j", "CONNMARK",
			"--save-mark",
			"--nfmask", constants.ConnSkipMask,
			"--ctmask", constants.ConnSkipMask,
		),

		// For things with the proxy mark, we need different routing just on returning packets
		// so we give a different mark to them.
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L103
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyForward,
			"-m", "mark",
			"--mark", constants.ProxyMark,
			"-j", "CONNMARK",
			"--save-mark",
			"--nfmask", constants.ProxyMask,
			"--ctmask", constants.ProxyMask,
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L104
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyInput,
			"-m", "mark",
			"--mark", constants.ProxyMark,
			"-j", "CONNMARK",
			"--save-mark",
			"--nfmask", constants.ProxyMask,
			"--ctmask", constants.ProxyMask,
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L106
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyOutput,
			"--source", HostIP,
			"-j", "MARK",
			"--set-mark", constants.ConnSkipMask,
		),

		// If we have an outbound mark, we don't need kube-proxy to do anything,
		// so accept it before kube-proxy translates service vips to pod ips
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L122
		newIptableRule(
			constants.TableNat,
			constants.ChainNodeProxyPrerouting,
			"-m", "mark",
			"--mark", constants.OutboundMark,
			"-j", "ACCEPT",
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L123
		newIptableRule(
			constants.TableNat,
			constants.ChainNodeProxyPostrouting,
			"-m", "mark",
			"--mark", constants.OutboundMark,
			"-j", "ACCEPT",
		),
	}

	if captureDNS {
		appendRules = append(appendRules,
			newIptableRule(
				constants.TableNat,
				constants.ChainNodeProxyPrerouting,
				"-p", "udp",
				"-m", "set",
				"--match-set", Ipset.Name, "src",
				"--dport", "53",
				"-j", "DNAT",
				"--to", fmt.Sprintf("%s:%d", nodeproxyIP, constants.DNSCapturePort),
			),
		)
	}

	appendRules2 := []*iptablesRule{
		// Don't set anything on the tunnel (geneve port is 6081), as the tunnel copies
		// the mark to the un-tunneled packet.
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L126
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-p", "udp",
			"-m", "udp",
			"--dport", "6081",
			"-j", "RETURN",
		),

		// If we have the conn mark, restore it to mark, to make sure that the other side of the connection
		// is skipped as well.
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L129-L130
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-m", "connmark",
			"--mark", constants.ConnSkipMark,
			"-j", "MARK",
			"--set-mark", constants.SkipMark,
		),
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-m", "mark",
			"--mark", constants.SkipMark,
			"-j", "RETURN",
		),

		// If we have the proxy mark in, set the return mark to make sure that original src packets go to ztunnel
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L133-L134
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"!", "-i", nodeproxyVeth,
			"-m", "connmark",
			"--mark", constants.ProxyMark,
			"-j", "MARK",
			"--set-mark", constants.ProxyRetMark,
		),
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-m", "mark",
			"--mark", constants.ProxyRetMark,
			"-j", "RETURN",
		),

		// Send fake source outbound connections to the outbound route table (for original src)
		// if it's original src, the source ip of packets coming from the proxy might be that of a pod, so
		// make sure we don't tproxy it
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L139-L140
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-i", nodeproxyVeth,
			"!", "--source", nodeproxyIP,
			"-j", "MARK",
			"--set-mark", constants.ProxyMark,
		),
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-m", "mark",
			"--mark", constants.SkipMark,
			"-j", "RETURN",
		),

		// Make sure anything that leaves ztunnel is routed normally (xds, connections to other ztunnels,
		// connections to upstream pods...)
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L143
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-i", nodeproxyVeth,
			"-j", "MARK",
			"--set-mark", constants.ConnSkipMark,
		),

		// skip udp so DNS works. We can make this more granular.
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L146
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-p", "udp",
			"-j", "MARK",
			"--set-mark", constants.ConnSkipMark,
		),

		// Skip things from host ip - these are usually kubectl probes
		// skip anything with skip mark. This can be used to add features like port exclusions
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L149
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-m", "mark",
			"--mark", constants.SkipMark,
			"-j", "RETURN",
		),

		// Mark outbound connections to route them to the proxy using ip rules/route tables
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L151
		// Per Yuval, interface_prefix can be left off this rule... but we should check this (hard to automate
		// detection).
		newIptableRule(
			constants.TableMangle,
			constants.ChainNodeProxyPrerouting,
			"-p", "tcp",
			"-m", "set",
			"--match-set", Ipset.Name, "src",
			"-j", "MARK",
			"--set-mark", constants.OutboundMark,
		),
	}

	err = s.iptablesAppend(appendRules)
	if err != nil {
		log.Errorf("failed to append iptables rule: %v", err)
	}

	err = s.iptablesAppend(appendRules2)
	if err != nil {
		log.Errorf("failed to append iptables rule: %v", err)
	}

	// Need to do some work in procfs
	// @TODO: This likely needs to be cleaned up, there are a lot of martians in AWS
	// that seem to necessitate this work.
	procs := map[string]int{
		"/proc/sys/net/ipv4/conf/default/rp_filter":                  0,
		"/proc/sys/net/ipv4/conf/all/rp_filter":                      0,
		"/proc/sys/net/ipv4/conf/" + nodeproxyVeth + "/rp_filter":    0,
		"/proc/sys/net/ipv4/conf/" + nodeproxyVeth + "/accept_local": 1,
	}
	for proc, val := range procs {
		err = SetProc(proc, fmt.Sprint(val))
		if err != nil {
			log.Errorf("failed to write to proc file %s: %v", proc, err)
		}
	}

	// Create tunnels
	// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L153-L161
	inbnd := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name: constants.InboundTun,
		},
		ID:     1000,
		Remote: net.ParseIP(nodeproxyIP),
	}
	log.Debugf("Building inbound tunnel: %+v", inbnd)
	err = netlink.LinkAdd(inbnd)
	if err != nil {
		log.Errorf("failed to add inbound tunnel: %v", err)
	}
	err = netlink.AddrAdd(inbnd, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP(constants.InboundTunIP),
			Mask: net.CIDRMask(constants.TunPrefix, 32),
		},
	})
	if err != nil {
		log.Errorf("failed to add inbound tunnel address: %v", err)
	}

	outbnd := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name: constants.OutboundTun,
		},
		ID:     1001,
		Remote: net.ParseIP(nodeproxyIP),
	}
	log.Debugf("Building outbound tunnel: %+v", outbnd)
	err = netlink.LinkAdd(outbnd)
	if err != nil {
		log.Errorf("failed to add outbound tunnel: %v", err)
	}
	err = netlink.AddrAdd(outbnd, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP(constants.OutboundTunIP),
			Mask: net.CIDRMask(constants.TunPrefix, 32),
		},
	})
	if err != nil {
		log.Errorf("failed to add outbound tunnel address: %v", err)
	}

	err = netlink.LinkSetUp(inbnd)
	if err != nil {
		log.Errorf("failed to set inbound tunnel up: %v", err)
	}
	err = netlink.LinkSetUp(outbnd)
	if err != nil {
		log.Errorf("failed to set outbound tunnel up: %v", err)
	}

	procs = map[string]int{
		"/proc/sys/net/ipv4/conf/" + constants.InboundTun + "/rp_filter":     0,
		"/proc/sys/net/ipv4/conf/" + constants.InboundTun + "/accept_local":  1,
		"/proc/sys/net/ipv4/conf/" + constants.OutboundTun + "/rp_filter":    0,
		"/proc/sys/net/ipv4/conf/" + constants.OutboundTun + "/accept_local": 1,
	}
	for proc, val := range procs {
		err = SetProc(proc, fmt.Sprint(val))
		if err != nil {
			log.Errorf("failed to write to proc file %s: %v", proc, err)
		}
	}

	dirEntries, err := os.ReadDir("/proc/sys/net/ipv4/conf")
	if err != nil {
		log.Errorf("failed to read /proc/sys/net/ipv4/conf: %v", err)
	}
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			if _, err := os.Stat("/proc/sys/net/ipv4/conf/" + dirEntry.Name() + "/rp_filter"); err != nil {
				err := SetProc("/proc/sys/net/ipv4/conf/"+dirEntry.Name()+"/rp_filter", "0")
				if err != nil {
					log.Errorf("failed to set /proc/sys/net/ipv4/conf/%s/rp_filter: %v", dirEntry.Name(), err)
				}
			}
		}
	}

	routes := []*ExecList{
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L164
		newExec("ip",
			[]string{
				"route", "add", "table", fmt.Sprint(constants.RouteTableOutbound), nodeproxyIP,
				"dev", nodeproxyVeth, "scope", "link",
			},
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L166
		newExec("ip",
			[]string{
				"route", "add", "table", fmt.Sprint(constants.RouteTableOutbound), "0.0.0.0/0",
				"via", constants.NodeProxyOutboundTunIP, "dev", constants.OutboundTun,
			},
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L168
		newExec("ip",
			[]string{
				"route", "add", "table", fmt.Sprint(constants.RouteTableProxy), nodeproxyIP,
				"dev", nodeproxyVeth, "scope", "link",
			},
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L169
		newExec("ip",
			[]string{
				"route", "add", "table", fmt.Sprint(constants.RouteTableProxy), "0.0.0.0/0",
				"via", nodeproxyIP, "dev", nodeproxyVeth, "onlink",
			},
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L171
		newExec("ip",
			[]string{
				"route", "add", "table", fmt.Sprint(constants.RouteTableInbound), nodeproxyIP,
				"dev", nodeproxyVeth, "scope", "link",
			},
		),
		// https://github.com/solo-io/istio-sidecarless/blob/master/redirect-worker.sh#L62-L77
		// Everything with the skip mark goes directly to the main table
		newExec("ip",
			[]string{
				"rule", "add", "priority", "100",
				"fwmark", fmt.Sprint(constants.SkipMark),
				"goto", "32766",
			},
		),
		// Everything with the outbound mark goes to the tunnel out device
		// using the outbound route table
		newExec("ip",
			[]string{
				"rule", "add", "priority", "101",
				"fwmark", fmt.Sprint(constants.OutboundMark),
				"lookup", fmt.Sprint(constants.RouteTableOutbound),
			},
		),
		// Things with the proxy return mark go directly to the proxy veth using the proxy
		// route table (useful for original src)
		newExec("ip",
			[]string{
				"rule", "add", "priority", "102",
				"fwmark", fmt.Sprint(constants.ProxyRetMark),
				"lookup", fmt.Sprint(constants.RouteTableProxy),
			},
		),
		// Send all traffic to the inbound table. This table has routes only to pods in the mesh.
		// It does not have a catch-all route, so if a route is missing, the search will continue
		// allowing us to override routing just for member pods.
		newExec("ip",
			[]string{
				"rule", "add", "priority", "103",
				"table", fmt.Sprint(constants.RouteTableInbound),
			},
		),
	}

	for _, route := range routes {
		err = execute(route.Cmd, route.Args...)
		if err != nil {
			log.Errorf(fmt.Errorf("failed to add route (%+v): %v", route, err))
		}
	}

	return nil
}

func (s *Server) cleanup() {
	log.Infof("server terminated, cleaning up")
	s.cleanRules()

	// Clean up ip route tables
	_ = routeFlushTable(constants.RouteTableInbound)
	_ = routeFlushTable(constants.RouteTableOutbound)
	_ = routeFlushTable(constants.RouteTableProxy)

	exec := []*ExecList{
		newExec("ip", []string{"rule", "del", "priority", "100"}),
		newExec("ip", []string{"rule", "del", "priority", "101"}),
		newExec("ip", []string{"rule", "del", "priority", "102"}),
		newExec("ip", []string{"rule", "del", "priority", "103"}),
	}
	for _, e := range exec {
		err := execute(e.Cmd, e.Args...)
		if err != nil {
			log.Warnf("Error running command %v %v: %v", e.Cmd, strings.Join(e.Args, " "), err)
		}
	}

	log.Debugf("Del InboundTun.")
	// Delete tunnel links
	err := netlink.LinkDel(&netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name: constants.InboundTun,
		},
	})
	if err != nil {
		log.Warnf("error deleting inbound tunnel: %v", err)
	}

	log.Debugf("Del OutboundTun.")
	err = netlink.LinkDel(&netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name: constants.OutboundTun,
		},
	})
	if err != nil {
		log.Warnf("error deleting outbound tunnel: %v", err)
	}

	_ = Ipset.DestroySet()
}

func routesDelete(routes []netlink.Route) error {
	for _, r := range routes {
		err := netlink.RouteDel(&r)
		if err != nil {
			return err
		}
	}
	return nil
}

func SetProc(path string, value string) error {
	return os.WriteFile(path, []byte(value), 0o644)
}

// This can be called on the node, as part of termination/cleanup,
// or it can be called from within a pod netns, as a "clean slate" prep.
//
// TODO `netlink.RuleDel` SHOULD work here - but it does not. Unsure why.
// So, for time being, rely on `ip`
func deleteIPRules(prioritiesToDelete []string, warnOnFail bool) {
	var exec []*ExecList
	for _, pri := range prioritiesToDelete {
		exec = append(exec, newExec("ip", []string{"rule", "del", "priority", pri}))
	}
	for _, e := range exec {
		err := execute(e.Cmd, e.Args...)
		if err != nil && warnOnFail {
			log.Warnf("Error running command %v %v: %v", e.Cmd, strings.Join(e.Args, " "), err)
		}
	}
}

func addTProxyMarks() error {
	// Set up tproxy marks
	var rules []*netlink.Rule
	// TODO IPv6, append  unix.AF_INET6
	families := []int{unix.AF_INET}
	for _, family := range families {
		// Equiv: "ip rule add priority 20000 fwmark 0x400/0xfff lookup 100"
		tproxMarkRule := netlink.NewRule()
		tproxMarkRule.Family = family
		tproxMarkRule.Table = constants.RouteTableInbound
		tproxMarkRule.Mark = constants.TProxyMark
		tproxMarkRule.Mask = constants.TProxyMask
		tproxMarkRule.Priority = constants.TProxyMarkPriority
		rules = append(rules, tproxMarkRule)

		// Equiv: "ip rule add priority 20003 fwmark 0x4d3/0xfff lookup 100"
		orgSrcRule := netlink.NewRule()
		orgSrcRule.Family = family
		orgSrcRule.Table = constants.RouteTableInbound
		orgSrcRule.Mark = constants.OrgSrcRetMark
		orgSrcRule.Mask = constants.OrgSrcRetMask
		orgSrcRule.Priority = constants.OrgSrcPriority
		rules = append(rules, orgSrcRule)
	}

	for _, rule := range rules {
		log.Debugf("Adding netlink rule : %+v", rule)
		if err := netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("failed to configure netlink rule: %v", err)
		}
	}

	return nil
}

func (s *Server) CreateEBPFRulesWithinNodeProxyNS(proxyNsVethIdx int, nodeProxyIP, nodeProxyNetNS string) error {
	ns := filepath.Base(nodeProxyNetNS)
	log.Debugf("CreateEBPFRulesWithinNodeProxyNS: proxyNsVethIdx=%d, nodeProxyIP=%s, from within netNS=%s", proxyNsVethIdx, nodeProxyIP, nodeProxyNetNS)
	err := netns.WithNetNSPath(fmt.Sprintf("/var/run/netns/%s", ns), func(netns.NetNS) error {
		// Make sure we flush table 100 before continuing - it should be empty in a new namespace
		// but better to ensure that.
		if err := routeFlushTable(constants.RouteTableInbound); err != nil {
			log.Error(err)
		}

		// Flush rules before initializing within 'addTProxyMarks'
		deleteIPRules([]string{strconv.Itoa(constants.TProxyMarkPriority), strconv.Itoa(constants.OrgSrcPriority)}, false)

		// Set up tproxy marks
		err := addTProxyMarks()
		if err != nil {
			return fmt.Errorf("failed to add TPROXY mark rules: %v", err)
		}

		loopbackLink, err := netlink.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("failed to find 'lo' link: %v", err)
		}
		// In routing table ${INBOUND_TPROXY_ROUTE_TABLE}, create a single default rule to route all traffic to
		// the loopback interface.
		// Equiv: "ip route add local 0.0.0.0/0 dev lo table 100"
		// TODO IPv6, append "0::0/0"
		cidrs := []string{"0.0.0.0/0"}
		for _, fullCIDR := range cidrs {
			_, dst, err := net.ParseCIDR(fullCIDR)
			if err != nil {
				return fmt.Errorf("parse CIDR: %v", err)
			}

			if err := netlink.RouteAdd(&netlink.Route{
				Dst:       dst,
				Scope:     netlink.SCOPE_HOST,
				Type:      unix.RTN_LOCAL,
				Table:     constants.RouteTableInbound,
				LinkIndex: loopbackLink.Attrs().Index,
			}); err != nil {
				// TODO clear this route every time
				// Would not expect this if we have properly cleared routes
				return fmt.Errorf("failed to add route: %v", err)
			}
		}

		// Flush prerouting table - this should be a new pod netns and it should be clean, but just to be safe..
		err = execute(s.IptablesCmd(), "-t", "mangle", "-F", "PREROUTING")
		if err != nil {
			return fmt.Errorf("failed to configure iptables rule: %v", err)
		}

		// Logging for prerouting mangle
		err = execute(s.IptablesCmd(), "-t", "mangle", "-I", "PREROUTING", "-j", "LOG", "--log-prefix", "ztunnel mangle pre")
		if err != nil {
			return fmt.Errorf("failed to configure iptables rule: %v", err)
		}

		vethLink, err := netlink.LinkByIndex(proxyNsVethIdx)
		if err != nil {
			return fmt.Errorf("failed to find veth with index '%d' within namespace %s: %v", proxyNsVethIdx, nodeProxyNetNS, err)
		}

		// Set up append rules
		appendRules := []*iptablesRule{
			// Set eBPF mark on inbound packets
			newIptableRule(
				constants.TableMangle,
				"PREROUTING",
				"-p", "tcp",
				"-m", "mark",
				"--mark", constants.EBPFInboundMark,
				"-m", "tcp",
				"--dport", fmt.Sprintf("%d", constants.NodeProxyInboundPort),
				"-j", "TPROXY",
				"--tproxy-mark", fmt.Sprintf("0x%x", constants.TProxyMark)+"/"+fmt.Sprintf("0x%x", constants.TProxyMask),
				"--on-port", fmt.Sprintf("%d", constants.NodeProxyInboundPort),
				"--on-ip", "127.0.0.1",
			),
			// Same mark, but on plaintext port
			newIptableRule(
				constants.TableMangle,
				"PREROUTING",
				"-p", "tcp",
				"-m", "mark",
				"--mark", constants.EBPFInboundMark,
				"-j", "TPROXY",
				"--tproxy-mark", fmt.Sprintf("0x%x", constants.TProxyMark)+"/"+fmt.Sprintf("0x%x", constants.TProxyMask),
				"--on-port", fmt.Sprintf("%d", constants.NodeProxyInboundPlaintextPort),
				"--on-ip", "127.0.0.1",
			),
			// Set outbound eBPF mark
			newIptableRule(
				constants.TableMangle,
				"PREROUTING",
				"-p", "tcp",
				"-m", "mark",
				"--mark", constants.EBPFOutboundMark,
				"-j", "TPROXY",
				"--tproxy-mark", fmt.Sprintf("0x%x", constants.TProxyMark)+"/"+fmt.Sprintf("0x%x", constants.TProxyMask),
				"--on-port", fmt.Sprintf("%d", constants.NodeProxyOutboundPort),
				"--on-ip", "127.0.0.1",
			),
			// For anything NOT going to the ztunnel IP, add the OrgSrcRet mark
			newIptableRule(
				constants.TableMangle,
				"PREROUTING",
				"-p", "tcp",
				"-i", vethLink.Attrs().Name,
				"!",
				"--dst", nodeProxyIP,
				"-j", "MARK",
				"--set-mark", fmt.Sprintf("0x%x", constants.OrgSrcRetMark)+"/"+fmt.Sprintf("0x%x", constants.OrgSrcRetMask),
			),
		}

		err = s.iptablesAppend(appendRules)
		if err != nil {
			log.Errorf("failed to append iptables rule: %v", err)
		}

		err = disableRPFiltersForLink(vethLink.Attrs().Name)
		if err != nil {
			log.Warnf("failed to disable procfs rp_filter for device %s: %v", vethLink.Attrs().Name, err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to configure ztunnel ebpf from within ns(%s): %v", ns, err)
	}
	return nil
}

func disableRPFiltersForLink(ifaceName string) error {
	// Need to do some work in procfs
	// @TODO: This needs to be cleaned up, there are a lot of martians in AWS
	// that seem to necessitate this work and in theory we shouldn't *need* to disable
	// `rp_filter` with eBPF.
	procs := map[string]int{
		"/proc/sys/net/ipv4/conf/default/rp_filter":           0,
		"/proc/sys/net/ipv4/conf/all/rp_filter":               0,
		"/proc/sys/net/ipv4/conf/" + ifaceName + "/rp_filter": 0,
	}
	for proc, val := range procs {
		err := setProc(proc, fmt.Sprint(val))
		if err != nil {
			log.Errorf("failed to write to proc file %s: %v", proc, err)
			return err
		}
	}

	return nil
}

func AddPodToMesh(client kubernetes.Interface, pod *corev1.Pod, ip string) {
	addPodToMeshWithIptables(pod, ip)

	if err := AnnotateEnrolledPod(client, pod); err != nil {
		log.Errorf("failed to annotate pod enrollment: %v", err)
	}
}

func addPodToMeshWithIptables(pod *corev1.Pod, ip string) {
	if ip == "" {
		ip = pod.Status.PodIP
	}
	if ip == "" {
		log.Debugf("skip adding pod %s/%s, IP not yet allocated", pod.Name, pod.Namespace)
		return
	}

	if !IsPodInIpset(pod) {
		log.Infof("Adding pod '%s/%s' (%s) to ipset", pod.Name, pod.Namespace, string(pod.UID))
		err := Ipset.AddIP(net.ParseIP(ip).To4(), string(pod.UID))
		if err != nil {
			log.Errorf("Failed to add pod %s to ipset list: %v", pod.Name, err)
		}
	} else {
		log.Infof("Pod '%s/%s' (%s) is in ipset", pod.Name, pod.Namespace, string(pod.UID))
	}

	rte, err := buildRouteFromPod(pod, ip)
	if err != nil {
		log.Errorf("Failed to build route for pod %s: %v", pod.Name, err)
	}

	if !RouteExists(rte) {
		log.Infof("Adding route for %s/%s: %+v", pod.Name, pod.Namespace, rte)
		// @TODO Try and figure out why buildRouteFromPod doesn't return a good route that we can
		// use err = netlink.RouteAdd(rte):
		// Error: {"level":"error","time":"2022-06-24T16:30:59.083809Z","msg":"Failed to add route ({Ifindex: 4 Dst: 10.244.2.7/32
		// Via: Family: 2, Address: 192.168.126.2 Src: 10.244.2.1 Gw: <nil> Flags: [] Table: 100 Realm: 0}) for pod
		// helloworld-v2-same-node-67b6b764bf-zhmp4: invalid argument"}
		err = execute("ip", append([]string{"route", "add"}, rte...)...)
		if err != nil {
			log.Warnf("Failed to add route (%s) for pod %s: %v", rte, pod.Name, err)
		}
	} else {
		log.Infof("Route already exists for %s/%s: %+v", pod.Name, pod.Namespace, rte)
	}

	dev, err := getDeviceWithDestinationOf(ip)
	if err != nil {
		log.Warnf("Failed to get device for destination %s", ip)
		return
	}

	err = disableRPFiltersForLink(dev)
	if err != nil {
		log.Warnf("failed to disable procfs rp_filter for device %s: %v", dev, err)
	}
}

func (s *Server) AddPodToMesh(pod *corev1.Pod) {
	switch s.redirectMode {
	case IptablesMode:
		AddPodToMesh(s.kubeClient.Kube(), pod, "")
	case EbpfMode:
		if err := s.updatePodEbpfOnNode(pod); err != nil {
			log.Errorf("failed to update POD ebpf: %v", err)
		}
		if err := AnnotateEnrolledPod(s.kubeClient.Kube(), pod); err != nil {
			log.Errorf("failed to annotate pod enrollment: %v", err)
		}
	}
}

var annotationPatch = []byte(fmt.Sprintf(
	`{"metadata":{"annotations":{"%s":"%s"}}}`,
	pconstants.AcmgRedirection,
	pconstants.AcmgRedirectionEnabled,
))

var annotationRemovePatch = []byte(fmt.Sprintf(
	`{"metadata":{"annotations":{"%s":null}}}`,
	pconstants.AcmgRedirection,
))

func AnnotateEnrolledPod(client kubernetes.Interface, pod *corev1.Pod) error {
	_, err := client.CoreV1().
		Pods(pod.Namespace).
		Patch(
			context.Background(),
			pod.Name,
			types.MergePatchType,
			annotationPatch,
			metav1.PatchOptions{},
		)
	return err
}

func AnnotateUnenrollPod(client kubernetes.Interface, pod *corev1.Pod) error {
	if pod.Annotations[pconstants.AcmgRedirection] != pconstants.AcmgRedirectionEnabled {
		return nil
	}
	// TODO: do not overwrite if already none
	_, err := client.CoreV1().
		Pods(pod.Namespace).
		Patch(
			context.Background(),
			pod.Name,
			types.MergePatchType,
			annotationRemovePatch,
			metav1.PatchOptions{},
		)
	return err
}

func DelPodFromMesh(client kubernetes.Interface, pod *corev1.Pod) {
	log.Debugf("Removing pod '%s/%s' (%s) from mesh", pod.Name, pod.Namespace, string(pod.UID))
	if IsPodInIpset(pod) {
		log.Infof("Removing pod '%s' (%s) from ipset", pod.Name, string(pod.UID))
		err := Ipset.DeleteIP(net.ParseIP(pod.Status.PodIP).To4())
		if err != nil {
			log.Errorf("Failed to delete pod %s from ipset list: %v", pod.Name, err)
		}
	} else {
		log.Infof("Pod '%s/%s' (%s) is not in ipset", pod.Name, pod.Namespace, string(pod.UID))
	}
	rte, err := buildRouteFromPod(pod, "")
	if err != nil {
		log.Errorf("Failed to build route for pod %s: %v", pod.Name, err)
	}
	if RouteExists(rte) {
		log.Infof("Removing route: %+v", rte)
		// @TODO Try and figure out why buildRouteFromPod doesn't return a good route that we can
		// use this:
		// err = netlink.RouteDel(rte)
		err = execute("ip", append([]string{"route", "del"}, rte...)...)
		if err != nil {
			log.Warnf("Failed to delete route (%s) for pod %s: %v", rte, pod.Name, err)
		}
	}

	if err := AnnotateUnenrollPod(client, pod); err != nil {
		log.Errorf("failed to annotate pod unenrollment: %v", err)
	}
}

func (s *Server) DelPodFromMesh(pod *corev1.Pod) {
	switch s.redirectMode {
	case IptablesMode:
		DelPodFromMesh(s.kubeClient.Kube(), pod)
	case EbpfMode:
		if pod.Spec.HostNetwork {
			log.Debugf("pod(%s/%s) is using host network, skip it", pod.Namespace, pod.Name)
			return
		}
		if err := s.delPodEbpfOnNode(pod.Status.PodIP); err != nil {
			log.Errorf("failed to del POD ebpf: %v", err)
		}
		if err := AnnotateUnenrollPod(s.kubeClient.Kube(), pod); err != nil {
			log.Errorf("failed to annotate pod unenrollment: %v", err)
		}
	}
}

func setProc(path string, value string) error {
	return os.WriteFile(path, []byte(value), 0o644)
}

// Get preferred outbound ip of this machine
func getOutboundIP(ip string) net.IP {
	conn, err := net.Dial("udp", ip+":80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// GetHostIPByRoute get the automatically chosen host ip to the Pod's CIDR
func GetHostIPByRoute(pods kclient.Client[*corev1.Pod]) (string, error) {
	// We assume per node POD's CIDR is the same block, so the route to the POD
	// from host should be "same". Otherwise, there may multiple host IPs will be
	// used as source to dial to PODs.
	for _, pod := range pods.List(metav1.NamespaceAll, nodeProxyLabels) {
		targetIP := pod.Status.PodIP
		if hostIP := getOutboundIP(targetIP); hostIP != nil {
			return hostIP.String(), nil
		}
	}
	return "", fmt.Errorf("failed to get outbound IP to Pods")
}
