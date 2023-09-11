package acmg

import (
	"errors"
	"fmt"
	netns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"io/fs"
	"istio.io/istio/cni/pkg/acmg/constants"
	ebpf "istio.io/istio/cni/pkg/ebpf-acmg/server"
	corev1 "k8s.io/api/core/v1"
	"net"
	"net/netip"
	"path"
	"path/filepath"
)

func (s *Server) cleanupNode() {
	log.Infof("Node-level network rule cleanup started")
	if s.redirectMode == EbpfMode {
		if err := s.delNodeProxyEbpfOnNode(); err != nil {
			log.Error(err)
		}
		return
	}
	s.cleanRules()

	flushAllRouteTables()

	deleteIPRules([]string{"100", "101", "102", "103"}, true)

	deleteTunnelLinks(constants.InboundTun, constants.OutboundTun, true)

	err := Ipset.DestroySet()
	if err != nil {
		log.Warnf("unable to delete IPSet: %v", err)
	}
}

// This can be called on the node, as part of termination/cleanup,
// or it can be called from within a pod netns, as a "clean slate" prep.
func flushAllRouteTables() {
	// Clean up ip route tables
	_ = routeFlushTable(constants.RouteTableInbound)
	_ = routeFlushTable(constants.RouteTableOutbound)
	_ = routeFlushTable(constants.RouteTableProxy)
}

func routeFlushTable(table int) error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	// default route is not handled proper in netlink
	// https://github.com/vishvananda/netlink/issues/670
	// https://github.com/vishvananda/netlink/issues/611
	for i, route := range routes {
		if (route.Dst == nil || route.Dst.IP == nil) && route.Src == nil && route.Gw == nil && route.MPLSDst == nil {
			_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
			routes[i].Dst = defaultDst
		}
	}
	err = routesDelete(routes)
	if err != nil {
		return err
	}
	return nil
}

// This can be called on the node, as part of termination/cleanup,
// or it can be called from within a pod netns, as a "clean slate" prep.
func deleteTunnelLinks(inboundName, outboundName string, warnOnFail bool) {
	// Delete geneve tunnel links

	// Re-fetch the container link to get its creation-time parameters, e.g. index and mac
	// Deleting by name doesn't work.
	inboundTun, err := netlink.LinkByName(inboundName)
	if err != nil && warnOnFail {
		log.Warnf("did not find existing inbound tunnel %s to delete: %v", inboundName, err)
	} else if inboundTun != nil {
		err = netlink.LinkDel(inboundTun)
		if err != nil && warnOnFail {
			log.Warnf("error deleting inbound tunnel: %v", err)
		}
	}
	outboundTun, err := netlink.LinkByName(outboundName)
	if err != nil && warnOnFail {
		log.Warnf("did not find existing outbound tunnel %s to delete: %v", outboundName, err)
		// Bail, if we can't find it don't try to delete it
		return
	} else if outboundTun != nil {
		err = netlink.LinkDel(outboundTun)
		if err != nil && warnOnFail {
			log.Warnf("error deleting outbound tunnel: %v", err)
		}
	}
}

func buildEbpfArgsByIP(ip string, isNodeProxy, isRemove bool) (*ebpf.RedirectArgs, error) {
	ipAddr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ip(%s): %v", ip, err)
	}
	veth, err := getVethWithDestinationOf(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %v", err)
	}
	peerIndex, err := getPeerIndex(veth)
	if err != nil {
		return nil, fmt.Errorf("failed to get veth peerIndex: %v", err)
	}

	peerNs, err := getNsNameFromNsID(veth.Attrs().NetNsID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ns name: %v", err)
	}

	mac, err := getMacFromNsIdx(peerNs, peerIndex)
	if err != nil {
		return nil, err
	}

	return &ebpf.RedirectArgs{
		IPAddrs:     []netip.Addr{ipAddr},
		MacAddr:     mac,
		Ifindex:     veth.Attrs().Index,
		PeerIndex:   peerIndex,
		PeerNs:      peerNs,
		IsNodeProxy: isNodeProxy,
		Remove:      isRemove,
	}, nil
}

func getMacFromNsIdx(ns string, ifIndex int) (net.HardwareAddr, error) {
	var hwAddr net.HardwareAddr
	err := netns.WithNetNSPath(fmt.Sprintf("/var/run/netns/%s", ns), func(netns.NetNS) error {
		link, err := netlink.LinkByIndex(ifIndex)
		if err != nil {
			return fmt.Errorf("failed to get link(%d) in ns(%s): %v", ifIndex, ns, err)
		}
		hwAddr = link.Attrs().HardwareAddr
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hwAddr, nil
}

func getPeerIndex(veth *netlink.Veth) (int, error) {
	return netlink.VethPeerIndex(veth)
}

func getNsNameFromNsID(nsid int) (string, error) {
	foundNs := errors.New("nsid found, stop iterating")
	nsName := ""
	err := filepath.WalkDir("/var/run/netns", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fd, err := unix.Open(p, unix.O_RDONLY, 0)
		if err != nil {
			log.Warnf("failed to open: %v", err)
			return nil
		}
		defer unix.Close(fd)

		id, err := netlink.GetNetNsIdByFd(fd)
		if err != nil {
			log.Warnf("failed to open: %v", err)
			return nil
		}
		if id == nsid {
			nsName = path.Base(p)
			return foundNs
		}
		return nil
	})
	if err == foundNs {
		return nsName, nil
	}
	return "", fmt.Errorf("failed to get namespace for %d", nsid)
}

func getVethWithDestinationOf(ip string) (*netlink.Veth, error) {
	link, err := getLinkWithDestinationOf(ip)
	if err != nil {
		return nil, err
	}
	veth, ok := link.(*netlink.Veth)
	if !ok {
		return nil, errors.New("not veth implemented CNI")
	}
	return veth, nil
}

func getLinkWithDestinationOf(ip string) (netlink.Link, error) {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Dst: &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(32, 32)}},
		netlink.RT_FILTER_DST)
	if err != nil {
		return nil, err
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes found for %s", ip)
	}

	linkIndex := routes[0].LinkIndex
	return netlink.LinkByIndex(linkIndex)
}

func (s *Server) updateNodeProxyEBPF(pod *corev1.Pod, captureDNS bool) error {
	if s.ebpfServer == nil {
		return fmt.Errorf("uninitialized ebpf server")
	}

	ip := pod.Status.PodIP

	veth, err := getVethWithDestinationOf(ip)
	if err != nil {
		log.Warnf("failed to get device: %v", err)
	}
	peerIndex, err := getPeerIndex(veth)
	if err != nil {
		return fmt.Errorf("failed to get veth peerIndex: %v", err)
	}

	err = disableRPFiltersForLink(veth.Attrs().Name)
	if err != nil {
		log.Warnf("failed to disable procfs rp_filter for device %s: %v", veth.Attrs().Name, err)
	}

	args, err := buildEbpfArgsByIP(ip, true, false)
	if err != nil {
		return err
	}
	args.CaptureDNS = captureDNS
	log.Debugf("update nodeproxy ebpf args: %+v", args)

	// Now that we have the ip, the veth, and the ztunnel netns,
	// two things need to happen:
	// 1. We need to interact with the kernel to jump into the ztunnel net namespace
	// and create some local rules within that net namespace
	err = s.CreateEBPFRulesWithinNodeProxyNS(peerIndex, ip, args.PeerNs)
	if err != nil {
		return fmt.Errorf("failed to configure nodeproxy pod rules: %v", err)
	}

	// 2. We need to interact with the kernel to attach eBPF progs to ztunnel
	s.ebpfServer.AcceptRequest(args)

	return nil
}

func (s *Server) delNodeProxyEbpfOnNode() error {
	if s.ebpfServer == nil {
		return fmt.Errorf("uninitialized ebpf server")
	}

	args := &ebpf.RedirectArgs{
		Ifindex:     0,
		IsNodeProxy: true,
		Remove:      true,
	}
	log.Debugf("del nodeproxy ebpf args: %+v", args)
	s.ebpfServer.AcceptRequest(args)
	return nil
}

// CreateRulesWithinNodeProxyNS initializes the routes and iptable rules that need to exist WITHIN
// the node proxy (ztunnel) netns - this is distinct from the routes and rules that need to exist OUTSIDE
// of the node proxy netns, on the node, which are handled elsewhere.
//
// There is no cleanup required for things we do within the netns, as when the netns is destroyed on pod delete,
// everything within the netns goes away.
func (s *Server) CreateRulesWithinNodeProxyNS(proxyNsVethIdx int, nodeProxyIP, nodeProxyNetNS, hostIP string) error {
	ns := filepath.Base(nodeProxyNetNS)
	log.Debugf("CreateRulesWithinNodeProxyNS: proxyNsVethIdx=%d, nodeProxyIP=%s, hostIP=%s, from within netns=%s", proxyNsVethIdx, nodeProxyIP, hostIP, nodeProxyNetNS)
	err := netns.WithNetNSPath(fmt.Sprintf("/var/run/netns/%s", ns), func(netns.NetNS) error {
		//"p" is just to visually distinguish from the host-side tunnel links in logs
		inboundGeneveLinkName := "p" + constants.InboundTun
		outboundGeneveLinkName := "p" + constants.OutboundTun

		// New pod NS SHOULD be empty - but in case it isn't, flush/clean everything we are
		// about to create, ignoring warnings
		//
		// TODO not strictly necessary? A harmless correctness check, at least.
		flushAllRouteTables()

		deleteIPRules([]string{"20000", "20001", "20002", "20003"}, false)

		deleteTunnelLinks(inboundGeneveLinkName, outboundGeneveLinkName, false)

		// Create INBOUND Geneve tunnel (from host)
		inbndTunLink := &netlink.Geneve{
			LinkAttrs: netlink.LinkAttrs{
				Name: inboundGeneveLinkName,
			},
			ID:     1000,
			Remote: net.ParseIP(hostIP),
		}
		log.Debugf("Building inbound tunnel: %+v", inbndTunLink)
		err := netlink.LinkAdd(inbndTunLink)
		if err != nil {
			log.Errorf("failed to add inbound tunnel: %v", err)
		}
		err = netlink.AddrAdd(inbndTunLink, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   net.ParseIP(constants.NodeProxyInboundTunIP),
				Mask: net.CIDRMask(constants.TunPrefix, 32),
			},
		})
		if err != nil {
			log.Errorf("failed to add inbound tunnel address: %v", err)
		}

		// Create OUTBOUND Geneve tunnel (to host)
		outbndTunLink := &netlink.Geneve{
			LinkAttrs: netlink.LinkAttrs{
				Name: outboundGeneveLinkName,
			},
			ID:     1001,
			Remote: net.ParseIP(hostIP),
		}
		log.Debugf("Building outbound tunnel: %+v", outbndTunLink)
		err = netlink.LinkAdd(outbndTunLink)
		if err != nil {
			log.Errorf("failed to add outbound tunnel: %v", err)
		}
		err = netlink.AddrAdd(outbndTunLink, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   net.ParseIP(constants.NodeProxyOutboundTunIP),
				Mask: net.CIDRMask(constants.TunPrefix, 32),
			},
		})
		if err != nil {
			log.Errorf("failed to add outbound tunnel address: %v", err)
		}

		log.Debugf("Bringing up inbound tunnel: %+v", inbndTunLink)
		// Bring the tunnels up
		err = netlink.LinkSetUp(inbndTunLink)
		if err != nil {
			log.Errorf("failed to set inbound tunnel up: %v", err)
		}
		log.Debugf("Bringing up outbound tunnel: %+v", outbndTunLink)
		err = netlink.LinkSetUp(outbndTunLink)
		if err != nil {
			log.Errorf("failed to set outbound tunnel up: %v", err)
		}

		// Turn OFF  reverse packet filtering for the tunnels
		// This is required for iptables impl, but not for eBPF impl
		log.Debugf("Disabling '/rp_filter' for inbound and outbound tunnels")
		procs := map[string]int{
			"/proc/sys/net/ipv4/conf/" + outbndTunLink.Name + "/rp_filter": 0,
			"/proc/sys/net/ipv4/conf/" + inbndTunLink.Name + "/rp_filter":  0,
		}
		for proc, val := range procs {
			err = SetProc(proc, fmt.Sprint(val))
			if err != nil {
				log.Errorf("failed to write to proc file %s: %v", proc, err)
			}
		}

		// Set up tproxy marks
		err = addTProxyMarks()
		if err != nil {
			return fmt.Errorf("failed to add TPROXY mark rules: %v", err)
		}

		loopbackLink, err := netlink.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("failed to find 'lo' link: %v", err)
		}

		// Set up netlink routes for localhost
		// TODO IPv6, append "0::0/0"
		cidrs := []string{"0.0.0.0/0"}
		for _, fullCIDR := range cidrs {
			_, localhostDst, err := net.ParseCIDR(fullCIDR)
			if err != nil {
				return fmt.Errorf("parse CIDR: %v", err)
			}

			netlinkRoutes := []*netlink.Route{
				// In routing table ${INBOUND_TPROXY_ROUTE_TABLE}, create a single default rule to route all traffic to
				// the loopback interface.
				// Equiv: "ip route add local 0.0.0.0/0 dev lo table 100"
				{
					Dst:       localhostDst,
					Scope:     netlink.SCOPE_HOST,
					Type:      unix.RTN_LOCAL,
					Table:     constants.RouteTableInbound,
					LinkIndex: loopbackLink.Attrs().Index,
				},
				// Send to localhost, if it came via OutboundTunIP
				// Equiv: "ip route add table 101 0.0.0.0/0 via $OUTBOUND_TUN_IP dev p$OUTBOUND_TUN"
				{
					Dst:       localhostDst,
					Gw:        net.ParseIP(constants.OutboundTunIP),
					Type:      unix.RTN_UNICAST,
					Table:     constants.RouteTableOutbound,
					LinkIndex: outbndTunLink.Attrs().Index,
				},
				// Send to localhost, if it came via InboundTunIP
				// Equiv: "ip route add table 102 0.0.0.0/0 via $INBOUND_TUN_IP dev p$INBOUND_TUN"
				{
					Dst:       localhostDst,
					Gw:        net.ParseIP(constants.InboundTunIP),
					Type:      unix.RTN_UNICAST,
					Table:     constants.RouteTableProxy,
					LinkIndex: inbndTunLink.Attrs().Index,
				},
			}

			for _, route := range netlinkRoutes {
				log.Debugf("Adding netlink route : %+v", route)
				if err := netlink.RouteAdd(route); err != nil {
					// TODO clear this route every time
					// Would not expect this if we have properly cleared routes
					log.Errorf("Failed to add netlink route : %+v", route)
					return fmt.Errorf("failed to add route: %v", err)
				}
			}
		}

		log.Debugf("Finding link and parsing host IP")
		_, parsedHostIPNet, err := net.ParseCIDR(hostIP + "/32")
		if err != nil {
			return fmt.Errorf("could not parse host IP %s: %v", hostIP, err)
		}

		vethLink, err := netlink.LinkByIndex(proxyNsVethIdx)
		if err != nil {
			return fmt.Errorf("failed to find veth with index '%d' within namespace %s: %v", proxyNsVethIdx, nodeProxyNetNS, err)
		}
		netlinkHostRoutes := []*netlink.Route{
			// Send to localhost, if it came via InboundTunIP
			// Equiv: "ip route add table 101 $HOST_IP dev eth0 scope link"
			{
				Dst:       parsedHostIPNet,
				Scope:     netlink.SCOPE_LINK,
				Type:      unix.RTN_UNICAST,
				Table:     constants.RouteTableOutbound,
				LinkIndex: vethLink.Attrs().Index,
			},
			// Send to localhost, if it came via InboundTunIP
			// Equiv: "ip route add table 102 $HOST_IP dev eth0 scope link"
			{
				Dst:       parsedHostIPNet,
				Scope:     netlink.SCOPE_LINK,
				Type:      unix.RTN_UNICAST,
				Table:     constants.RouteTableProxy,
				LinkIndex: vethLink.Attrs().Index,
			},
		}

		for _, route := range netlinkHostRoutes {
			log.Debugf("Adding netlink HOST_IP routes : %+v", route)
			if err := netlink.RouteAdd(route); err != nil {
				// TODO clear this route every time
				// Would not expect this if we have properly cleared routes
				return fmt.Errorf("failed to add host route: %v", err)
			}
		}

		log.Debugf("Preparing to apply iptables rules")
		// Flush prerouting and output table - this should be a new pod netns and it should be clean, but just to be safe..
		err = execute(s.IptablesCmd(), "-t", "mangle", "-F", "PREROUTING")
		if err != nil {
			return fmt.Errorf("failed to configure iptables rule: %v", err)
		}
		err = execute(s.IptablesCmd(), "-t", "nat", "-F", "OUTPUT")
		if err != nil {
			return fmt.Errorf("failed to configure iptables rule: %v", err)
		}

		// Set up append rules
		appendRules := []*iptablesRule{
			// Set tproxy mark on anything going to inbound port via the tunnel link and set it to ztunnel
			newIptableRule(
				constants.TableMangle,
				"PREROUTING",
				"-p", "tcp",
				"-i", inbndTunLink.Name,
				"-m", "tcp",
				"--dport", fmt.Sprintf("%d", constants.NodeProxyInboundPort),
				"-j", "TPROXY",
				"--tproxy-mark", fmt.Sprintf("0x%x", constants.TProxyMark)+"/"+fmt.Sprintf("0x%x", constants.TProxyMask),
				"--on-port", fmt.Sprintf("%d", constants.NodeProxyInboundPort),
				"--on-ip", "127.0.0.1",
			),
			// Set tproxy mark on anything coming from outbound tunnel link, and forward it to the ztunnel outbound port
			newIptableRule(
				constants.TableMangle,
				"PREROUTING",
				"-p", "tcp",
				"-i", outbndTunLink.Name,
				"-j", "TPROXY",
				"--tproxy-mark", fmt.Sprintf("0x%x", constants.TProxyMark)+"/"+fmt.Sprintf("0x%x", constants.TProxyMask),
				"--on-port", fmt.Sprintf("%d", constants.NodeProxyOutboundPort),
				"--on-ip", "127.0.0.1",
			),
			// Same mark, but on plaintext port
			newIptableRule(
				constants.TableMangle,
				"PREROUTING",
				"-p", "tcp",
				"-i", inbndTunLink.Name,
				"-j", "TPROXY",
				"--tproxy-mark", fmt.Sprintf("0x%x", constants.TProxyMark)+"/"+fmt.Sprintf("0x%x", constants.TProxyMask),
				"--on-port", fmt.Sprintf("%d", constants.NodeProxyInboundPlaintextPort),
				"--on-ip", "127.0.0.1",
			),
			// For anything NOT going to the nodeproxy IP, add the OrgSrcRet mark
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

		log.Debugf("Adding iptables rules")
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
		return fmt.Errorf("failed to configure nodeproxy via iptables from within ns(%s): %v", ns, err)
	}

	return nil
}

func (s *Server) updatePodEbpfOnNode(pod *corev1.Pod) error {
	if s.ebpfServer == nil {
		return fmt.Errorf("uninitialized ebpf server")
	}

	ip := pod.Status.PodIP
	if ip == "" {
		log.Debugf("skip adding pod %s/%s, IP not yet allocated", pod.Name, pod.Namespace)
		return nil
	}

	args, err := buildEbpfArgsByIP(ip, false, false)
	if err != nil {
		return err
	}

	log.Debugf("update POD ebpf args: %+v", args)
	s.ebpfServer.AcceptRequest(args)
	return nil
}

func (s *Server) delPodEbpfOnNode(ip string) error {
	if s.ebpfServer == nil {
		return fmt.Errorf("uninitialized ebpf server")
	}

	if ip == "" {
		log.Debugf("nothing could be performed to delete ebpf for empty ip")
		return nil
	}
	ipAddr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("failed to parse ip(%s): %v", ip, err)
	}

	ifIndex := 0

	if veth, err := getVethWithDestinationOf(ip); err != nil {
		log.Debugf("failed to get device: %v", err)
	} else {
		ifIndex = veth.Attrs().Index
	}

	args := &ebpf.RedirectArgs{
		IPAddrs:     []netip.Addr{ipAddr},
		Ifindex:     ifIndex,
		IsNodeProxy: false,
		Remove:      true,
	}
	log.Debugf("del POD ebpf args: %+v", args)
	s.ebpfServer.AcceptRequest(args)
	return nil
}
