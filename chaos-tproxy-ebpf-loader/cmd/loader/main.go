// chaos-tproxy eBPF loader — dae-style.
//
// Deploy: docker run --rm --privileged \
//                    --network=container:<target> --pid=container:<target> \
//                    -v /sys/fs/bpf:/sys/fs/bpf \
//                    -v /path/chaos.yaml:/etc/chaos.yaml:ro \
//                    chaos-mesh/tproxy-ebpf --config /etc/chaos.yaml
//
// We're already inside the target's netns. We build a sibling 'chaosns'
// netns + dae0/dae0peer veth, attach BPF on eth0+dae0+(in chaosns)dae0peer,
// and spawn chaos-tproxy-proxy inside chaosns.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	vnetns "github.com/vishvananda/netns"

	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-ebpf-loader/internal/bpfload"
	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-ebpf-loader/internal/config"
	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-ebpf-loader/internal/netns"
	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-ebpf-loader/internal/proxy"
	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-ebpf-loader/internal/tc"
)

// must match the params_map struct in bpf/redirect.bpf.c.
type bpfParams struct {
	ProxyMark    uint32
	NginxIP      uint32   // network byte order
	Dae0Ifindex  uint32
	Eth0Ifindex  uint32
	LoIfindex    uint32
	Dae0PeerMAC  [6]byte
	_            [2]byte // padding
	Eth0MAC      [6]byte
	_            [2]byte // padding
}

func main() {
	cfgPath := flag.String("config", "/etc/chaos.yaml", "loader YAML config")
	proxyBin := flag.String("proxy-bin", "/usr/local/bin/chaos-tproxy", "chaos-tproxy binary")
	flag.Parse()
	if err := run(*cfgPath, *proxyBin); err != nil {
		fmt.Fprintf(os.Stderr, "loader: %v\n", err)
		os.Exit(1)
	}
}

func run(cfgPath, proxyBin string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	ports, err := cfg.ProxyPorts()
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		return fmt.Errorf("proxy_ports must list at least one port")
	}

	// Resolve nginx IP. For v1 we trust the caller to supply it via the
	// YAML 'nginx_ip' field. The loader is already in the target netns,
	// so this is the target container's eth0 IP.
	rawIP, ok := cfg.Proxy["nginx_ip"].(string)
	if !ok || rawIP == "" {
		// Auto-discover: take the first non-loopback IPv4 on eth0.
		ifaceIP, err := primaryIPv4(cfg.IfaceWAN)
		if err != nil {
			return fmt.Errorf("auto-detect nginx_ip on %s: %w; please set nginx_ip in config", cfg.IfaceWAN, err)
		}
		rawIP = ifaceIP.String()
		fmt.Fprintf(os.Stderr, "auto-detected nginx_ip=%s on %s\n", rawIP, cfg.IfaceWAN)
	}
	nginxIP := net.ParseIP(rawIP).To4()
	if nginxIP == nil {
		return fmt.Errorf("invalid nginx_ip %q", rawIP)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	// Build chaosns + veth + routes. This LockOSThreads us; keep it locked
	// while we attach BPF programs (because dae0peer attach must happen
	// from inside chaosns).
	ns, err := netns.Setup(cfg.IfaceWAN)
	if err != nil {
		return fmt.Errorf("setup chaosns: %w", err)
	}
	defer ns.Teardown()

	// Permissive sysctls in target netns so packets we redirect to lo
	// (from chaosns toward nginx) with non-loopback src IPs are accepted.
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/lo/rp_filter", []byte("0"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/eth0/rp_filter", []byte("0"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/accept_local", []byte("1"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/lo/accept_local", []byte("1"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/eth0/accept_local", []byte("1"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)

	// Load BPF objects (in host netns; programs are netns-agnostic until attached).
	var objs bpfload.RedirectObjects
	if err := bpfload.LoadRedirectObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	// Populate params_map.
	loIface, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("look up lo: %w", err)
	}
	params := bpfParams{
		ProxyMark:   cfg.ProxyMark,
		NginxIP:     binary.LittleEndian.Uint32(nginxIP),
		Dae0Ifindex: uint32(ns.Dae0.Attrs().Index),
		Eth0Ifindex: uint32(ns.Eth0.Attrs().Index),
		LoIfindex:   uint32(loIface.Index),
	}
	copy(params.Dae0PeerMAC[:], ns.PeerMac)
	copy(params.Eth0MAC[:], ns.Eth0.Attrs().HardwareAddr)
	if err := objs.ParamsMap.Update(uint32(0), params, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update params_map: %w", err)
	}

	// proxy_ports — store with bytes in network byte order (htons).
	one := uint8(1)
	for _, p := range ports {
		key := (p << 8) | (p >> 8) // htons on a little-endian host
		if err := objs.ProxyPorts.Update(key, one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update proxy_ports: %w", err)
		}
	}

	// Attach BPF programs.
	detachFns := []func() error{}
	defer func() {
		for i := len(detachFns) - 1; i >= 0; i-- {
			_ = detachFns[i]()
		}
	}()

	// eth0 ingress — in host (target) netns. We're already there.
	if fn, err := tc.Attach(cfg.IfaceWAN, tc.Ingress, objs.TcEth0Ingress); err != nil {
		return fmt.Errorf("attach eth0 ingress: %w", err)
	} else {
		detachFns = append(detachFns, fn)
	}
	// eth0 egress — catches nginx's reply to the proxy's forged connection.
	if fn, err := tc.Attach(cfg.IfaceWAN, tc.Egress, objs.TcEth0Egress); err != nil {
		return fmt.Errorf("attach eth0 egress: %w", err)
	} else {
		detachFns = append(detachFns, fn)
	}
	// dae0 ingress — also in host (target) netns.
	if fn, err := tc.Attach(netns.HostVethName, tc.Ingress, objs.TcDae0Ingress); err != nil {
		return fmt.Errorf("attach dae0 ingress: %w", err)
	} else {
		detachFns = append(detachFns, fn)
	}

	// dae0peer ingress — must attach from inside chaosns.
	if err := withNetns(ns.ChaosNs, func() error {
		fn, err := tc.Attach(netns.NsVethName, tc.Ingress, objs.TcDae0peerIngress)
		if err != nil {
			return err
		}
		// Wrap fn so it also runs inside chaosns at teardown.
		chaosNs := ns.ChaosNs
		detachFns = append(detachFns, func() error {
			return withNetns(chaosNs, func() error { return fn() })
		})
		return nil
	}); err != nil {
		return fmt.Errorf("attach dae0peer ingress: %w", err)
	}
	fmt.Fprintln(os.Stderr, "BPF programs attached")

	// Build proxy payload (passed via the existing UDS protocol).
	payload := map[string]interface{}{}
	for k, v := range cfg.Proxy {
		payload[k] = v
	}
	// Strip our own keys before forwarding.
	delete(payload, "nginx_ip")
	payload["proxy_mark"] = cfg.ProxyMark

	// Spawn the proxy *inside chaosns*. The Spawner needs to fork the child
	// in chaosns; the simplest correct way is to enter chaosns ourselves
	// for the fork+exec, then return.
	sp := &proxy.Spawner{
		BinaryPath: proxyBin,
		Netns:      ns.ChaosNs,
	}
	fdCh := make(chan int, 1)
	sp.OnListenerFD(func(fd int) { fdCh <- fd })
	if err := sp.Start(payload); err != nil {
		return fmt.Errorf("spawn proxy: %w", err)
	}
	defer sp.Stop()

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		return nil
	case fd := <-fdCh:
		if err := objs.ListenSocketMap.Update(uint32(0), uint64(fd),
			ebpf.UpdateAny); err != nil {
			return fmt.Errorf("populate listen_socket_map: %w", err)
		}
		_ = syscall.Close(fd)
		fmt.Fprintln(os.Stderr, "listener fd inserted into SOCKMAP")
	}

	fmt.Fprintln(os.Stderr, "chaos-tproxy eBPF loader ready")

	// Start a goroutine that polls flow_l2 and installs static ARP
	// entries for every client we've seen. This lets nginx's reply to
	// the proxy's forged connection get its dst MAC resolved without
	// triggering an ARP request (which would fail because the kernel
	// never saw the client's incoming packet).
	go arpPoller(ctx, ns, &objs)

	errCh := make(chan error, 1)
	go func() { errCh <- sp.Wait(ctx) }()
	select {
	case <-ctx.Done():
		_ = sp.Wait(context.Background())
		return nil
	case err := <-errCh:
		return err
	}
}

// arpPoller scans flow_l2 every 200ms and installs static ARP for each
// (client_ip, client_mac) it finds.
func arpPoller(ctx context.Context, ns *netns.Handles, objs *bpfload.RedirectObjects) {
	seen := map[uint32]bool{}
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var k struct {
			ClientIP   uint32
			NginxIP    uint32
			ClientPort uint16
			NginxPort  uint16
		}
		var v struct {
			OrigSMAC [6]byte
			OrigDMAC [6]byte
		}
		it := objs.FlowL2.Iterate()
		for it.Next(&k, &v) {
			if seen[k.ClientIP] {
				continue
			}
			seen[k.ClientIP] = true
			ip := net.IPv4(byte(k.ClientIP), byte(k.ClientIP>>8),
				byte(k.ClientIP>>16), byte(k.ClientIP>>24))
			mac := net.HardwareAddr(v.OrigSMAC[:])
			if err := ns.AddTargetARP(ip, mac); err != nil {
				fmt.Fprintf(os.Stderr, "static ARP %s -> %s failed: %v\n", ip, mac, err)
			} else {
				fmt.Fprintf(os.Stderr, "static ARP %s -> %s installed\n", ip, mac)
			}
		}
	}
}

// withNetns runs fn while temporarily switched into target netns.
// LockOSThread'd; caller's thread returns to whatever ns it was in.
func withNetns(target vnetns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	prev, err := vnetns.Get()
	if err != nil {
		return err
	}
	defer prev.Close()
	if err := vnetns.Set(target); err != nil {
		return fmt.Errorf("set target ns: %w", err)
	}
	defer vnetns.Set(prev)
	return fn()
}

// primaryIPv4 returns the first non-link-local IPv4 address on ifname.
func primaryIPv4(ifname string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip, nil
	}
	return nil, fmt.Errorf("no IPv4 address on %s", ifname)
}
