// Package injector orchestrates the BPF + proxy lifecycle for a single
// target container.
//
// One Inject() call == one chaos injection: enter the target's netns,
// build a sibling chaosns + veth, load and attach the BPF programs,
// spawn the chaos-tproxy proxy inside chaosns, then block on ctx until
// the caller cancels (Ctrl-C or daemon-mode SIGTERM). All resources are
// torn down on return.
package injector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	vnetns "github.com/vishvananda/netns"

	"github.com/Andrewmatilde/chaos-tproxy/internal/ebpf/bpfload"
	"github.com/Andrewmatilde/chaos-tproxy/internal/ebpf/config"
	"github.com/Andrewmatilde/chaos-tproxy/internal/ebpf/netns"
	"github.com/Andrewmatilde/chaos-tproxy/internal/ebpf/proxy"
	"github.com/Andrewmatilde/chaos-tproxy/internal/ebpf/tc"
	rt "github.com/Andrewmatilde/chaos-tproxy/internal/runtime"
)

// Options is what `chaos-tproxy run` hands to the injector.
type Options struct {
	Target   *rt.Container // resolved container (PID + netns)
	Config   *config.Loader
	ProxyBin string // path to chaos-tproxy proxy binary
}

// bpfParams must match the params_map struct in bpf/redirect.bpf.c.
type bpfParams struct {
	ProxyMark   uint32
	NginxIP     uint32 // network byte order
	Dae0Ifindex uint32
	Eth0Ifindex uint32
	LoIfindex   uint32
	Dae0PeerMAC [6]byte
	_           [2]byte // padding
	Eth0MAC     [6]byte
	_           [2]byte // padding
}

// Inject runs the full injection flow. Blocks until ctx is cancelled or
// the proxy child exits. Returns the proxy's exit error (nil on clean
// cancellation).
func Inject(ctx context.Context, opts Options) error {
	if opts.Target == nil {
		return fmt.Errorf("injector: nil Target")
	}
	if opts.Config == nil {
		return fmt.Errorf("injector: nil Config")
	}
	if opts.ProxyBin == "" {
		opts.ProxyBin = "/usr/local/bin/chaos-tproxy"
	}

	cfg := opts.Config
	ports, err := cfg.ProxyPorts()
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		return fmt.Errorf("proxy_ports must list at least one port")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	// Enter the target container's netns up front and stay there for
	// everything that touches in-netns kernel objects (chaosns setup,
	// TC attach, sysctls, listener auto-detection). LockOSThread is
	// required because Set() pins to the current OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hostNs, err := vnetns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer hostNs.Close()

	targetNs, err := vnetns.GetFromPath(opts.Target.NetnsPath)
	if err != nil {
		return fmt.Errorf("open target netns %s: %w", opts.Target.NetnsPath, err)
	}
	defer targetNs.Close()
	if err := vnetns.Set(targetNs); err != nil {
		return fmt.Errorf("enter target netns: %w", err)
	}
	defer vnetns.Set(hostNs)

	// From here on we're in the target container's netns. Auto-detect
	// the in-container service IP unless the user supplied one.
	rawIP, ok := cfg.Proxy["nginx_ip"].(string)
	if !ok || rawIP == "" {
		ifaceIP, err := primaryIPv4(cfg.IfaceWAN)
		if err != nil {
			return fmt.Errorf("auto-detect target IP on %s: %w; set nginx_ip in config", cfg.IfaceWAN, err)
		}
		rawIP = ifaceIP.String()
		fmt.Fprintf(os.Stderr, "auto-detected target IP %s on %s\n", rawIP, cfg.IfaceWAN)
	}
	nginxIP := net.ParseIP(rawIP).To4()
	if nginxIP == nil {
		return fmt.Errorf("invalid target IP %q", rawIP)
	}

	// Build chaosns sibling + veth.
	ns, err := netns.Setup(cfg.IfaceWAN)
	if err != nil {
		return fmt.Errorf("setup chaosns: %w", err)
	}
	defer ns.Teardown()

	// Permissive sysctls in target netns so packets bounced to lo with
	// non-loopback src IPs are accepted by the kernel.
	for _, kv := range []struct{ path, val string }{
		{"/proc/sys/net/ipv4/conf/all/rp_filter", "0"},
		{"/proc/sys/net/ipv4/conf/lo/rp_filter", "0"},
		{"/proc/sys/net/ipv4/conf/eth0/rp_filter", "0"},
		{"/proc/sys/net/ipv4/conf/all/accept_local", "1"},
		{"/proc/sys/net/ipv4/conf/lo/accept_local", "1"},
		{"/proc/sys/net/ipv4/conf/eth0/accept_local", "1"},
		{"/proc/sys/net/ipv4/ip_forward", "1"},
	} {
		_ = os.WriteFile(kv.path, []byte(kv.val), 0644)
	}

	// Load BPF objects. Programs are netns-agnostic until attached.
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

	if fn, err := tc.Attach(cfg.IfaceWAN, tc.Ingress, objs.TcEth0Ingress); err != nil {
		return fmt.Errorf("attach eth0 ingress: %w", err)
	} else {
		detachFns = append(detachFns, fn)
	}
	if fn, err := tc.Attach(cfg.IfaceWAN, tc.Egress, objs.TcEth0Egress); err != nil {
		return fmt.Errorf("attach eth0 egress: %w", err)
	} else {
		detachFns = append(detachFns, fn)
	}
	if fn, err := tc.Attach(netns.HostVethName, tc.Ingress, objs.TcDae0Ingress); err != nil {
		return fmt.Errorf("attach dae0 ingress: %w", err)
	} else {
		detachFns = append(detachFns, fn)
	}

	// dae0peer ingress lives in chaosns.
	if err := withNetns(ns.ChaosNs, func() error {
		fn, err := tc.Attach(netns.NsVethName, tc.Ingress, objs.TcDae0peerIngress)
		if err != nil {
			return err
		}
		chaosNs := ns.ChaosNs
		detachFns = append(detachFns, func() error {
			return withNetns(chaosNs, func() error { return fn() })
		})
		return nil
	}); err != nil {
		return fmt.Errorf("attach dae0peer ingress: %w", err)
	}
	fmt.Fprintln(os.Stderr, "BPF programs attached")

	// Build proxy payload — forward Proxy verbatim, strip loader-only
	// keys, inject proxy_mark.
	payload := map[string]any{}
	for k, v := range cfg.Proxy {
		payload[k] = v
	}
	delete(payload, "nginx_ip")
	payload["proxy_mark"] = cfg.ProxyMark

	sp := &proxy.Spawner{
		BinaryPath: opts.ProxyBin,
		Netns:      ns.ChaosNs,
	}
	if err := sp.Start(payload); err != nil {
		return fmt.Errorf("spawn proxy: %w", err)
	}
	defer sp.Stop()

	fmt.Fprintf(os.Stderr, "chaos injected into %s/%s (runtime=%s, pid=%d)\n",
		opts.Target.Runtime, opts.Target.Name, opts.Target.Runtime, opts.Target.PID)

	// ARP poller: install static ARP for each client we observe, so
	// nginx's reply path can resolve the (forged) source without going
	// out for ARP (which would fail).
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
