// chaos-tproxy iptables loader, dae-style topology + iptables datapath.
//
// Deploy:
//   docker run --rm --privileged \
//              --network=container:<target> --pid=container:<target> \
//              -v /path/chaos.yaml:/etc/chaos.yaml:ro \
//              chaos-mesh/tproxy-iptables --config /etc/chaos.yaml
//
// We're already inside the target container's netns. We build a sibling
// chaosns sub-netns and a dae0/dae0peer veth, then steer inbound traffic
// from the target netns to chaosns purely with iptables MARK + ip rule,
// no BPF. chaos-tproxy-proxy lives inside chaosns and listens with
// IP_TRANSPARENT; TPROXY in chaosns hands packets to it.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	vnetns "github.com/vishvananda/netns"

	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-iptables-loader/internal/config"
	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-iptables-loader/internal/netns"
	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-iptables-loader/internal/proxy"
	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-iptables-loader/internal/rules"
)

func main() {
	cfgPath := flag.String("config", "/etc/chaos.yaml", "YAML config")
	proxyBin := flag.String("proxy-bin", "/usr/local/bin/chaos-tproxy", "proxy binary")
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

	// 1. Build chaosns + dae0/dae0peer veth + chaosns routing.
	ns, err := netns.Setup(cfg.IfaceWAN)
	if err != nil {
		return fmt.Errorf("setup chaosns: %w", err)
	}
	defer ns.Teardown()

	// 2. Install steering rules in the target netns (current netns).
	if err := rules.InstallTargetNs(rules.TargetNsConfig{
		ProxyPorts: ports,
		Dae0Index:  ns.Dae0.Attrs().Index,
	}); err != nil {
		return fmt.Errorf("install target-ns rules: %w", err)
	}
	defer rules.UninstallTargetNs()
	fmt.Fprintln(os.Stderr, "target netns rules installed")

	// 3. Install TPROXY rules INSIDE chaosns.
	if err := withNetns(ns.ChaosNs, func() error {
		return rules.InstallChaosNs(rules.ChaosNsConfig{
			ProxyPorts: ports,
			ListenPort: cfg.ListenPort(),
		})
	}); err != nil {
		return fmt.Errorf("install chaosns rules: %w", err)
	}
	defer func() {
		_ = withNetns(ns.ChaosNs, func() error {
			rules.UninstallChaosNs()
			return nil
		})
	}()
	fmt.Fprintln(os.Stderr, "chaosns rules installed")

	// 4. Spawn proxy inside chaosns.
	payload := map[string]interface{}{}
	for k, v := range cfg.Proxy {
		payload[k] = v
	}
	payload["proxy_mark"] = uint32(rules.ProxyMark)

	sp := &proxy.Spawner{
		BinaryPath: proxyBin,
		Netns:      ns.ChaosNs,
	}
	if err := sp.Start(payload); err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}
	defer sp.Stop()

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintln(os.Stderr, "chaos-tproxy iptables loader ready")

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
