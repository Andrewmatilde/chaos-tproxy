// chaos-tproxy iptables-redirect loader (istio-style).
//
// Deploy:
//   docker run --rm --privileged \
//              --network=container:<target> --pid=container:<target> \
//              -v /path/chaos.yaml:/etc/chaos.yaml:ro \
//              chaos-mesh/tproxy-iptables --config /etc/chaos.yaml
//
// We're already inside the target container's netns. We install
// iptables NAT REDIRECT + fwmark routing inside that netns, spawn
// chaos-tproxy-proxy in the same netns, and tear down on exit.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-iptables-loader/internal/config"
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

	rcfg := rules.Config{
		ProxyMark:  cfg.ProxyMark,
		ConnMark:   0x111,
		ListenPort: cfg.ListenPort(),
		ProxyPorts: ports,
	}

	// Best-effort: wipe any stale rules left over from a previous run.
	rules.Uninstall(rcfg)
	if err := rules.Install(rcfg); err != nil {
		return fmt.Errorf("install iptables rules: %w", err)
	}
	defer rules.Uninstall(rcfg)
	fmt.Fprintln(os.Stderr, "iptables rules installed")

	// Build proxy payload by forwarding the inline YAML keys + injecting
	// proxy_mark so the proxy's onward sockets carry SO_MARK.
	payload := map[string]interface{}{}
	for k, v := range cfg.Proxy {
		payload[k] = v
	}
	payload["proxy_mark"] = cfg.ProxyMark

	sp := &proxy.Spawner{BinaryPath: proxyBin}
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
