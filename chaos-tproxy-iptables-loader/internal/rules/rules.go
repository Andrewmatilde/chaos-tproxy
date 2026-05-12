// Package rules installs and tears down the iptables-based traffic
// redirection for chaos-tproxy. Uses dae's two-netns topology
// (chaosns inside the target's netns) but replaces dae's BPF datapath
// with iptables + policy routing.
//
// Data flow:
//
//   client → target eth0
//     ↓
//   [target netns]
//     mangle PREROUTING: --dport 80 -j MARK --set-mark 0xCFC1
//     ip rule fwmark 0xCFC1 lookup 100
//     ip route default via 169.254.0.1 dev dae0 table 100
//     ↓ packet leaves via dae0 veth into chaosns
//
//   [chaosns netns]
//     (TPROXY-style: fwmark + lookup local default dev lo)
//     iptables -t mangle PREROUTING -p tcp --dport 80
//       -j TPROXY --on-port 58080 --tproxy-mark 0x8000000
//     ip rule fwmark 0x8000000 lookup 2023
//     ip route add local default dev lo table 2023
//     ↓ kernel delivers to IP_TRANSPARENT listener on :58080
//
//   proxy in chaosns: accept; original 5-tuple preserved.
//   proxy out: bind(client_ip, client_port) + connect(nginx_ip, 80)
//   with SO_MARK=0xCFC1 so chaosns mangle exempts it.
//   ↓ packet exits chaosns via dae0peer → dae0 → target netns
//   ↓ target netns: routes via main table (default eth0) to docker bridge
//   ↓ docker bridge hairpins back to same target eth0 (or directly to nginx)
//   ↓ nginx receives with src=real client_ip.

package rules

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Constants shared with the netns package.
const (
	ProxyMark        uint32 = 0xCFC1     // proxy's own SO_MARK; identifies proxy-originated traffic
	TproxyMark       uint32 = 0x8000000  // TPROXY mark used in chaosns (matches dae)
	TproxyRouteTable        = 2023       // chaosns local-default routing table
	WanRouteTable           = 100        // target netns routing table for inbound steering
	MarkMask         uint32 = 0xFFFFFFFF
)

// TargetNsConfig is what we install in the target netns to steer
// inbound traffic to chaosns.
type TargetNsConfig struct {
	ProxyPorts []uint16 // ports to capture (e.g. [80])
	Dae0Index  int      // dae0 ifindex in target netns
}

// InstallTargetNs sets up traffic steering in the *current* netns
// (must be target netns when called).
func InstallTargetNs(cfg TargetNsConfig) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("new iptables: %w", err)
	}

	// Permissive sysctls in target netns so reply traffic from chaosns
	// (src = nginx's own IP arriving on dae0) isn't dropped as spoofed.
	_ = setSysctl("net.ipv4.conf.all.rp_filter", "0")
	_ = setSysctl("net.ipv4.conf.dae0.rp_filter", "0")
	_ = setSysctl("net.ipv4.conf.eth0.rp_filter", "0")
	_ = setSysctl("net.ipv4.conf.all.accept_local", "1")
	_ = setSysctl("net.ipv4.conf.dae0.accept_local", "1")
	_ = setSysctl("net.ipv4.conf.eth0.accept_local", "1")
	_ = setSysctl("net.ipv4.ip_forward", "1")

	// Custom chains in mangle for cleanup safety.
	_ = ipt.NewChain("mangle", "CHAOS_PRERT")

	mark := fmt.Sprintf("0x%x/0x%x", TproxyMark, MarkMask)

	// mangle PREROUTING: any inbound packet to a proxied port gets
	// our mark. Skip if the packet already carries our mark (a
	// defensive measure in case something else re-injects).
	for _, port := range cfg.ProxyPorts {
		if err := ipt.AppendUnique("mangle", "CHAOS_PRERT",
			"-p", "tcp",
			"--dport", strconv.Itoa(int(port)),
			"-m", "mark", "!", "--mark", mark,
			"-j", "MARK", "--set-mark", fmt.Sprintf("0x%x", TproxyMark),
		); err != nil {
			return fmt.Errorf("mangle CHAOS_PRERT mark: %w", err)
		}
	}

	// Hook into PREROUTING.
	if err := ipt.AppendUnique("mangle", "PREROUTING", "-j", "CHAOS_PRERT"); err != nil {
		return fmt.Errorf("hook mangle PREROUTING: %w", err)
	}

	// Policy route: marked traffic goes to table WanRouteTable.
	//
	// IMPORTANT: priority must be lower than the default `local` rule
	// (priority 0) because dst IP is the container's own eth0 IP, which
	// matches the `local` table and would be delivered locally before
	// reaching our fwmark rule. We move our rule to priority 1 and
	// (re-)insert the local rule at higher priority so it doesn't catch
	// us first.
	//
	// Linux pre-installs `0: from all lookup local` automatically. To
	// override its priority we must add a copy with a different priority
	// and (separately) remove the priority-0 one. The kernel allows
	// multiple rules pointing at the same table.
	localRule := netlink.NewRule()
	localRule.Family = unix.AF_INET
	localRule.Table = 255 // RT_TABLE_LOCAL
	localRule.Priority = 32765
	_ = netlink.RuleDel(localRule)
	if err := netlink.RuleAdd(localRule); err != nil {
		return fmt.Errorf("re-add local rule at lower priority: %w", err)
	}
	// Now delete the original priority-0 local rule. After this the
	// local table is consulted only at priority 32765, after our
	// fwmark rule.
	origLocal := netlink.NewRule()
	origLocal.Family = unix.AF_INET
	origLocal.Table = 255
	origLocal.Priority = 0
	_ = netlink.RuleDel(origLocal)

	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Table = WanRouteTable
	rule.Mark = int(TproxyMark)
	rule.Mask = int(MarkMask)
	rule.Priority = 1
	_ = netlink.RuleDel(rule)
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("ip rule fwmark in target ns: %w", err)
	}

	// Route table: marked packets go out dae0 (will arrive in chaosns
	// via the veth peer). 169.254.0.1 is dae0peer's static-neigh gw.
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: cfg.Dae0Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:        net.ParseIP("169.254.0.1"),
		Table:     WanRouteTable,
	}); err != nil {
		return fmt.Errorf("ip route default via dae0 table %d: %w", WanRouteTable, err)
	}

	return nil
}

func UninstallTargetNs() {
	ipt, _ := iptables.New()
	if ipt != nil {
		_ = ipt.Delete("mangle", "PREROUTING", "-j", "CHAOS_PRERT")
		_ = ipt.ClearChain("mangle", "CHAOS_PRERT")
		_ = ipt.DeleteChain("mangle", "CHAOS_PRERT")
	}
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Table = WanRouteTable
	rule.Mark = int(TproxyMark)
	rule.Mask = int(MarkMask)
	rule.Priority = 1
	_ = netlink.RuleDel(rule)

	// Restore original local rule at priority 0.
	localRule := netlink.NewRule()
	localRule.Family = unix.AF_INET
	localRule.Table = 255
	localRule.Priority = 0
	_ = netlink.RuleAdd(localRule)
	// Remove our priority-32765 copy.
	localRule.Priority = 32765
	_ = netlink.RuleDel(localRule)
}

// ChaosNsConfig is what we install inside chaosns.
type ChaosNsConfig struct {
	ProxyPorts []uint16
	ListenPort uint16 // chaos-tproxy-proxy listener port (e.g. 58080)
}

// InstallChaosNs runs INSIDE chaosns (caller must have switched into
// chaosns). Sets up TPROXY-style packet delivery to the local listener
// without rewriting any IP header.
func InstallChaosNs(cfg ChaosNsConfig) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("new iptables in chaosns: %w", err)
	}

	tproxyMarkSpec := fmt.Sprintf("0x%x/0x%x", TproxyMark, MarkMask)
	proxyMarkSpec := fmt.Sprintf("0x%x/0x%x", ProxyMark, MarkMask)
	listen := strconv.Itoa(int(cfg.ListenPort))

	_ = ipt.NewChain("mangle", "CHAOS_PRERT")
	_ = ipt.NewChain("mangle", "CHAOS_DIVERT")

	// DIVERT chain: already-established TPROXY sockets short-circuit.
	// (-m socket matches packets that have an existing matching socket.)
	// Set mark and ACCEPT.
	if err := ipt.AppendUnique("mangle", "CHAOS_DIVERT",
		"-j", "MARK", "--set-mark", fmt.Sprintf("0x%x", TproxyMark),
	); err != nil {
		return fmt.Errorf("divert mark: %w", err)
	}
	if err := ipt.AppendUnique("mangle", "CHAOS_DIVERT",
		"-j", "ACCEPT",
	); err != nil {
		return fmt.Errorf("divert accept: %w", err)
	}

	// Established sockets: divert (skip TPROXY again).
	if err := ipt.AppendUnique("mangle", "CHAOS_PRERT",
		"-p", "tcp",
		"-m", "socket",
		"-j", "CHAOS_DIVERT",
	); err != nil {
		return fmt.Errorf("prert socket -> divert: %w", err)
	}

	// New TCP connections to proxied ports: TPROXY to listen port,
	// marking the packet for the local-route policy below.
	for _, port := range cfg.ProxyPorts {
		if err := ipt.AppendUnique("mangle", "CHAOS_PRERT",
			"-p", "tcp",
			"--dport", strconv.Itoa(int(port)),
			"-j", "TPROXY",
			"--tproxy-mark", fmt.Sprintf("0x%x/0x%x", TproxyMark, MarkMask),
			"--on-port", listen,
		); err != nil {
			return fmt.Errorf("tproxy --dport %d: %w", port, err)
		}
	}

	if err := ipt.AppendUnique("mangle", "PREROUTING", "-j", "CHAOS_PRERT"); err != nil {
		return fmt.Errorf("hook chaosns mangle PRE: %w", err)
	}

	// Avoid the proxy's own outbound connection being re-captured by
	// TPROXY: it carries ProxyMark; let it leave chaosns unchanged.
	// (The mark also exempts it from the fwmark route below.)
	_ = ipt.NewChain("mangle", "CHAOS_OUTPUT")
	if err := ipt.AppendUnique("mangle", "CHAOS_OUTPUT",
		"-m", "mark", "--mark", proxyMarkSpec,
		"-j", "ACCEPT",
	); err != nil {
		return fmt.Errorf("output proxy-mark accept: %w", err)
	}
	if err := ipt.AppendUnique("mangle", "OUTPUT", "-j", "CHAOS_OUTPUT"); err != nil {
		return fmt.Errorf("hook chaosns mangle OUTPUT: %w", err)
	}

	// fwmark routing: any packet with TPROXY mark is treated as local.
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Table = TproxyRouteTable
	rule.Mark = int(TproxyMark)
	rule.Mask = int(MarkMask)
	rule.Priority = 100
	_ = netlink.RuleDel(rule)
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("ip rule fwmark in chaosns: %w", err)
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("look up lo in chaosns: %w", err)
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Scope:     unix.RT_SCOPE_HOST,
		Type:      unix.RTN_LOCAL,
		Table:     TproxyRouteTable,
	}); err != nil {
		return fmt.Errorf("local default dev lo table %d: %w", TproxyRouteTable, err)
	}

	// Permissive sysctls so non-local dst is accepted.
	_ = setSysctl("net.ipv4.ip_forward", "1")
	_ = setSysctl("net.ipv4.conf.all.rp_filter", "0")
	_ = setSysctl("net.ipv4.conf.dae0peer.rp_filter", "0")
	_ = setSysctl("net.ipv4.conf.all.accept_local", "1")

	// Suppress notes about mangle PREROUTING tproxy_mark spec — the
	// tproxy match uses `--tproxy-mark` directly above; keep this
	// var to silence unused.
	_ = tproxyMarkSpec
	return nil
}

func UninstallChaosNs() {
	ipt, _ := iptables.New()
	if ipt != nil {
		_ = ipt.Delete("mangle", "PREROUTING", "-j", "CHAOS_PRERT")
		_ = ipt.Delete("mangle", "OUTPUT", "-j", "CHAOS_OUTPUT")
		_ = ipt.ClearChain("mangle", "CHAOS_PRERT")
		_ = ipt.ClearChain("mangle", "CHAOS_OUTPUT")
		_ = ipt.ClearChain("mangle", "CHAOS_DIVERT")
		_ = ipt.DeleteChain("mangle", "CHAOS_PRERT")
		_ = ipt.DeleteChain("mangle", "CHAOS_OUTPUT")
		_ = ipt.DeleteChain("mangle", "CHAOS_DIVERT")
	}
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Table = TproxyRouteTable
	rule.Mark = int(TproxyMark)
	rule.Mask = int(MarkMask)
	rule.Priority = 100
	_ = netlink.RuleDel(rule)
}

func setSysctl(key, value string) error {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return os.WriteFile(path, []byte(value), 0644)
}
