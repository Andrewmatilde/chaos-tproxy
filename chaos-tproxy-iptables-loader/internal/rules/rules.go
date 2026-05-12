// Package rules installs and removes the iptables NAT REDIRECT rules
// that pull inbound traffic into chaos-tproxy-proxy. Inspired by
// istio/cni/pkg/iptables/iptables.go but trimmed down to the chaos-tproxy
// use case (single target container, single proxy port, one mark).
//
// All rules live in custom chains (CHAOS_PRERT, CHAOS_OUTPUT) jumped to
// from the main chains so teardown can drop our chains without touching
// existing rules.
package rules

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	ChainPrerouting = "CHAOS_PRERT"
	ChainOutput     = "CHAOS_OUTPUT"

	// fwmark routing table for the proxy's reply path.
	RouteTable    = 100
	RoutePriority = 32764
)

// PerListener carries the per-proxy-port configuration.
type Config struct {
	ProxyMark  uint32   // SO_MARK on proxy's onward sockets (e.g. 0xCFC1).
	ConnMark   uint32   // Distinct value stamped into conntrack so reply
	                    // traffic can be identified via CONNMARK restore.
	ListenPort uint16   // chaos-tproxy-proxy listener port.
	ProxyPorts []uint16 // ports to capture (e.g. 80).
}

// ConnmarkMask is the mask we use on packet-mark <-> connmark conversion.
const ConnmarkMask = 0xFFFFFFFF

func proxyMarkSpec(m uint32) string {
	return fmt.Sprintf("0x%x/0x%x", m, ConnmarkMask)
}

// Install adds all rules. Idempotent: existing rules with the same spec
// are skipped.
func Install(cfg Config) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("new iptables handle: %w", err)
	}

	// Create custom chains (idempotent).
	for _, c := range []struct{ table, chain string }{
		{"nat", ChainPrerouting},
		{"nat", ChainOutput},
		{"mangle", ChainPrerouting},
		{"mangle", ChainOutput},
	} {
		_ = ipt.NewChain(c.table, c.chain) // ignore "already exists"
	}

	mark := proxyMarkSpec(cfg.ProxyMark)
	listen := strconv.Itoa(int(cfg.ListenPort))

	// === nat PREROUTING: incoming client → proxy ===
	//
	// For each proxy_port, REDIRECT --to-ports listen_port. Skip packets
	// already carrying our mark — required because loopback traffic
	// passes through OUTPUT *and* PREROUTING; the proxy's onward
	// connection to a local upstream would otherwise be re-captured on
	// the PREROUTING side.
	for _, port := range cfg.ProxyPorts {
		if err := ipt.AppendUnique("nat", ChainPrerouting,
			"-p", "tcp",
			"--dport", strconv.Itoa(int(port)),
			"-m", "mark", "!", "--mark", mark,
			"-j", "REDIRECT",
			"--to-ports", listen,
		); err != nil {
			return fmt.Errorf("nat %s redirect %d: %w", ChainPrerouting, port, err)
		}
	}

	// === nat OUTPUT: proxy → nginx (forged source) ===
	//
	// Reply packets that had their mark restored from CONNMARK:
	// let them through unchanged. This is istio's
	//   -A ISTIO_OUTPUT -p tcp -m mark --mark 0x111/0xfff -j ACCEPT
	connmarkSpec := fmt.Sprintf("0x%x/0x%x", cfg.ConnMark, ConnmarkMask)
	if err := ipt.AppendUnique("nat", ChainOutput,
		"-p", "tcp",
		"-m", "mark", "--mark", connmarkSpec,
		"-j", "ACCEPT",
	); err != nil {
		return fmt.Errorf("nat %s connmark accept: %w", ChainOutput, err)
	}
	// Proxy's onward connection carries SO_MARK == proxy_mark; let it through.
	if err := ipt.AppendUnique("nat", ChainOutput,
		"-p", "tcp",
		"-m", "mark", "--mark", mark,
		"-j", "ACCEPT",
	); err != nil {
		return fmt.Errorf("nat %s mark accept: %w", ChainOutput, err)
	}
	// Local app → its own proxy_port (e.g. container internal call to
	// nginx) also gets REDIRECTed unless already marked.
	for _, port := range cfg.ProxyPorts {
		if err := ipt.AppendUnique("nat", ChainOutput,
			"-p", "tcp",
			"--dport", strconv.Itoa(int(port)),
			"-m", "mark", "!", "--mark", mark,
			"-j", "REDIRECT",
			"--to-ports", listen,
		); err != nil {
			return fmt.Errorf("nat %s output redirect %d: %w", ChainOutput, port, err)
		}
	}

	// === mangle: connmark propagation for reply-path fwmark routing ===
	//
	// When the proxy connects to a local upstream (e.g. nginx on 127.0.0.1
	// or the same container's eth0 IP), the outbound SYN carries packet
	// mark == proxy_mark and passes through mangle PREROUTING (loopback
	// is bidirectional). We stamp the connection with a distinct
	// CONNMARK so reply traffic (mark=0) can recover it.
	//
	// On the reply direction, nginx emits SYN-ACK with packet mark == 0.
	// mangle OUTPUT restores packet mark from the CONNMARK, which lets
	// the fwmark ip-rule pull the reply back into the proxy via
	// `local default dev lo`.
	//
	// Using a distinct CONNMARK value (not equal to proxy_mark) is an
	// istio ambient trick: it lets us distinguish "first seen outbound
	// packet" (triggers set) vs "restored reply" (triggers skip).
	connmark := fmt.Sprintf("0x%x/0x%x", cfg.ConnMark, ConnmarkMask)
	proxyMark := proxyMarkSpec(cfg.ProxyMark)

	// mangle PREROUTING: when we see a packet bearing the proxy mark,
	// stamp a CONNMARK. Loopback traffic traverses both OUTPUT and
	// PREROUTING, and the SYN from proxy->nginx (co-located) passes
	// through PREROUTING still carrying proxy_mark.
	if err := ipt.AppendUnique("mangle", ChainPrerouting,
		"-m", "mark", "--mark", proxyMark,
		"-j", "CONNMARK", "--set-xmark", connmark,
	); err != nil {
		return fmt.Errorf("mangle %s set-xmark: %w", ChainPrerouting, err)
	}

	// mangle OUTPUT: when sending a packet whose CONNMARK matches ours,
	// propagate it into the packet mark so fwmark routing and the
	// outbound-ACCEPT rule below can see it.
	if err := ipt.AppendUnique("mangle", ChainOutput,
		"-m", "connmark", "--mark", connmark,
		"-j", "CONNMARK", "--restore-mark",
		"--nfmask", fmt.Sprintf("0x%x", ConnmarkMask),
		"--ctmask", fmt.Sprintf("0x%x", ConnmarkMask),
	); err != nil {
		return fmt.Errorf("mangle %s restore-mark: %w", ChainOutput, err)
	}

	// === Hook our chains into the main chains ===
	for _, h := range []struct{ table, mainChain, ourChain string }{
		{"nat", "PREROUTING", ChainPrerouting},
		{"nat", "OUTPUT", ChainOutput},
		{"mangle", "PREROUTING", ChainPrerouting},
		{"mangle", "OUTPUT", ChainOutput},
	} {
		if err := ipt.AppendUnique(h.table, h.mainChain, "-j", h.ourChain); err != nil {
			return fmt.Errorf("hook %s %s -> %s: %w", h.table, h.mainChain, h.ourChain, err)
		}
	}

	// === Routing rule + table for marked reply packets ===
	//
	// Reply packets restored to ConnMark via mangle OUTPUT need to be
	// routed through the local `dev lo` entry so they land back in the
	// proxy socket instead of being re-sent to the original source IP.
	if err := installRouting(cfg.ConnMark); err != nil {
		return fmt.Errorf("install routing: %w", err)
	}

	return nil
}

// Uninstall removes everything Install() added. Best-effort: continues
// past missing rules.
func Uninstall(cfg Config) {
	ipt, err := iptables.New()
	if err != nil {
		return
	}
	for _, h := range []struct{ table, mainChain, ourChain string }{
		{"nat", "PREROUTING", ChainPrerouting},
		{"nat", "OUTPUT", ChainOutput},
		{"mangle", "PREROUTING", ChainPrerouting},
		{"mangle", "OUTPUT", ChainOutput},
	} {
		_ = ipt.Delete(h.table, h.mainChain, "-j", h.ourChain)
	}
	for _, c := range []struct{ table, chain string }{
		{"nat", ChainPrerouting},
		{"nat", ChainOutput},
		{"mangle", ChainPrerouting},
		{"mangle", ChainOutput},
	} {
		_ = ipt.ClearChain(c.table, c.chain)
		_ = ipt.DeleteChain(c.table, c.chain)
	}
	_ = removeRouting(cfg.ConnMark)
}

func installRouting(mark uint32) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("lookup lo: %w", err)
	}
	// ip route add local 0.0.0.0/0 dev lo table 100
	route := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Scope:     unix.RT_SCOPE_HOST,
		Type:      unix.RTN_LOCAL,
		Table:     RouteTable,
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("route replace local default lo table %d: %w", RouteTable, err)
	}
	// ip rule add fwmark <mark> lookup 100 pref 32764
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Table = RouteTable
	rule.Mark = int(mark)
	rule.Mask = int(mark)
	rule.Priority = RoutePriority
	// Best-effort: delete any pre-existing identical rule first.
	_ = netlink.RuleDel(rule)
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("rule add fwmark: %w", err)
	}
	return nil
}

func removeRouting(mark uint32) error {
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Table = RouteTable
	rule.Mark = int(mark)
	rule.Mask = int(mark)
	rule.Priority = RoutePriority
	_ = netlink.RuleDel(rule)

	lo, err := netlink.LinkByName("lo")
	if err == nil {
		_ = netlink.RouteDel(&netlink.Route{
			LinkIndex: lo.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Table:     RouteTable,
		})
	}
	return nil
}
