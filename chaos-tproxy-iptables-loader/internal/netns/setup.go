// Package netns sets up the dae-style sibling netns inside the target's
// netns: dae0/dae0peer veth pair, chaosns netns, fwmark routing rules.
//
// Lifted (simplified) from daeuniverse/dae/control/netns_utils.go. We're
// already inside the target container's netns when this runs, so "host"
// for our purposes IS the target netns.
package netns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	ChaosNsName       = "chaosns"
	HostVethName      = "dae0"
	NsVethName        = "dae0peer"
	TproxyMark        = 0x8000000
	TproxyRouteTable  = 2023
	// Link-local addresses used so the chaosns has a default gateway
	// to push reply packets toward dae0.
	PeerLinkLocalIPv4 = "169.254.0.11"
	GwLinkLocalIPv4   = "169.254.0.1"
)

type Handles struct {
	HostNs    netns.NsHandle // the netns this process started in (= target's netns)
	ChaosNs   netns.NsHandle
	Dae0      netlink.Link
	Dae0Peer  netlink.Link
	Dae0Mac   net.HardwareAddr
	PeerMac   net.HardwareAddr
	Eth0      netlink.Link
}

// Setup creates everything. Returns Handles that must be passed to Teardown.
// The caller must NOT be using goroutines: we LockOSThread and switch netns.
func Setup(eth0Name string) (*Handles, error) {
	runtime.LockOSThread()
	hostNs, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("get current netns: %w", err)
	}

	h := &Handles{HostNs: hostNs}

	// Resolve target eth0.
	eth0, err := netlink.LinkByName(eth0Name)
	if err != nil {
		return nil, fmt.Errorf("look up %s: %w", eth0Name, err)
	}
	h.Eth0 = eth0

	// Best-effort cleanup of any stale leftover.
	_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: HostVethName}})
	_ = deleteNamedNetns(ChaosNsName)

	// Create veth pair dae0 <-> dae0peer in host (target) ns.
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: HostVethName, TxQLen: 1000},
		PeerName:  NsVethName,
	}); err != nil {
		return nil, fmt.Errorf("create veth: %w", err)
	}

	dae0, err := netlink.LinkByName(HostVethName)
	if err != nil {
		return nil, fmt.Errorf("look up dae0: %w", err)
	}
	dae0peer, err := netlink.LinkByName(NsVethName)
	if err != nil {
		return nil, fmt.Errorf("look up dae0peer: %w", err)
	}
	h.Dae0 = dae0
	h.Dae0Peer = dae0peer
	h.Dae0Mac = dae0.Attrs().HardwareAddr
	h.PeerMac = dae0peer.Attrs().HardwareAddr

	if err := netlink.LinkSetUp(dae0); err != nil {
		return nil, fmt.Errorf("set dae0 up: %w", err)
	}

	// Give dae0 in target netns a link-local IP so we can route
	// marked traffic via 169.254.0.1 (= dae0peer's IP in chaosns).
	// 169.254.0.10 is host side; 169.254.0.11 is in chaosns.
	dae0IP := net.ParseIP("169.254.0.10")
	if err := netlink.AddrAdd(dae0, &netlink.Addr{
		IPNet: &net.IPNet{IP: dae0IP, Mask: net.CIDRMask(32, 32)},
	}); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("addr add dae0: %w", err)
	}
	// Route to 169.254.0.1 via dae0 (link scope).
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: dae0.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("169.254.0.1"), Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
	}); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("route 169.254.0.1 via dae0: %w", err)
	}
	// Static neigh: 169.254.0.1 -> dae0peer's mac.
	if err := netlink.NeighSet(&netlink.Neigh{
		IP:           net.ParseIP("169.254.0.1"),
		HardwareAddr: dae0peer.Attrs().HardwareAddr,
		LinkIndex:    dae0.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return nil, fmt.Errorf("neigh set in target ns: %w", err)
	}

	// Create chaosns and move dae0peer into it.
	chaosNs, err := newNamedNetns(ChaosNsName)
	if err != nil {
		return nil, fmt.Errorf("create chaosns: %w", err)
	}
	h.ChaosNs = chaosNs

	if err := netlink.LinkSetNsFd(dae0peer, int(chaosNs)); err != nil {
		return nil, fmt.Errorf("move dae0peer to chaosns: %w", err)
	}

	// Switch into chaosns to configure routes/addrs/rules on dae0peer + lo.
	if err := netns.Set(chaosNs); err != nil {
		return nil, fmt.Errorf("switch to chaosns: %w", err)
	}
	chaosErr := func() error {
		// Re-resolve dae0peer in this namespace.
		peer, err := netlink.LinkByName(NsVethName)
		if err != nil {
			return fmt.Errorf("dae0peer in chaosns: %w", err)
		}
		if err := netlink.LinkSetUp(peer); err != nil {
			return fmt.Errorf("set dae0peer up: %w", err)
		}
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("lo in chaosns: %w", err)
		}
		if err := netlink.LinkSetUp(lo); err != nil {
			return fmt.Errorf("set lo up: %w", err)
		}

		// Address + link-local gateway plumbing.
		// ip a a 169.254.0.11/32 dev dae0peer
		peerIP := net.ParseIP(PeerLinkLocalIPv4)
		if err := netlink.AddrAdd(peer, &netlink.Addr{
			IPNet: &net.IPNet{IP: peerIP, Mask: net.CIDRMask(32, 32)},
		}); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("addr add peer: %w", err)
		}
		// ip r a 169.254.0.1 dev dae0peer
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: peer.Attrs().Index,
			Dst:       &net.IPNet{IP: net.ParseIP(GwLinkLocalIPv4), Mask: net.CIDRMask(32, 32)},
			Scope:     netlink.SCOPE_LINK,
		}); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("route gw: %w", err)
		}
		// ip r a default via 169.254.0.1 dev dae0peer
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: peer.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Gw:        net.ParseIP(GwLinkLocalIPv4),
		}); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("route default: %w", err)
		}
		// Static neigh: 169.254.0.1 -> dae0 MAC, so packets from chaosns
		// reach dae0 without ARP.
		if err := netlink.NeighSet(&netlink.Neigh{
			IP:           net.ParseIP(GwLinkLocalIPv4),
			HardwareAddr: h.Dae0Mac,
			LinkIndex:    peer.Attrs().Index,
			State:        netlink.NUD_PERMANENT,
		}); err != nil {
			return fmt.Errorf("neigh set: %w", err)
		}

		// ip route add local default dev lo table 2023
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: lo.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Scope:     unix.RT_SCOPE_HOST,
			Type:      unix.RTN_LOCAL,
			Table:     TproxyRouteTable,
		}); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("route local default: %w", err)
		}

		// ip rule add fwmark 0x8000000/0x8000000 table 2023
		rule := netlink.NewRule()
		rule.Family = unix.AF_INET
		rule.Table = TproxyRouteTable
		rule.Mark = TproxyMark
		rule.Mask = TproxyMark
		rule.Priority = 100
		if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("rule add: %w", err)
		}

		// Permissive sysctls in chaosns. Failures are non-fatal.
		_ = writeSysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
		_ = writeSysctl("/proc/sys/net/ipv4/conf/dae0peer/rp_filter", "0")
		_ = writeSysctl("/proc/sys/net/ipv4/conf/all/accept_local", "1")
		_ = writeSysctl("/proc/sys/net/ipv4/conf/dae0peer/accept_local", "1")
		_ = writeSysctl("/proc/sys/net/ipv4/ip_forward", "1")
		return nil
	}()

	// Switch back regardless.
	if err := netns.Set(hostNs); err != nil {
		return nil, fmt.Errorf("switch back to host: %w", err)
	}
	if chaosErr != nil {
		return nil, chaosErr
	}

	return h, nil
}

// AddTargetARP installs a static ARP entry (client_ip -> client_mac)
// in the target netns. Without this, when nginx tries to reply to the
// proxy's forged connection (where src=client_ip), the kernel runs
// ARP resolution and gets nowhere because BPF intercepted the original
// inbound flow before the kernel could learn the client's MAC.
func (h *Handles) AddTargetARP(clientIP net.IP, clientMAC net.HardwareAddr) error {
	return netlink.NeighSet(&netlink.Neigh{
		IP:           clientIP,
		HardwareAddr: clientMAC,
		LinkIndex:    h.Eth0.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
	})
}

// Teardown undoes everything. Idempotent.
func (h *Handles) Teardown() {
	// Re-resolve dae0 by name in case Link object went stale.
	if l, err := netlink.LinkByName(HostVethName); err == nil {
		_ = netlink.LinkDel(l)
	}
	_ = deleteNamedNetns(ChaosNsName)
	if h.ChaosNs != 0 {
		_ = h.ChaosNs.Close()
	}
	if h.HostNs != 0 {
		_ = h.HostNs.Close()
	}
	runtime.UnlockOSThread()
}

// newNamedNetns creates /var/run/netns/<name> + a fresh netns and returns
// the fd handle. Caller is responsible for closing it via Teardown.
func newNamedNetns(name string) (netns.NsHandle, error) {
	// Ensure /var/run/netns exists.
	if err := os.MkdirAll("/var/run/netns", 0755); err != nil {
		return 0, err
	}
	path := "/var/run/netns/" + name
	// touch the file
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	f.Close()

	// Save current ns, create new, mount-bind it to path, then go back.
	runtime.LockOSThread()
	prev, err := netns.Get()
	if err != nil {
		return 0, err
	}
	defer prev.Close()

	newNs, err := netns.New() // also Set()s into new
	if err != nil {
		return 0, fmt.Errorf("create new netns: %w", err)
	}
	// Bind-mount /proc/self/ns/net onto the file so `ip netns` and others see it.
	if err := unix.Mount("/proc/self/ns/net", path, "none", unix.MS_BIND, ""); err != nil {
		newNs.Close()
		_ = os.Remove(path)
		return 0, fmt.Errorf("bind mount netns to %s: %w", path, err)
	}
	if err := netns.Set(prev); err != nil {
		newNs.Close()
		return 0, fmt.Errorf("restore prev ns: %w", err)
	}
	return newNs, nil
}

func deleteNamedNetns(name string) error {
	path := "/var/run/netns/" + name
	_ = unix.Unmount(path, unix.MNT_DETACH)
	return os.Remove(path)
}

func writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value), 0644)
}
