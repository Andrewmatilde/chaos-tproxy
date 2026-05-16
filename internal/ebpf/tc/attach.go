// Package tc attaches eBPF programs to TC clsact qdiscs on a single
// interface using the classic netlink path: ensure clsact qdisc, then
// add a bpf filter with direct-action.
package tc

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// Direction is which TC hook to attach to.
type Direction int

const (
	Ingress Direction = iota
	Egress
)

// Attach attaches prog on the given interface in the given direction
// and returns a Cleanup func that removes the filter (and the qdisc
// if we created it).
func Attach(ifname string, dir Direction, prog *ebpf.Program) (func() error, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %s: %w", ifname, err)
	}

	link, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return nil, fmt.Errorf("netlink LinkByIndex %d: %w", iface.Index, err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	addedQdisc := false
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !isFileExists(err) {
			return nil, fmt.Errorf("add clsact on %s: %w", iface.Name, err)
		}
	} else {
		addedQdisc = true
	}

	parent := uint32(netlink.HANDLE_MIN_INGRESS)
	if dir == Egress {
		parent = uint32(netlink.HANDLE_MIN_EGRESS)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    1,
			Protocol:  0x0003, // ETH_P_ALL
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         prog.String(),
		DirectAction: true,
	}
	// Replace any stale filter from a previous loader run that died
	// without cleanup (the clsact qdisc + filter persist in the
	// target container's netns).
	if existing, err := netlink.FilterList(link, parent); err == nil {
		for _, f := range existing {
			_ = netlink.FilterDel(f)
		}
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("add bpf filter on %s: %w", iface.Name, err)
	}

	cleanup := func() error {
		_ = netlink.FilterDel(filter)
		if addedQdisc {
			_ = netlink.QdiscDel(qdisc)
		}
		return nil
	}
	return cleanup, nil
}

func isFileExists(err error) bool {
	if err == nil {
		return false
	}
	// netlink wraps the syscall errno; the message we get is "file exists".
	if errors.Is(err, errFileExists) {
		return true
	}
	return err.Error() == "file exists"
}

var errFileExists = errors.New("file exists")
