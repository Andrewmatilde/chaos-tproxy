package runtime

import (
	"context"
	"errors"
	"os"
)

// Containerd talks to the local containerd daemon. Stub for now —
// implementation will go through containerd's ttRPC client (or shell out
// to `ctr` / `nerdctl`) once we wire it up.
type Containerd struct {
	SocketPath string
}

func NewContainerd() *Containerd {
	return &Containerd{SocketPath: "/run/containerd/containerd.sock"}
}

func (c *Containerd) Name() string { return "containerd" }

func (c *Containerd) Available(ctx context.Context) bool {
	if _, err := os.Stat(c.SocketPath); err != nil {
		return false
	}
	// TODO: real liveness probe via ttRPC.
	return false
}

func (c *Containerd) InspectByName(ctx context.Context, name string) (*Container, error) {
	return nil, errors.New("containerd backend not implemented yet")
}
