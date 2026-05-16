// Package runtime is the abstraction over container runtimes (docker,
// containerd). The injector only cares about resolving a friendly name
// to a PID + netns path; everything else stays runtime-agnostic.
package runtime

import (
	"context"
	"errors"
)

// Container is the minimal view of a running container that the injector
// needs to attach BPF + spawn the proxy inside the target's netns.
type Container struct {
	Runtime   string // "docker" | "containerd"
	ID        string
	Name      string
	PID       int
	NetnsPath string // /proc/<pid>/ns/net
}

// Runtime is implemented by each container runtime backend.
type Runtime interface {
	Name() string
	// Available is a cheap "is this runtime usable on this host?" probe
	// (e.g. socket exists + responds). Used by Resolve to skip backends.
	Available(ctx context.Context) bool
	// InspectByName returns the container with the given friendly name,
	// or ErrNotFound. Callers should not assume name uniqueness across
	// runtimes — that's Resolve's job.
	InspectByName(ctx context.Context, name string) (*Container, error)
}

var (
	// ErrNotFound means no container with that name in this runtime.
	ErrNotFound = errors.New("container not found")
	// ErrAmbiguous means the same name resolves in multiple runtimes;
	// caller should pin one with -r.
	ErrAmbiguous = errors.New("container name matches in multiple runtimes")
	// ErrNoRuntime means no supported runtime is available on this host.
	ErrNoRuntime = errors.New("no container runtime available")
)
