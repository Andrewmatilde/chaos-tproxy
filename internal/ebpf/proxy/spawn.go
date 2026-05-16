// Package proxy spawns chaos-tproxy-proxy as a child process and feeds
// it its JSON configuration over the child's stdin.
//
// The child reads stdin until EOF, parses RawConfig, and starts the
// codec server. There is no reverse channel — the codec backend owns
// its listener and serves on it directly. If you ever need to pull
// the listener fd back out (e.g. to install into a BPF SOCKMAP),
// that has to ride a separate inheritable socket rather than the
// stdin pipe.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	vnetns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Spawner manages the chaos-tproxy proxy child process.
type Spawner struct {
	BinaryPath string

	// Netns, if non-zero, is the network namespace the child process
	// (and therefore its listener) must be created in.
	Netns vnetns.NsHandle

	cmd *exec.Cmd
}

// Start launches the proxy child and pushes the JSON payload over the
// child's stdin, closing the write half so the child's read_to_end()
// returns. Returns once the config has been delivered; the child runs
// asynchronously and must be awaited via Wait().
func (s *Spawner) Start(payload map[string]any) error {
	if s.BinaryPath == "" {
		s.BinaryPath = "/usr/local/bin/chaos-tproxy"
	}

	buf, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal proxy config: %w", err)
	}

	s.cmd = exec.Command(s.BinaryPath, "-vv", "--proxy")
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr

	stdin, err := s.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	// Go's exec.Cmd.Start fork+execs on the calling goroutine's thread;
	// if Netns is set, switch this thread's netns to the target so the
	// child inherits it, then switch back.
	if s.Netns != 0 {
		runtime.LockOSThread()
		prev, gerr := vnetns.Get()
		if gerr != nil {
			runtime.UnlockOSThread()
			return fmt.Errorf("get current netns: %w", gerr)
		}
		if err := vnetns.Set(s.Netns); err != nil {
			prev.Close()
			runtime.UnlockOSThread()
			return fmt.Errorf("enter target netns: %w", err)
		}
		startErr := s.cmd.Start()
		_ = vnetns.Set(prev)
		prev.Close()
		runtime.UnlockOSThread()
		if startErr != nil {
			return fmt.Errorf("spawn proxy %s: %w", s.BinaryPath, startErr)
		}
	} else {
		if err := s.cmd.Start(); err != nil {
			return fmt.Errorf("spawn proxy %s: %w", s.BinaryPath, err)
		}
	}

	// Push config over stdin and close the write half. The child's
	// read_to_end() returns on EOF.
	if _, err := stdin.Write(buf); err != nil {
		_ = stdin.Close()
		return fmt.Errorf("write proxy config to stdin: %w", err)
	}
	if err := stdin.Close(); err != nil {
		return fmt.Errorf("close proxy stdin: %w", err)
	}
	return nil
}

// Wait blocks until the child exits or ctx is cancelled. If cancelled,
// SIGINT is sent first, then SIGKILL after a short grace period.
func (s *Spawner) Wait(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-ctx.Done():
		_ = s.cmd.Process.Signal(unix.SIGINT)
		select {
		case err := <-done:
			return err
		case <-time.After(3 * time.Second):
			_ = s.cmd.Process.Kill()
			return <-done
		}
	case err := <-done:
		return err
	}
}

// Stop sends SIGINT to the child.
func (s *Spawner) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(unix.SIGINT)
	}
}

