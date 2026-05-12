// Package proxy spawns chaos-tproxy-proxy as a child process and
// exchanges configuration + listener fd over a Unix Domain Socket.
//
// The protocol is the existing one-shot push from chaos-tproxy-controller
// (serialize RawConfig as JSON, write to client, close write half),
// extended with an SCM_RIGHTS message in the reverse direction once
// the proxy has bound its listener.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	vnetns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Config is the marshaled-as-JSON shape we push to the proxy. We mirror
// chaos-tproxy-proxy/src/raw_config.rs::RawConfig so serde_json on the
// other side accepts it as-is. We construct this from the user's YAML
// loader.Proxy map, then inject the two new fields.
type pushPayload map[string]interface{}

// Spawner manages the child proxy process and the UDS handoff.
type Spawner struct {
	BinaryPath string
	SocketDir  string
	// Netns, if non-zero, is the network namespace the child process
	// (and its listener) must be created in.
	Netns vnetns.NsHandle

	cmd      *exec.Cmd
	sockPath string
	ln       *net.UnixListener
	onFD     func(int)
	expectFD bool
}

// Start launches the proxy child. The caller should then call
// Handshake() to push config and receive the listener fd, then
// Wait()/Stop() in a goroutine.
func (s *Spawner) Start(payload map[string]interface{}) error {
	if s.BinaryPath == "" {
		s.BinaryPath = "/usr/local/bin/chaos-tproxy"
	}
	if s.SocketDir == "" {
		s.SocketDir = os.TempDir()
	}
	s.sockPath = filepath.Join(s.SocketDir,
		fmt.Sprintf("chaos-tproxy-%d.sock", os.Getpid()))
	_ = os.Remove(s.sockPath)

	ln, err := net.ListenUnix("unix",
		&net.UnixAddr{Name: s.sockPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen uds %s: %w", s.sockPath, err)
	}
	s.ln = ln

	// Inject required fields into the payload before we forget.
	// The pingora backend does its own bind; only the hyper backend
	// hands the listener fd back via SCM_RIGHTS.
	backend, _ := payload["backend"].(string)
	s.expectFD = backend != "pingora"
	payload["send_listener_fd"] = s.expectFD
	// proxy_ports is required to be present (may be "" if all-ports);
	// downstream serde requires Option<String>, leave whatever user
	// set or empty.

	s.cmd = exec.Command(s.BinaryPath,
		"-vv", "--proxy", "--ipc-path="+s.sockPath)
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr

	// If Netns is set, lock the current OS thread, switch its netns to
	// target, fork+exec (child inherits the netns), then switch back.
	// Go's exec.Cmd.Start performs fork/exec on the calling goroutine's
	// thread, so this works as long as we don't yield.
	if s.Netns != 0 {
		runtime.LockOSThread()
		prev, gerr := vnetns.Get()
		if gerr != nil {
			runtime.UnlockOSThread()
			_ = ln.Close()
			return fmt.Errorf("get current netns: %w", gerr)
		}
		if err := vnetns.Set(s.Netns); err != nil {
			prev.Close()
			runtime.UnlockOSThread()
			_ = ln.Close()
			return fmt.Errorf("enter chaosns: %w", err)
		}
		startErr := s.cmd.Start()
		_ = vnetns.Set(prev)
		prev.Close()
		runtime.UnlockOSThread()
		if startErr != nil {
			_ = ln.Close()
			return fmt.Errorf("spawn proxy %s: %w", s.BinaryPath, startErr)
		}
	} else {
		if err := s.cmd.Start(); err != nil {
			_ = ln.Close()
			return fmt.Errorf("spawn proxy %s: %w", s.BinaryPath, err)
		}
	}

	// Push config in a goroutine — the child connects, we write,
	// then half-close the write side so the child's read_to_end()
	// returns.
	go s.pushConfig(payload)
	return nil
}

func (s *Spawner) pushConfig(payload pushPayload) {
	buf, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal proxy config: %v\n", err)
		return
	}
	// Connection 1: write JSON config, close write half, close.
	// Connection 2: receive listener fd via SCM_RIGHTS.
	stage := 0
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "uds accept: %v\n", err)
			return
		}
		switch stage {
		case 0:
			if _, werr := conn.Write(buf); werr != nil {
				fmt.Fprintf(os.Stderr, "uds write config: %v\n", werr)
			}
			_ = conn.CloseWrite()
			_ = conn.Close()
			if !s.expectFD {
				// pingora backend manages its own listener; nothing
				// further to exchange over UDS.
				return
			}
			stage = 1
		case 1:
			fd, err := recvFD(conn, 5*time.Second)
			_ = conn.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "uds recv fd: %v\n", err)
				return
			}
			if s.onFD != nil {
				s.onFD(fd)
			} else {
				_ = unix.Close(fd)
			}
			return
		}
	}
}

// onFD is invoked once when the child sends its listener fd back.
// Returns nothing — the loader main will use this to populate the
// SOCKMAP.
func (s *Spawner) OnListenerFD(cb func(fd int)) { s.onFD = cb }

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

// Stop sends SIGINT, then SIGKILL after grace.
func (s *Spawner) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(unix.SIGINT)
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	if s.sockPath != "" {
		_ = os.Remove(s.sockPath)
	}
}

// recvFD reads one SCM_RIGHTS message from c and returns the fd.
func recvFD(c *net.UnixConn, timeout time.Duration) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return -1, err
	}
	oob := make([]byte, unix.CmsgSpace(4))
	buf := make([]byte, 1)
	_, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return -1, fmt.Errorf("readmsg: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse scm: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_RIGHTS {
			continue
		}
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			return -1, fmt.Errorf("parse rights: %w", err)
		}
		if len(fds) == 0 {
			continue
		}
		// First fd is the listener; close any extras defensively.
		for _, extra := range fds[1:] {
			_ = unix.Close(extra)
		}
		return fds[0], nil
	}
	return -1, errors.New("no SCM_RIGHTS message received")
}

