// Package proxy spawns chaos-tproxy-proxy and pushes the JSON config
// to it over the existing UDS protocol (one-shot push, half-close).
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
	"time"

	"golang.org/x/sys/unix"
)

type Spawner struct {
	BinaryPath string
	SocketDir  string

	cmd      *exec.Cmd
	sockPath string
	ln       *net.UnixListener
}

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

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.sockPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen uds %s: %w", s.sockPath, err)
	}
	s.ln = ln

	s.cmd = exec.Command(s.BinaryPath,
		"-vv", "--proxy", "--ipc-path="+s.sockPath)
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr
	if err := s.cmd.Start(); err != nil {
		_ = ln.Close()
		return fmt.Errorf("spawn proxy: %w", err)
	}

	go s.pushConfig(payload)
	return nil
}

func (s *Spawner) pushConfig(payload map[string]interface{}) {
	buf, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		return
	}
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "accept: %v\n", err)
			return
		}
		if _, werr := conn.Write(buf); werr != nil {
			fmt.Fprintf(os.Stderr, "uds write: %v\n", werr)
		}
		_ = conn.CloseWrite()
		_ = conn.Close()
		return
	}
}

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
