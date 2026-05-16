package state

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// DefaultLogDir is where detached daemons write their stdout/stderr by
// default. tmpfs on systemd hosts, so wiped at reboot.
const DefaultLogDir = "/var/log/chaos-tproxy"

// LogDir returns the resolved log directory. Override with
// CHAOS_TPROXY_LOG_DIR.
func LogDir() string {
	if d := os.Getenv("CHAOS_TPROXY_LOG_DIR"); d != "" {
		return d
	}
	return DefaultLogDir
}

// LogFileFor returns the absolute path of the log file for a container.
func LogFileFor(container string) string {
	return filepath.Join(LogDir(), sanitize(container)+".log")
}

// SpawnDetached re-execs the current binary with the same arguments
// plus a sentinel flag (DaemonSentinel) and detaches it: new session,
// stdio routed to logPath, parent returns immediately.
//
// The detached child must check IsDaemonized() to know it's the
// runaway copy and skip its own re-exec.
//
// Returns the child's PID.
func SpawnDetached(args []string, logPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return 0, fmt.Errorf("mkdir log dir: %w", err)
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return 0, fmt.Errorf("open log %s: %w", logPath, err)
	}
	defer logf.Close()

	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("locate self: %w", err)
	}

	full := append([]string{DaemonSentinel}, args...)
	cmd := exec.Command(exe, full...)
	cmd.Stdin = nil
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // new session — detaches from the controlling terminal
	}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("spawn detached: %w", err)
	}
	pid := cmd.Process.Pid
	// Release so the child outlives us. Release() clears Process.Pid,
	// so capture it first.
	if err := cmd.Process.Release(); err != nil {
		return pid, fmt.Errorf("release child: %w", err)
	}
	return pid, nil
}

// DaemonSentinel is the hidden first argument the detached re-exec
// receives. The main entry point strips it and remembers the daemonized
// flag.
const DaemonSentinel = "__chaos-tproxy-daemonized__"

// IsDaemonized returns (true, restArgs) if os.Args[1] == DaemonSentinel.
// Call this very early in main(); if true, treat the remaining args as
// the real CLI invocation and don't re-detach.
func IsDaemonized() (bool, []string) {
	if len(os.Args) >= 2 && os.Args[1] == DaemonSentinel {
		// Rebuild os.Args without the sentinel so cobra parses cleanly.
		rest := append([]string{os.Args[0]}, os.Args[2:]...)
		return true, rest
	}
	return false, nil
}
