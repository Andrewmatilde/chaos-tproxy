package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Andrewmatilde/chaos-tproxy/internal/ebpf/config"
	"github.com/Andrewmatilde/chaos-tproxy/internal/injector"
	"github.com/Andrewmatilde/chaos-tproxy/internal/runtime"
	"github.com/Andrewmatilde/chaos-tproxy/internal/state"
)

func newRunCmd() *cobra.Command {
	var (
		configPath string
		proxyBin   string
		runtimeRT  string
		detach     bool
		logFile    string
	)
	cmd := &cobra.Command{
		Use:   "run <container>",
		Short: "Inject chaos into a container (foreground; Ctrl-C to remove)",
		Long: `Inject HTTP-layer chaos into a running container.

By default runs in the foreground and removes the injection on
SIGINT/SIGTERM. With --detach, daemonizes and returns immediately;
the injection lives until SIGTERM is sent to the recorded pid.

The container is resolved via the local Docker daemon by default;
pass -r containerd to pin a runtime.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInject(cmd.Context(), runOpts{
				name:       args[0],
				configPath: configPath,
				proxyBin:   proxyBin,
				rtHint:     runtimeRT,
				detach:     detach,
				logFile:    logFile,
			})
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "f", "",
		"Path to chaos config (yaml/json). Required.")
	_ = cmd.MarkFlagRequired("config")
	cmd.Flags().StringVarP(&runtimeRT, "runtime", "r", "",
		"Container runtime: docker | containerd (default: auto-detect)")
	cmd.Flags().StringVar(&proxyBin, "proxy-bin", "/usr/local/bin/chaos-tproxy",
		"Path to the chaos-tproxy proxy binary")
	cmd.Flags().BoolVarP(&detach, "detach", "d", false,
		"Run in the background; return immediately after starting")
	cmd.Flags().StringVar(&logFile, "log-file", "",
		"With --detach, write logs here (default: /var/log/chaos-tproxy/<container>.log)")
	return cmd
}

type runOpts struct {
	name       string
	configPath string
	proxyBin   string
	rtHint     string
	detach     bool
	logFile    string
}

func runInject(parent context.Context, o runOpts) error {
	// Resolve config path to absolute so the recorded state survives
	// the user's cwd changing.
	absConfig, err := filepath.Abs(o.configPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	if _, err := os.Stat(absConfig); err != nil {
		return fmt.Errorf("config %s: %w", absConfig, err)
	}

	// Prevent double-inject before we do anything expensive.
	if err := state.EnsureNotRunning(o.name); err != nil {
		return err
	}

	// --detach branch: re-exec self as a daemon with the same args,
	// then return. The daemonized process re-enters this function and
	// proceeds through the foreground path.
	if o.detach && !daemonized {
		logPath := o.logFile
		if logPath == "" {
			logPath = state.LogFileFor(o.name)
		}
		// Rebuild a stable, absolute arg list for the re-exec.
		args := []string{
			"run", o.name,
			"--config", absConfig,
			"--proxy-bin", o.proxyBin,
		}
		if o.rtHint != "" {
			args = append(args, "--runtime", o.rtHint)
		}
		if o.logFile != "" {
			args = append(args, "--log-file", o.logFile)
		}
		args = append(args, "--detach") // keep the flag; sentinel branch skips re-exec
		pid, err := state.SpawnDetached(args, logPath)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "✓ injection started for %s (pid=%d)\n", o.name, pid)
		fmt.Fprintf(os.Stdout, "  logs:   %s\n", logPath)
		fmt.Fprintf(os.Stdout, "  remove: kill %d\n", pid)
		return nil
	}

	ctx, cancel := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	target, err := runtime.Resolve(ctx, o.name, o.rtHint)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "resolved %s/%s (pid=%d, netns=%s)\n",
		target.Runtime, target.Name, target.PID, target.NetnsPath)

	cfg, err := config.Load(absConfig)
	if err != nil {
		return err
	}

	// Persist state file so `ls` can see us; remove on exit.
	logPath := o.logFile
	if logPath == "" && o.detach {
		logPath = state.LogFileFor(o.name)
	}
	entry := &state.Entry{
		Container:   o.name,
		Runtime:     target.Runtime,
		ContainerID: target.ID,
		NetnsPath:   target.NetnsPath,
		ConfigPath:  absConfig,
		PID:         os.Getpid(),
		StartedAt:   time.Now().UTC(),
		LogPath:     logPath,
		Detached:    o.detach,
	}
	if err := state.Write(entry); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	defer func() { _ = state.Remove(o.name) }()

	return injector.Inject(ctx, injector.Options{
		Target:   target,
		Config:   cfg,
		ProxyBin: o.proxyBin,
	})
}
