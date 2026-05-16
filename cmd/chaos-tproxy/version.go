package main

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Andrewmatilde/chaos-tproxy/internal/runtime"
)

// Set by -ldflags at build time, e.g.:
//   go build -ldflags "-X main.version=0.6.0 -X main.commit=abc1234"
var (
	version = "dev"
	commit  = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version + build info + runtime support",
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			avail := runtime.Available(ctx)
			if len(avail) == 0 {
				avail = []string{"(none detected on this host)"}
			}
			cmd.Printf("chaos-tproxy %s (commit %s)\n", version, commit)
			cmd.Printf("runtime support: %s\n", strings.Join(avail, ", "))
		},
	}
}
