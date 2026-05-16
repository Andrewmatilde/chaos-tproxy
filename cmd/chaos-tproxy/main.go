// Command chaos-tproxy injects HTTP-layer chaos into a running container
// via an eBPF dataplane + a transparent proxy spawned in the target's
// netns.
//
// Subcommands:
//   run     — inject chaos into a container (foreground; Ctrl-C to remove)
//   ls      — list active injections
//   check   — validate a config file (no privileges required)
//   version — print build info
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Andrewmatilde/chaos-tproxy/internal/state"
)

// daemonized is set true when the binary was re-exec'd by
// state.SpawnDetached. The `run` command uses it to skip the
// re-detach branch and proceed straight into the injection loop.
var daemonized bool

func main() {
	// Detect + strip the daemon sentinel before cobra sees os.Args.
	if isd, rest := state.IsDaemonized(); isd {
		daemonized = true
		os.Args = rest
	}

	root := &cobra.Command{
		Use:           "chaos-tproxy",
		Short:         "Inject HTTP chaos into a running container",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newRunCmd(), newLsCmd(), newCheckCmd(), newVersionCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
