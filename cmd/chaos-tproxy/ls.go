package main

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Andrewmatilde/chaos-tproxy/internal/state"
)

func newLsCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List active chaos injections",
		Long: `List currently active chaos injections by reading the state
directory (default /var/run/chaos-tproxy/). Entries whose recorded
pid is no longer alive are silently collected.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLs(cmd, output)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "table",
		"Output format: table | json")
	return cmd
}

func runLs(cmd *cobra.Command, output string) error {
	entries, err := state.List()
	if err != nil {
		return err
	}

	switch output {
	case "json":
		// Always emit an array, even when empty, so scripts can rely
		// on the shape.
		if entries == nil {
			entries = []*state.Entry{}
		}
		buf, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		cmd.Println(string(buf))
		return nil
	case "table", "":
		// fall through
	default:
		return fmt.Errorf("unknown output format %q (use table|json)", output)
	}

	if len(entries) == 0 {
		cmd.Println("no active injections")
		return nil
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTAINER\tRUNTIME\tPID\tUPTIME\tCONFIG")
	now := time.Now()
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n",
			e.Container, e.Runtime, e.PID,
			humanizeDuration(now.Sub(e.StartedAt)), e.ConfigPath)
	}
	return tw.Flush()
}

func humanizeDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	h := int(d.Hours())
	return fmt.Sprintf("%dh%dm", h, int(d.Minutes())%60)
}
