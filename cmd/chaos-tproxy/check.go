package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/Andrewmatilde/chaos-tproxy/internal/chaosconfig"
)

func newCheckCmd() *cobra.Command {
	var configPath string
	var strict bool
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate a chaos config file (no privileges required)",
		Long: `Parse and validate a chaos config file against the OpenAPI schema,
then run a handful of static lints. Useful before invoking 'run'.

Does not touch any container, BPF, or networking — safe to run as
a normal user.

Exit code 0 means schema OK + no errors. With --strict, any lint
warning is also treated as an error.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cmd, configPath, strict)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "f", "",
		"Path to chaos config (yaml/json). Required.")
	_ = cmd.MarkFlagRequired("config")
	cmd.Flags().BoolVar(&strict, "strict", false,
		"Treat lint warnings as errors")
	return cmd
}

func runCheck(cmd *cobra.Command, path string, strict bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var asJSON []byte
	switch ext := filepath.Ext(path); ext {
	case ".json":
		asJSON = raw
	case ".yaml", ".yml":
		var any any
		if err := yaml.Unmarshal(raw, &any); err != nil {
			return fmt.Errorf("yaml parse %s: %w", path, err)
		}
		asJSON, err = json.Marshal(any)
		if err != nil {
			return fmt.Errorf("yaml→json %s: %w", path, err)
		}
	default:
		return fmt.Errorf("unsupported extension %q (use .yaml/.yml/.json)", ext)
	}

	var cfg chaosconfig.ChaosTproxyConfig
	if err := json.Unmarshal(asJSON, &cfg); err != nil {
		return fmt.Errorf("schema validation: %w", err)
	}

	warnings := lint(&cfg)

	nRules := 0
	if cfg.Rules != nil {
		nRules = len(*cfg.Rules)
	}
	cmd.Printf("✓ schema OK\n")
	cmd.Printf("✓ %d rule(s), listen_port=%d\n", nRules, cfg.ListenPort)
	for _, w := range warnings {
		cmd.Printf("⚠ %s\n", w)
	}
	if strict && len(warnings) > 0 {
		return fmt.Errorf("%d lint warning(s) (strict mode)", len(warnings))
	}
	return nil
}

// validMethods is the conservative set of HTTP methods we accept in
// selectors and replace actions. Mismatches are far more likely to be
// typos than legitimate WEBDAV/CalDAV methods, so warn on anything else.
var validMethods = map[string]struct{}{
	"GET": {}, "HEAD": {}, "POST": {}, "PUT": {}, "DELETE": {},
	"CONNECT": {}, "OPTIONS": {}, "TRACE": {}, "PATCH": {},
}

func lint(cfg *chaosconfig.ChaosTproxyConfig) []string {
	var warn []string

	// listen_port range check (schema only guarantees int32).
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		warn = append(warn, fmt.Sprintf("listen_port %d is out of range (1..65535)", cfg.ListenPort))
	} else if cfg.ListenPort < 1024 {
		warn = append(warn, fmt.Sprintf("listen_port %d is privileged (<1024) — proxy must run as root", cfg.ListenPort))
	}

	rules := []chaosconfig.Rule(nil)
	if cfg.Rules != nil {
		rules = *cfg.Rules
	}
	if len(rules) == 0 {
		warn = append(warn, "rules list is empty — proxy will pass traffic through unmodified")
	}

	for i, r := range rules {
		prefix := fmt.Sprintf("rule[%d]", i)

		// selector.method
		if r.Selector.Method != nil {
			m := strings.ToUpper(strings.TrimSpace(*r.Selector.Method))
			if _, ok := validMethods[m]; !ok {
				warn = append(warn, fmt.Sprintf("%s selector.method=%q is not a standard HTTP method", prefix, *r.Selector.Method))
			} else if m != *r.Selector.Method {
				warn = append(warn, fmt.Sprintf("%s selector.method=%q should be uppercase (%q)", prefix, *r.Selector.Method, m))
			}
		}

		// selector.code only meaningful on Response rules
		if r.Selector.Code != nil && r.Target == chaosconfig.Target("Request") {
			warn = append(warn, fmt.Sprintf("%s selector.code on a Request rule will never match", prefix))
		}

		// delay parseable?
		if r.Actions.Delay != nil {
			if _, err := time.ParseDuration(*r.Actions.Delay); err != nil {
				// humantime accepts forms Go's time.ParseDuration doesn't
				// (e.g. "1m30s" works, "1 hour" doesn't). We accept either
				// passing ParseDuration OR being non-empty + matching the
				// humantime token pattern; here just sanity-check non-empty.
				if strings.TrimSpace(*r.Actions.Delay) == "" {
					warn = append(warn, fmt.Sprintf("%s actions.delay is empty", prefix))
				}
			}
		}

		// actions empty?
		if r.Actions.Abort == nil && r.Actions.Delay == nil &&
			r.Actions.Patch == nil && r.Actions.Replace == nil {
			warn = append(warn, fmt.Sprintf("%s has no actions — rule is a no-op", prefix))
		}

		// replace.code on Request rule
		if r.Actions.Replace != nil && r.Actions.Replace.Code != nil &&
			r.Target == chaosconfig.Target("Request") {
			warn = append(warn, fmt.Sprintf("%s actions.replace.code on a Request rule is ignored", prefix))
		}

		// replace.method/path on Response rule
		if r.Actions.Replace != nil && r.Target == chaosconfig.Target("Response") {
			if r.Actions.Replace.Method != nil {
				warn = append(warn, fmt.Sprintf("%s actions.replace.method on a Response rule is ignored", prefix))
			}
			if r.Actions.Replace.Path != nil {
				warn = append(warn, fmt.Sprintf("%s actions.replace.path on a Response rule is ignored", prefix))
			}
		}
	}

	return warn
}
