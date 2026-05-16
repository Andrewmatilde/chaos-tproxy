package main

import (
	"strings"
	"testing"

	"github.com/Andrewmatilde/chaos-tproxy/internal/chaosconfig"
)

// strPtr returns a pointer to s — cuts down on `s := "x"; &s` boilerplate.
func strPtr(s string) *string { return &s }
func i32Ptr(i int32) *int32   { return &i }
func boolPtr(b bool) *bool    { return &b }

// hasWarn returns true if any warning contains substr (case sensitive).
func hasWarn(warns []string, substr string) bool {
	for _, w := range warns {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestLintCleanConfig(t *testing.T) {
	cfg := &chaosconfig.ChaosTproxyConfig{
		ListenPort: 58080,
		Rules: &[]chaosconfig.Rule{{
			Target: chaosconfig.Target("Request"),
			Selector: chaosconfig.Selector{
				Method: strPtr("GET"),
			},
			Actions: chaosconfig.Actions{
				Delay: strPtr("100ms"),
			},
		}},
	}
	if w := lint(cfg); len(w) != 0 {
		t.Fatalf("clean config should produce no warnings, got: %v", w)
	}
}

func TestLintPortRange(t *testing.T) {
	for _, tc := range []struct {
		port int32
		want string
	}{
		{0, "out of range"},
		{-1, "out of range"},
		{99999, "out of range"},
		{80, "privileged"},
		{443, "privileged"},
		{1023, "privileged"},
	} {
		cfg := &chaosconfig.ChaosTproxyConfig{ListenPort: tc.port}
		warns := lint(cfg)
		if !hasWarn(warns, tc.want) {
			t.Errorf("port %d: expected warning containing %q, got %v",
				tc.port, tc.want, warns)
		}
	}
}

func TestLintEmptyRules(t *testing.T) {
	cfg := &chaosconfig.ChaosTproxyConfig{ListenPort: 58080}
	warns := lint(cfg)
	if !hasWarn(warns, "rules list is empty") {
		t.Errorf("expected empty-rules warning, got %v", warns)
	}
}

func TestLintMethodCase(t *testing.T) {
	cfg := &chaosconfig.ChaosTproxyConfig{
		ListenPort: 58080,
		Rules: &[]chaosconfig.Rule{{
			Target: chaosconfig.Target("Request"),
			Selector: chaosconfig.Selector{Method: strPtr("get")},
			Actions: chaosconfig.Actions{Delay: strPtr("100ms")},
		}},
	}
	warns := lint(cfg)
	if !hasWarn(warns, "should be uppercase") {
		t.Errorf("expected uppercase warning, got %v", warns)
	}
}

func TestLintInvalidMethod(t *testing.T) {
	cfg := &chaosconfig.ChaosTproxyConfig{
		ListenPort: 58080,
		Rules: &[]chaosconfig.Rule{{
			Target: chaosconfig.Target("Request"),
			Selector: chaosconfig.Selector{Method: strPtr("BANANA")},
			Actions: chaosconfig.Actions{Delay: strPtr("100ms")},
		}},
	}
	warns := lint(cfg)
	if !hasWarn(warns, "not a standard HTTP method") {
		t.Errorf("expected non-standard-method warning, got %v", warns)
	}
}

func TestLintCodeOnRequestRule(t *testing.T) {
	cfg := &chaosconfig.ChaosTproxyConfig{
		ListenPort: 58080,
		Rules: &[]chaosconfig.Rule{{
			Target: chaosconfig.Target("Request"),
			Selector: chaosconfig.Selector{
				Code: i32Ptr(404),
			},
			Actions: chaosconfig.Actions{Abort: boolPtr(true)},
		}},
	}
	warns := lint(cfg)
	if !hasWarn(warns, "selector.code on a Request rule will never match") {
		t.Errorf("expected code-on-request warning, got %v", warns)
	}
}

func TestLintEmptyActions(t *testing.T) {
	cfg := &chaosconfig.ChaosTproxyConfig{
		ListenPort: 58080,
		Rules: &[]chaosconfig.Rule{{
			Target:   chaosconfig.Target("Request"),
			Selector: chaosconfig.Selector{},
			Actions:  chaosconfig.Actions{},
		}},
	}
	warns := lint(cfg)
	if !hasWarn(warns, "no actions — rule is a no-op") {
		t.Errorf("expected no-op warning, got %v", warns)
	}
}

func TestLintReplaceCodeOnRequest(t *testing.T) {
	cfg := &chaosconfig.ChaosTproxyConfig{
		ListenPort: 58080,
		Rules: &[]chaosconfig.Rule{{
			Target:   chaosconfig.Target("Request"),
			Selector: chaosconfig.Selector{Method: strPtr("GET")},
			Actions: chaosconfig.Actions{
				Replace: &chaosconfig.ReplaceAction{Code: i32Ptr(503)},
			},
		}},
	}
	warns := lint(cfg)
	if !hasWarn(warns, "replace.code on a Request rule is ignored") {
		t.Errorf("expected replace.code warning, got %v", warns)
	}
}

func TestLintReplaceMethodPathOnResponse(t *testing.T) {
	cfg := &chaosconfig.ChaosTproxyConfig{
		ListenPort: 58080,
		Rules: &[]chaosconfig.Rule{{
			Target:   chaosconfig.Target("Response"),
			Selector: chaosconfig.Selector{},
			Actions: chaosconfig.Actions{
				Replace: &chaosconfig.ReplaceAction{
					Method: strPtr("POST"),
					Path:   strPtr("/x"),
				},
			},
		}},
	}
	warns := lint(cfg)
	if !hasWarn(warns, "replace.method on a Response rule is ignored") {
		t.Errorf("expected replace.method warning, got %v", warns)
	}
	if !hasWarn(warns, "replace.path on a Response rule is ignored") {
		t.Errorf("expected replace.path warning, got %v", warns)
	}
}
