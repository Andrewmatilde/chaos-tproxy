package chaosconfig

import (
	"encoding/json"
	"testing"
)

// Smoke test: real chaos-tproxy YAML/JSON parses into the generated
// types without losing fields the proxy actually reads.
func TestParseMinimal(t *testing.T) {
	// Equivalent of:
	//   listen_port: 80
	//   proxy_mark: 53185
	//   rules: []
	input := `{"listen_port": 80, "proxy_mark": 53185, "rules": []}`
	var cfg ChaosTproxyConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.ListenPort != 80 {
		t.Fatalf("listen_port = %d, want 80", cfg.ListenPort)
	}
	if cfg.ProxyMark == nil || *cfg.ProxyMark != 53185 {
		t.Fatalf("proxy_mark = %v, want 53185", cfg.ProxyMark)
	}
}

func TestParseRuleWithDelayAndReplace(t *testing.T) {
	input := `{
		"listen_port": 8080,
		"rules": [{
			"target": "Request",
			"selector": {"method": "GET", "path": "/api*"},
			"actions": {
				"delay": "100ms",
				"abort": false,
				"replace": {
					"code": 503,
					"body": {"contents": {"type": "TEXT", "value": "down"}}
				}
			}
		}]
	}`
	var cfg ChaosTproxyConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Rules == nil || len(*cfg.Rules) != 1 {
		t.Fatalf("rules len = %v", cfg.Rules)
	}
	rule := (*cfg.Rules)[0]
	if rule.Target != Request {
		t.Fatalf("target = %s, want Request", rule.Target)
	}
	if rule.Actions.Delay == nil || *rule.Actions.Delay != "100ms" {
		t.Fatalf("delay = %v", rule.Actions.Delay)
	}
	if rule.Actions.Replace == nil || rule.Actions.Replace.Code == nil ||
		*rule.Actions.Replace.Code != 503 {
		t.Fatalf("replace.code = %v", rule.Actions.Replace)
	}
}

func TestParseRoleClient(t *testing.T) {
	input := `{"listen_port": 80, "role": {"Client": ["10.0.0.1", "10.0.0.2"]}}`
	var cfg ChaosTproxyConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Role == nil {
		t.Fatalf("role missing")
	}
	c, err := cfg.Role.AsRoleClient()
	if err != nil {
		t.Fatalf("AsRoleClient: %v", err)
	}
	if len(c.Client) != 2 || c.Client[0] != "10.0.0.1" {
		t.Fatalf("client ips = %v", c.Client)
	}
}

func TestParsePatchQueriesAsArrayOfPairs(t *testing.T) {
	// PatchAction.queries is intentionally [][]string (pairs) — verify
	// duplicate keys flow through.
	input := `{
		"listen_port": 80,
		"rules": [{
			"target": "Request",
			"selector": {},
			"actions": {
				"patch": {"queries": [["foo","1"],["foo","2"]]}
			}
		}]
	}`
	var cfg ChaosTproxyConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := (*cfg.Rules)[0].Actions.Patch.Queries
	if q == nil || len(*q) != 2 || (*q)[1][0] != "foo" {
		t.Fatalf("queries = %v", q)
	}
}
