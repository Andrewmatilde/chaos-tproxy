//! Cross-language parity tests against the same JSON snippets that
//! `bench/go-chaosconfig/parse_test.go` parses on the Go side.
//!
//! Two layers are exercised:
//!   * Hand-written `raw_config::RawConfig` — the legacy struct the
//!     action engine and rule conversion code still consume.
//!   * Generated `schema::openapi::ChaosTproxyConfig` — from the
//!     OpenAPI contract via the `tools/codegen` crate.
//!
//! Both layers must accept the same wire format. Once the legacy
//! struct is retired we'll drop the hand-written half.

use bytes::Bytes;
use chaos_tproxy_proxy::raw_config::{RawConfig, RawTarget, Role as LegacyRole};
use chaos_tproxy_proxy::schema::openapi as oa;

const MINIMAL: &str = r#"{"listen_port": 80, "proxy_mark": 53185, "rules": []}"#;

const RULE_WITH_DELAY_AND_REPLACE: &str = r#"{
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
}"#;

const ROLE_CLIENT: &str = r#"{"listen_port": 80, "role": {"Client": ["10.0.0.1", "10.0.0.2"]}}"#;

const PATCH_QUERIES: &str = r#"{
    "listen_port": 80,
    "rules": [{
        "target": "Request",
        "selector": {},
        "actions": {
            "patch": {"queries": [["foo","1"],["foo","2"]]}
        }
    }]
}"#;

// ---------------------------------------------------------------------
// Legacy types (raw_config)
// ---------------------------------------------------------------------

#[test]
fn legacy_parses_minimal() {
    let cfg: RawConfig = serde_json::from_str(MINIMAL).expect("parse");
    assert_eq!(cfg.listen_port, 80);
    assert_eq!(cfg.proxy_mark, Some(53185));
    assert!(cfg.rules.is_empty());
}

#[test]
fn legacy_parses_rule_with_delay_and_replace() {
    let cfg: RawConfig = serde_json::from_str(RULE_WITH_DELAY_AND_REPLACE).expect("parse");
    assert_eq!(cfg.rules.len(), 1);
    let r = &cfg.rules[0];
    assert!(matches!(r.target, RawTarget::Request));
    assert_eq!(r.actions.delay, Some(std::time::Duration::from_millis(100)));
    let replace = r.actions.replace.as_ref().expect("replace set");
    assert_eq!(replace.code, Some(503));
}

#[test]
fn legacy_parses_role_client() {
    let cfg: RawConfig = serde_json::from_str(ROLE_CLIENT).expect("parse");
    match cfg.role.expect("role") {
        LegacyRole::Client(ips) => {
            assert_eq!(ips.len(), 2);
            assert_eq!(ips[0].to_string(), "10.0.0.1");
        }
        LegacyRole::Server(_) => panic!("expected Client"),
    }
}

#[test]
fn legacy_parses_patch_queries_as_pairs() {
    let cfg: RawConfig = serde_json::from_str(PATCH_QUERIES).expect("parse");
    let patch = cfg.rules[0]
        .actions
        .patch
        .as_ref()
        .expect("patch set");
    let queries = patch.queries.as_ref().expect("queries set");
    assert_eq!(queries.len(), 2);
    assert_eq!(queries[1], ("foo".to_string(), "2".to_string()));
}

#[test]
fn legacy_ignores_unknown_fields() {
    // Existing chaos-tproxy yamls in the wild often include these
    // loader keys. Make sure they still parse silently.
    let input = r#"{
        "listen_port": 80,
        "iface_wan": "eth0",
        "iface_lo": "lo",
        "container": "target",
        "rules": []
    }"#;
    let _: RawConfig = serde_json::from_str(input).expect("parse");
}

// Silence the dead `_b: Bytes` import noise from earlier iterations.
#[allow(dead_code)]
fn _bytes_anchor(_b: Bytes) {}

// ---------------------------------------------------------------------
// Generated OpenAPI types
// ---------------------------------------------------------------------

#[test]
fn generated_parses_minimal() {
    let cfg: oa::ChaosTproxyConfig = serde_json::from_str(MINIMAL).expect("parse");
    assert_eq!(u32::from(cfg.listen_port), 80);
    assert_eq!(cfg.proxy_mark, Some(53185));
    assert!(cfg.rules.is_empty());
}

#[test]
fn generated_parses_rule_with_delay_and_replace() {
    let cfg: oa::ChaosTproxyConfig =
        serde_json::from_str(RULE_WITH_DELAY_AND_REPLACE).expect("parse");
    assert_eq!(cfg.rules.len(), 1);
    let r = &cfg.rules[0];
    assert!(matches!(r.target, oa::Target::Request));
    assert_eq!(r.actions.delay.as_deref(), Some("100ms"));
    let replace = r.actions.replace.as_ref().expect("replace set");
    assert_eq!(replace.code.map(i32::from), Some(503));
}

#[test]
fn generated_parses_role_client() {
    let cfg: oa::ChaosTproxyConfig = serde_json::from_str(ROLE_CLIENT).expect("parse");
    match cfg.role.expect("role") {
        oa::Role::Client(c) => {
            assert_eq!(c.client.len(), 2);
            assert_eq!(c.client[0].to_string(), "10.0.0.1");
        }
        oa::Role::Server(_) => panic!("expected Client"),
    }
}

#[test]
fn generated_parses_patch_queries_as_pairs() {
    let cfg: oa::ChaosTproxyConfig = serde_json::from_str(PATCH_QUERIES).expect("parse");
    let queries = cfg.rules[0]
        .actions
        .patch
        .as_ref()
        .expect("patch")
        .queries
        .as_ref()
        .expect("queries");
    assert_eq!(queries.len(), 2);
    assert_eq!(queries[1][0], "foo");
    assert_eq!(queries[1][1], "2");
}
