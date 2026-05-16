//! Feed every real-world config-example through the generated
//! OpenAPI types. These files predate the OpenAPI work and include
//! loader-only fields (container, iface_wan, proxy_ports as array,
//! ignore_mark, safe_mode, …) — they should parse silently with
//! those fields ignored.

use std::fs;
use std::path::PathBuf;

use chaos_tproxy_proxy::schema::openapi as oa;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("config-examples")
}

#[test]
fn json_example_parses_via_generated_types() {
    // proxy_ports here is an ARRAY of ints (loader format), not a
    // string — our schema doesn't model proxy_ports at all, so this
    // should be dropped silently.
    let path = examples_dir().join("json_example.json");
    let raw = fs::read_to_string(&path).expect("read");
    let cfg: oa::ChaosTproxyConfig = serde_json::from_str(&raw).expect("parse");
    assert_eq!(u32::from(cfg.listen_port), 58080);
    assert_eq!(cfg.proxy_mark, Some(1));
    assert_eq!(cfg.rules.len(), 2);

    // Rule 0: GET /example, delay+replace+patch
    let r0 = &cfg.rules[0];
    assert!(matches!(r0.target, oa::Target::Request));
    assert_eq!(r0.actions.delay.as_deref(), Some("10s"));
    // replace.body.contents == TEXT
    let body = r0.actions.replace.as_ref().unwrap().body.as_ref().unwrap();
    match &body.contents {
        oa::ReplaceBodyContents::Text(t) => {
            assert_eq!(t.value, r#"{"name": "Chaos Mesh", "message": "Hello!"}"#);
        }
        oa::ReplaceBodyContents::Base64(_) => panic!("expected TEXT, got BASE64"),
    }
    // patch.queries
    let q = r0.actions.patch.as_ref().unwrap().queries.as_ref().unwrap();
    assert_eq!(q.len(), 2);
    assert_eq!(q[1][1], "other");

    // Rule 1: Response 404, abort
    let r1 = &cfg.rules[1];
    assert!(matches!(r1.target, oa::Target::Response));
    assert_eq!(r1.selector.code.map(i32::from), Some(404));
    assert_eq!(r1.actions.abort, Some(true));
}

#[test]
fn ebpf_example_yaml_parses_via_generated_types() {
    // Has container / iface_wan / iface_lo / proxy_ports (as STRING
    // "80") / safe_mode — all loader-only fields we ignore.
    let path = examples_dir().join("ebpf-example.yaml");
    let raw = fs::read_to_string(&path).expect("read");
    let yaml_val: serde_yaml::Value = serde_yaml::from_str(&raw).expect("yaml parse");
    let cfg: oa::ChaosTproxyConfig =
        serde_yaml::from_value(yaml_val).expect("decode via schema");
    assert_eq!(u32::from(cfg.listen_port), 58080);
    assert_eq!(cfg.rules.len(), 1);
    assert_eq!(cfg.rules[0].actions.delay.as_deref(), Some("3s"));
}

#[test]
fn abort_by_path_yaml_parses_via_generated_types() {
    // No listen_port in this file — listen_port is REQUIRED in our
    // schema. This SHOULD fail. Verify the failure mode is clean.
    let path = examples_dir().join("abort_by_path.yaml");
    let raw = fs::read_to_string(&path).expect("read");
    let yaml_val: serde_yaml::Value = serde_yaml::from_str(&raw).expect("yaml parse");
    let err = serde_yaml::from_value::<oa::ChaosTproxyConfig>(yaml_val).unwrap_err();
    assert!(
        err.to_string().contains("listen_port"),
        "expected listen_port error, got: {err}"
    );
}
