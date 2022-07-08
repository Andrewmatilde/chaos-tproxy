use std::collections::HashMap;
use chaos_tproxy_controller_lib::raw_config::RawConfig;
use chaos_tproxy_proxy::raw_config::{RawActions, RawPatchAction, RawPatchBody, RawPatchBodyContents, RawReplaceAction, RawReplaceBody, RawReplaceBodyContents, RawRule, RawSelector, RawTarget};

fn main() {
    let config = RawConfig{
        proxy_ports: Some(vec![80]),
        rules: Some(vec![RawRule{
            target: RawTarget::Request,
            selector: RawSelector {
                port: None,
                path: None,
                method: Some("GET".to_string()),
                code: None,
                request_headers: None,
                response_headers: None
            },
            actions: RawActions {
                abort: None,
                delay: None,
                replace: Some(RawReplaceAction {
                    path: None,
                    method: Some("POST".to_string()),
                    body: None,
                    code: None,
                    queries: None,
                    headers: None
                }),
                patch: None
        }
        }, RawRule {
            target: RawTarget::Response,
            selector: RawSelector {
                port: None,
                path: Some("/example*".to_string()),
                method: Some("GET".to_string()),
                code: None,
                request_headers: None,
                response_headers: None
            },
            actions: RawActions {
                abort: None,
                delay: None,
                replace: Some(RawReplaceAction {
                    path: None,
                    method: None,
                    body: Some(RawReplaceBody{
                        contents: RawReplaceBodyContents::TEXT(vec!["[",vec!["\"Hallo chaos-mesh\"";1000].join(",").as_str(),"]"].join(""))
                    }),
                    code: None,
                    queries: None,
                    headers: Some({
                        let mut m = HashMap::new();
                        m.insert("Host".to_string(),"8.8.8.8".to_string());
                        m
                    })
                }),
                patch: Some(RawPatchAction {
                    body: Some(RawPatchBody {
                        contents: RawPatchBodyContents::JSON("{\"foo\":\"foo\"}".to_string())
                    }),
                    queries: None,
                    headers: Some({
                        vec![("a".to_string(), "a".to_string())]
                    })
                })
            }
        }]),
        tls: None,

        safe_mode: None,
        interface: None,
        listen_port: None,
        proxy_mark: None,
        ignore_mark: None,
        route_table: None
    };

    let s = serde_json::to_string(&config).unwrap();
    println!("{}",s)
}
