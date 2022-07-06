use chaos_tproxy_proxy::raw_config::{RawRule, TLSRawConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)] // To prevent typos.
pub struct RawConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_ports: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<RawRule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TLSRawConfig>,

    // Useless options now. Keep these options for upward compatible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_mark: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_mark: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_table: Option<u8>,
}
