use crate::handler::http::rule::Rule;
use crate::raw_config::Role;

#[derive(Clone)]
pub struct Config {
    pub http_config: HTTPConfig,
}

#[derive(Clone, Debug)]
pub struct HTTPConfig {
    pub listen_port: u16,
    pub rules: Vec<Rule>,
    pub role: Option<Role>,
    pub proxy_mark: Option<u32>,
}
