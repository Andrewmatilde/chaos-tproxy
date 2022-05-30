use std::path::PathBuf;

use anyhow::{anyhow, Result};
use structopt::StructOpt;
use tracing_subscriber::filter::LevelFilter;

use crate::config::{get_free_port, Config};

//todo: name & about. (need discussion)
#[derive(Debug, StructOpt)]
#[structopt(name = "chaos-tproxy", about = "The option of chaos-tproxy")]
pub struct Opt {
    /// port[ port]...
    /// Match if the tcp package port is one of the given ports.
    #[structopt(short = "p", long = "ports")]
    pub ports: Vec<u16>,

    /// Controller will run ip netns exec netns_name <command> for command in commands.
    #[structopt(short, long)]
    pub commands: Option<Vec<String>>,

    /// Path of unix socket file used by controller.
    #[structopt(short, long)]
    pub service_sock_path: Option<PathBuf>,

    // The number of occurrences of the `v/verbose` flag
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,
}

impl Opt {
    pub fn get_level_filter(&self) -> LevelFilter {
        match self.verbose {
            0 => LevelFilter::ERROR,
            1 => LevelFilter::INFO,
            2 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    }

    pub fn from_args_checked() -> Result<Self> {
        Self::from_args_safe()?.checked()
    }

    fn checked(self) -> Result<Self> {
        if self.ports.len() > 15 {
            return Err(anyhow!("Up to 15 ports can be specified."));
        }
        Ok(self)
    }
}

pub fn get_config_from_opt(opt: &Opt) -> Result<Config> {
    return Ok(Config {
        proxy_ports: opt
            .ports
            .clone()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        listen_port: get_free_port(Some(opt.ports.clone()))?,
    });
}
