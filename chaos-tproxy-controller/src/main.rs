use std::fs::remove_file;
use std::process::exit;

use chaos_tproxy_proxy::signal::Signals;
use tokio::signal::unix::SignalKind;
use tracing::error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

use crate::cmd::command_line::{get_config_from_opt, Opt};
use crate::handle::NetworkHandler;
use crate::service::{ControllerInfo, Service};

pub mod cmd;
pub mod config;
pub mod handle;
pub mod net;
pub mod service;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = match Opt::from_args_checked() {
        Err(e) => {
            println!("{}", e);
            exit(1)
        }
        Ok(o) => o,
    };
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env().add_directive(opt.get_level_filter().into()))
        .with(EnvFilter::from_default_env().add_directive("chaos_tproxy".parse().unwrap()))
        .init();

    let cfg = get_config_from_opt(&opt)?;

    let mut handler = NetworkHandler::new().await;
    if handler.run(cfg.clone()).await.is_err() {
        return handler.stop().await;
    }

    let service = Service::new(
        opt.service_sock_path,
        ControllerInfo {
            listen_port: cfg.listen_port,
            server_ip: handler.net_env.ip.clone(),
        },
    );
    let path = service.path.clone();
    tokio::spawn(async move {
        if let Err(e) = service.serve().await {
            error!("serve with error:{}", e)
        }
    });

    let mut signals = Signals::from_kinds(&[SignalKind::interrupt(), SignalKind::terminate()])?;
    signals.wait().await?;
    handler.stop().await?;
    remove_file(path)?;
    Ok(())
}
