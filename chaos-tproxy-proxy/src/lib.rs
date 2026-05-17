use std::convert::TryInto;
use std::path::PathBuf;

use tokio::signal::unix::SignalKind;
use tokio::sync::oneshot::channel;

use crate::proxy::http::server::HttpServer;
use crate::raw_config::RawConfig;
use crate::signal::Signals;
use crate::uds_client::UdsDataClient;

pub mod handler;
pub mod proxy;
pub mod raw_config;
pub mod signal;
pub mod uds_client;
pub mod uds_fd;

pub async fn proxy_main(path: PathBuf) -> anyhow::Result<()> {
    tracing::info!("Proxy get uds path {:?}", path);
    let client = UdsDataClient::new(path.clone());
    let mut buf: Vec<u8> = vec![];
    let raw_config: RawConfig = client.read_into(&mut buf).await?;
    let send_fd = raw_config.send_listener_fd;
    let config: crate::proxy::http::config::Config = raw_config.try_into()?;
    let (sender, rx) = channel();

    let mut server = HttpServer::new(config);
    let listener = server.bind_listener()?;

    if send_fd {
        tracing::info!("Sending listener fd back to loader via SCM_RIGHTS");
        uds_fd::send_fd(&path, listener.listen_fd())
            .map_err(|e| anyhow::anyhow!("send listener fd: {}", e))?;
    }

    let spawn = tokio::spawn(async move {
        tracing::info!("Proxy Starting");
        server.serve_with_listener(listener, rx).await.unwrap();
    });

    let mut signals = Signals::from_kinds(&[SignalKind::interrupt(), SignalKind::terminate()])?;
    signals.wait().await?;

    let _ = sender.send(());
    spawn.await?;
    Ok(())
}
