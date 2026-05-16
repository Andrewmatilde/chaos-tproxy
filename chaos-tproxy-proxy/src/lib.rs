use std::convert::TryInto;
use std::sync::Arc;

use tokio::io::AsyncReadExt;

use crate::raw_config::RawConfig;

pub mod handler;
pub mod proxy;
pub mod raw_config;
pub mod schema;
pub mod signal;

/// Entry point for the proxy sub-process.
///
/// Reads a JSON-serialized `RawConfig` from stdin until EOF, parses
/// it, and starts the codec server. The parent process is expected
/// to write the config + close its write end.
pub async fn proxy_main() -> anyhow::Result<()> {
    tracing::info!("proxy reading config from stdin");
    let mut buf = Vec::with_capacity(4096);
    tokio::io::stdin().read_to_end(&mut buf).await?;
    tracing::info!("proxy read {} bytes of config from stdin", buf.len());

    let raw_config: RawConfig = serde_json::from_slice(&buf)?;
    let config: crate::proxy::config::Config = raw_config.try_into()?;
    let http_config = Arc::new(config.http_config);

    tokio::task::spawn_blocking(move || crate::proxy::server::run(http_config)).await?
}
