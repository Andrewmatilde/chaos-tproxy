use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use warp::Filter;

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize, Default)]
pub struct ControllerInfo {
    pub listen_port: u16,
    pub server_ip: String,
}

#[derive(Debug)]
pub struct Service {
    pub path: PathBuf,
    pub info: ControllerInfo,
}

impl Service {
    pub fn new(path: Option<PathBuf>, info: ControllerInfo) -> Self {
        Self {
            path: path.unwrap_or_else(|| "/tmp/chaos-tproxy-controller.sock".into()),
            info,
        }
    }

    pub async fn serve(self) -> Result<()> {
        let listener = UnixListener::bind(self.path.clone())?;
        let incoming = UnixListenerStream::new(listener);

        // GET /
        let ok = warp::path::end().map(|| "OK");

        let json_info = serde_json::to_string(&self.info)?;
        // GET /info
        let info = warp::path("info").map(move || json_info.clone());

        let routes = warp::get().and(ok.or(info));
        warp::serve(routes).run_incoming(incoming).await;
        Ok(())
    }
}
