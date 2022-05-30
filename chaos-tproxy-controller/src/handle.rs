use rtnetlink::{new_connection, Handle};
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::config::Config;
use crate::net::bridge::NetEnv;
use crate::net::set_net::set_net;

#[derive(Debug)]
pub struct NetworkHandler {
    pub net_env: NetEnv,
    pub rtnl_handle: Handle,
    pub sender: Option<Sender<()>>,
    pub rx: Option<Receiver<()>>,
}

impl NetworkHandler {
    pub async fn new() -> Self {
        let (sender, rx) = channel();

        let (conn, handle, _) = new_connection().unwrap();
        tokio::spawn(conn);
        Self {
            net_env: NetEnv::new(&handle).await,
            rtnl_handle: handle,
            sender: Some(sender),
            rx: Some(rx),
        }
    }

    pub async fn run(&mut self, config: Config) -> anyhow::Result<()> {
        set_net(
            &mut self.rtnl_handle,
            &self.net_env,
            config.proxy_ports,
            config.listen_port,
        )
        .await?;
        Ok(())
    }

    pub async fn stop(&mut self) -> anyhow::Result<()> {
        let _ = self.net_env.clear_bridge(&mut self.rtnl_handle).await;
        Ok(())
    }
}
