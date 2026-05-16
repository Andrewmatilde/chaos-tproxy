use std::process::Stdio;

use anyhow::Error;
use chaos_tproxy_proxy::raw_config::RawConfig as ProxyRawConfig;
use rtnetlink::{new_connection, Handle};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::select;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

use crate::proxy::net::bridge::NetEnv;
use crate::proxy::net::set_net::set_net;

#[derive(Debug, Clone)]
pub struct ProxyOpt {
    pub verbose: u8,
}

impl ProxyOpt {
    pub fn new(verbose: u8) -> Self {
        Self { verbose }
    }
}

#[derive(Debug)]
pub struct Proxy {
    pub opt: ProxyOpt,
    pub net_env: NetEnv,
    pub rtnl_handle: Handle,
    pub sender: Option<Sender<()>>,
    pub rx: Option<Receiver<()>>,
    pub task: Option<JoinHandle<Result<(), Error>>>,
}

impl Proxy {
    pub async fn new(verbose: u8) -> Self {
        let opt = ProxyOpt::new(verbose);
        let (sender, rx) = channel();

        let (conn, handle, _) = new_connection().unwrap();
        tokio::spawn(conn);
        Self {
            opt,
            net_env: NetEnv::new(&handle).await,
            rtnl_handle: handle,
            sender: Some(sender),
            rx: Some(rx),
            task: None,
        }
    }

    pub async fn exec(&mut self, config: ProxyRawConfig) -> anyhow::Result<()> {
        tracing::info!("transferring proxy raw config {:?}", &config);

        let exe_path = match std::env::current_exe() {
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to get current exe path,error : {:?}",
                    e
                ));
            }
            Ok(path) => path,
        };

        tracing::info!("Network device name {}", self.net_env.device.clone());
        set_net(
            &mut self.rtnl_handle,
            &self.net_env,
            config.proxy_ports.clone(),
            config.listen_port,
            config.safe_mode,
        )
        .await?;

        let payload = serde_json::to_vec(&config)?;

        let mut proxy = Command::new("ip");
        proxy
            .arg("netns")
            .arg("exec")
            .arg(&self.net_env.netns)
            .arg(exe_path)
            .arg(format!(
                "-{}",
                String::from_utf8(vec![b'v'; self.opt.verbose as usize]).unwrap()
            ))
            .arg("--proxy");

        let rx = self.rx.take().unwrap();
        self.task = Some(tokio::spawn(async move {
            tracing::info!("Proxy executor Starting proxy.");
            let mut process = match proxy.stdin(Stdio::piped()).spawn() {
                Ok(process) => {
                    tracing::info!("Proxy executor Proxy is running.");
                    process
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("failed to exec sub proxy : {:?}", e));
                }
            };

            // Push the config and close the write end so the child's
            // read_to_end() on stdin returns.
            if let Some(mut child_stdin) = process.stdin.take() {
                if let Err(e) = child_stdin.write_all(&payload).await {
                    return Err(anyhow::anyhow!(
                        "failed to write config to sub proxy stdin: {:?}",
                        e
                    ));
                }
                drop(child_stdin);
            }

            select! {
                _ = process.wait() => {}
                _ = rx => {
                    tracing::info!("Proxy executor killing sub process");
                    let id = process.id().unwrap() as i32;
                    unsafe {
                        libc::kill(id, libc::SIGINT);
                    }
                }
            };
            Ok(())
        }));
        Ok(())
    }

    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(task) = self.task.take() {
            if let Some(sender) = self.sender.take() {
                let _ = sender.send(());
            };
            let _ = self.net_env.clear_bridge(&mut self.rtnl_handle).await;
            let _ = task.await?;
        }
        Ok(())
    }

    pub async fn reload(&mut self, config: ProxyRawConfig) -> anyhow::Result<()> {
        self.stop().await?;
        if config.proxy_ports.is_none() {
            return Ok(());
        }
        if self.task.is_none() {
            let mut new = Self::new(self.opt.verbose).await;
            self.net_env = new.net_env;
            self.opt = new.opt;
            self.sender = new.sender.take();
            self.rx = new.rx.take();
        }

        match self.exec(config).await {
            Err(e) => {
                self.net_env.clear_bridge(&mut self.rtnl_handle).await?;
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    }
}
