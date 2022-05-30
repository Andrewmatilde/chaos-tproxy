use tokio::process::Command;
use tokio::select;
use tokio::sync::oneshot::{channel, Receiver, Sender};

pub struct Executor {
    pub cmd: String,
    pub netns: String,
    pub sender: Sender<()>,
    pub rx: Option<Receiver<()>>,
}

impl Executor {
    pub fn new(cmd: String, netns: String) -> Self {
        let (sender, rx) = channel();
        Self {
            cmd,
            netns,
            sender,
            rx: Some(rx),
        }
    }
    pub async fn exec(&mut self) {
        let mut command = Command::new("ip");
        command.arg("netns").arg("exec").arg(self.netns.clone());
        let args: Vec<&str> = self.cmd.split(' ').filter(|&p| !p.is_empty()).collect();
        command.args(args);
        tracing::info!("try run {:?}", command);
        let rx = self.rx.take().unwrap();
        tokio::spawn(async move {
            let mut process = match command.spawn() {
                Ok(process) => {
                    tracing::info!("Process is running.");
                    process
                }
                Err(e) => {
                    tracing::error!("failed to exec command : {:?}", e);
                    return;
                }
            };
            select! {
                _ = process.wait() => {
                    tracing::info!("sub process:{:?} exit",process);
                }
                _ = rx => {
                    tracing::info!("executor killing sub process:{:?}",process);
                    let id = process.id().unwrap() as i32;
                    unsafe {
                        libc::kill(id, libc::SIGINT);
                    }
                }
            };
        });
    }
    pub fn stop(self) {
        if self.sender.send(()).is_err() {
            tracing::error!("send stop msg failed");
        }
    }
}
