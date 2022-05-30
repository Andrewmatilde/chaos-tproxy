use std::process::Stdio;

use tokio::process::Command;

pub struct Executor {
    pub cmds: Vec<String>,
    pub netns: String,
}

impl Executor {
    pub fn new(cmds: Vec<String>, netns: String) -> Self {
        Self { cmds, netns }
    }
    pub async fn exec(self) {
        for cmd in self.cmds {
            let mut command = Command::new("ip");
            command.arg("netns").arg("exec").arg(self.netns.clone());
            let args: Vec<&str> = cmd.split(' ').filter(|&p| !p.is_empty()).collect();
            command.args(args);
            tracing::info!("try run {:?}", command);
            tokio::spawn(async move {
                let mut process = match command.stdin(Stdio::piped()).spawn() {
                    Ok(process) => {
                        tracing::info!("Process is running.");
                        process
                    }
                    Err(e) => {
                        tracing::error!("failed to exec command : {:?}", e);
                        return;
                    }
                };
                if let Err(e) = process.wait().await {
                    tracing::error!("wait exec command with error : {:?}", e);
                };
            });
        }
    }
}
