use rtnetlink::Handle;

use super::bridge::{bash_c, execute, execute_all, get_interface, NetEnv};
use super::iptables::set_iptables;

#[cfg(target_os = "linux")]
pub async fn set_net(
    handle: &mut Handle,
    net_env: &NetEnv,
    proxy_ports: String,
    listen_port: u16,
) -> anyhow::Result<()> {
    net_env.setenv_bridge(handle).await?;
    let port = listen_port.to_string();
    let restore_dns = "cp /etc/resolv.conf.bak /etc/resolv.conf";
    let device_interface = get_interface(net_env.veth4.clone()).unwrap();
    let device_mac = device_interface.mac.unwrap().to_string();

    execute_all(set_iptables(net_env, &proxy_ports, &port, &device_mac))?;

    let _ = execute(bash_c(restore_dns));
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn set_env() {}
