use super::bridge::{ip_netns, NetEnv};

pub fn set_iptables<'a>(
    net_env: &'a NetEnv,
    proxy_ports: &'a str,
    listen_port: &'a str,
    device_mac: &'a str,
) -> Vec<Vec<&'a str>> {
    vec![
        ip_netns(
            &net_env.netns,
            vec!["iptables", "-t", "mangle", "-N", "DIVERT"],
        ),
        ip_netns(
            &net_env.netns,
            vec![
                "iptables",
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "-m",
                "socket",
                "-j",
                "DIVERT",
            ],
        ),
        ip_netns(
            &net_env.netns,
            vec![
                "iptables",
                "-t",
                "mangle",
                "-A",
                "DIVERT",
                "-j",
                "MARK",
                "--set-mark",
                "1",
            ],
        ),
        ip_netns(
            &net_env.netns,
            vec!["iptables", "-t", "mangle", "-A", "DIVERT", "-j", "ACCEPT"],
        ),
        ip_netns(
            &net_env.netns,
            vec![
                "iptables",
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "-m",
                "multiport",
                "--dports",
                proxy_ports,
                "-j",
                "TPROXY",
                "--tproxy-mark",
                "0x1/0x1",
                "--on-port",
                listen_port,
            ],
        ),
        ip_netns(
            &net_env.netns,
            vec![
                "ebtables-legacy",
                "-t",
                "broute",
                "-A",
                "BROUTING",
                "-p",
                "IPv4",
                "--ip-proto",
                "6",
                "--ip-dport",
                "!",
                "22",
                "--ip-sport",
                "!",
                "22",
                "-j",
                "redirect",
                "--redirect-target",
                "DROP",
            ],
        ),
        vec![
            "ebtables",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            &net_env.device,
            "-j",
            "dnat",
            "--to-dst",
            device_mac,
            "--dnat-target",
            "ACCEPT",
        ],
    ]
}

pub fn clear_ebtables() -> Vec<&'static str> {
    vec!["ebtables", "-t", "nat", "-F"]
}
