# chaos-tproxy-ebpf-loader

eBPF-based traffic redirection for chaos-tproxy, scoped to a single
container's network namespace. Replaces the host-level netns/bridges/
veths/iptables/ebtables surgery done by `chaos-tproxy-controller` with
three TC clsact eBPF programs:

| Program            | Hook                  | Job |
|--------------------|-----------------------|-----|
| `tc_redirect_ingress` | `eth0` ingress     | `bpf_sk_assign` matching TCP to the proxy's `IP_TRANSPARENT` listener |
| `tc_redirect_egress`  | `eth0` egress      | Bounce container-originated TCP to `lo` so the ingress hook can pick it up; skip if `skb->mark == proxy_mark` (proxy's onward connection) |
| `tc_redirect_ingress` | `lo` ingress       | Same as above; catches the packets bounced from eth0 egress |

Reference: dae's `control/kern/tproxy.c` (`assign_listener` helper).

## Deploy

```bash
make ebpf-image       # builds chaos-mesh/tproxy-ebpf

# 1. Run your target service.
docker run -d --name target -p 18080:80 nginx:alpine

# 2. Run the chaos sidecar joined to its netns + pid namespace.
cat > /tmp/chaos.yaml <<EOF
proxy_ports: "80"
listen_port: 58080
rules:
  - target: Request
    selector:
      method: GET
    actions:
      delay: 3s
EOF

docker run --rm --privileged \
    --network=container:target --pid=container:target \
    -v /tmp/chaos.yaml:/etc/chaos.yaml:ro \
    -v /sys/fs/bpf:/sys/fs/bpf \
    chaos-mesh/tproxy-ebpf --config /etc/chaos.yaml

# 3. Verify
curl -w '%{time_total}\n' -s -o /dev/null http://localhost:18080/
# -> should now take ~3s
```

## Config schema

The YAML is a superset of `chaos-tproxy-proxy`'s `RawConfig` (so all
existing rule fields work). Loader-only additions:

| Key          | Default  | Meaning |
|--------------|----------|---------|
| `container`  | (none)   | Informational; the sidecar must be deployed into the target's netns. |
| `proxy_mark` | `0xCFC1` | `SO_MARK` set on the proxy's onward connections; the BPF egress hook skips packets carrying this mark to break the redirect loop. |
| `iface_wan`  | `eth0`   | WAN-side interface inside the netns. |
| `iface_lo`   | `lo`     | Loopback interface inside the netns. |

## Kernel requirements

- `bpf_sk_assign` (kernel ≥ 5.7).
- TCX is used when available (kernel ≥ 6.6); falls back to legacy
  `clsact` + `bpf` filter on older kernels.
- `IP_TRANSPARENT` listener — already what chaos-tproxy-proxy does.

## Limitations

- TCP only. UDP redirect is not implemented (chaos-tproxy-proxy itself
  is TCP-only).
- IPv4 only at present.
- One target container per loader instance.
- Loader must run with `CAP_BPF` + `CAP_NET_ADMIN` (or just
  `--privileged`).
