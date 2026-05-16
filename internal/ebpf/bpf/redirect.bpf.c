// SPDX-License-Identifier: GPL-2.0
//
// chaos-tproxy eBPF redirect, dae-style.
//
// Topology (all inside the target container's netns):
//
//   eth0 ────────────── dae0 ═══veth═══ dae0peer ────── lo
//                       └─host───┘     └─── chaosns ───┘
//                                       │
//                                       └── chaos-tproxy-proxy
//                                           (listens 0.0.0.0:LISTEN_PORT, IP_TRANSPARENT)
//
//   tc/eth0_ingress       on target-netns eth0 ingress
//   tc/dae0_ingress       on target-netns dae0  ingress
//   tc/dae0peer_ingress   on chaosns       dae0peer ingress
//
// Forward path (client → proxy):
//   client → eth0_ingress: dst==nginx_ip & proxy_port & mark==0
//     → rewrite h_dest = dae0peer_mac, bpf_redirect(dae0)
//   → dae0peer_ingress: mark = TPROXY_MARK, sk_assign(listener) on SYN
//   → fwmark + ip route local default dev lo table 2023 → kernel delivers locally
//   → proxy accept(); peer_addr()=client, local_addr()=nginx_ip:80 (IP_TRANSPARENT)
//
// Proxy → upstream (forged src):
//   proxy connect() with bind(client_ip)+SO_MARK=PROXY_MARK+IP_TRANSPARENT
//   → packet leaves chaosns via dae0peer (default route)
//   → dae0_ingress: mark==PROXY_MARK → bpf_redirect(eth0)
//   → eth0 egress (no hook) → nginx
//   nginx sees src=client_ip
//
// Nginx → "client" (reply):
//   nginx → eth0_ingress: src==nginx_ip & mark==0 → redirect to dae0
//   → dae0peer_ingress: established socket lookup → proxy
//
// Proxy → client (reply from listener):
//   proxy listener emits SYN-ACK; chaosns has no route for client_ip;
//   default route via 169.254.0.1 dev dae0peer → dae0_ingress
//   → mark != PROXY_MARK → bpf_redirect(eth0) (egress fanout)
//   → client

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef PACKET_HOST
#define PACKET_HOST 0   // from <linux/if_packet.h>: "destined for this host"
#endif

#define TPROXY_MARK 0x8000000u

struct chaos_params {
	__u32 proxy_mark;       // SO_MARK proxy uses on its onward sockets
	__u32 nginx_ip;         // target service IP, network byte order (v4 only for v1)
	__u32 dae0_ifindex;     // ifindex of dae0 (host side of veth, in target netns)
	__u32 eth0_ifindex;     // ifindex of target eth0
	__u32 lo_ifindex;       // ifindex of target lo
	__u8  dae0peer_mac[6];  // MAC of dae0peer (chaosns side); used to rewrite h_dest
	__u8  _pad0[2];
	__u8  eth0_mac[6];      // MAC of target eth0 (= nginx's MAC, same container)
	__u8  _pad1[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct chaos_params);
} params_map SEC(".maps");

// proxy_ports: set of TCP dst ports (network byte order) to capture.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, __u8);
} proxy_ports SEC(".maps");

// flow_key: identifies a TCP 5-tuple from the client's perspective.
// We use (client_ip, nginx_ip, client_port, nginx_port) — no l4proto since
// we only handle TCP.
struct flow_key {
	__u32 client_ip;   // remote/client IP (network byte order)
	__u32 nginx_ip;    // local/nginx IP (network byte order); always p->nginx_ip
	__u16 client_port; // remote/client port (network byte order)
	__u16 nginx_port;  // local/nginx port (network byte order)
};

// l2_info stores the original Ethernet header info captured when the
// client's SYN traversed eth0_ingress, so dae0_ingress can restore it
// when sending packets back out toward the client.
struct l2_info {
	__u8 orig_smac[6]; // src mac on the inbound packet (= client/gw mac)
	__u8 orig_dmac[6]; // dst mac on the inbound packet (= eth0's own mac)
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow_key);
	__type(value, struct l2_info);
} flow_l2 SEC(".maps");

// listen_socket_map: SOCKMAP holding the proxy's IP_TRANSPARENT listener fd.
// Populated from userspace via SCM_RIGHTS handoff.
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} listen_socket_map SEC(".maps");

static __always_inline struct chaos_params *get_params(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&params_map, &k);
}

static __always_inline int port_is_proxied(__u16 dport_be)
{
	return bpf_map_lookup_elem(&proxy_ports, &dport_be) ? 1 : 0;
}

// parse_v4_tcp: validate Ethernet + IPv4 + TCP, return saddr/daddr/dport in network byte order.
static __always_inline int parse_v4_tcp(struct __sk_buff *skb,
				        __u32 *saddr, __u32 *daddr,
				        __u16 *sport, __u16 *dport,
				        __u8  *tcp_flags)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + ETH_HLEN > data_end)
		return 0;
	struct ethhdr *eth = data;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;

	struct iphdr *iph = data + ETH_HLEN;
	if ((void *)(iph + 1) > data_end)
		return 0;
	if (iph->protocol != IPPROTO_TCP)
		return 0;

	__u32 ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		return 0;
	struct tcphdr *tcph = (void *)iph + ihl;
	if ((void *)(tcph + 1) > data_end)
		return 0;

	*saddr = iph->saddr;
	*daddr = iph->daddr;
	*sport = tcph->source;
	*dport = tcph->dest;
	// tcp_flags: pull the byte that contains SYN/ACK/FIN/RST bits.
	// Layout: doff:4|res:4|flags:8 — flags byte sits at offset 13 from tcph.
	__u8 *flags_byte = (void *)tcph + 13;
	if ((void *)(flags_byte + 1) > data_end)
		return 0;
	*tcp_flags = *flags_byte;
	return 1;
}

#define TCPH_FIN  0x01
#define TCPH_SYN  0x02
#define TCPH_RST  0x04
#define TCPH_ACK  0x10

static __always_inline int assign_listener(struct __sk_buff *skb)
{
	__u32 k = 0;
	struct bpf_sock *sk = bpf_map_lookup_elem(&listen_socket_map, &k);
	if (!sk)
		return -1;
	int ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	return ret;
}

// eth0 egress: catch nginx's reply to proxy's forged connection
// (src=nginx_ip, dst=client_ip with sport in proxy_ports). nginx's
// stack tries to send these out, but client_ip isn't really on the
// docker bridge in the sense nginx expects — proxy is. Bounce these
// back into chaosns so the proxy's onward-connection socket can pick
// them up via established-lookup.
SEC("tc/eth0_egress")
int tc_eth0_egress(struct __sk_buff *skb)
{
	struct chaos_params *p = get_params();
	if (!p)
		return TC_ACT_OK;

	__u32 saddr, daddr; __u16 sport, dport; __u8 flags;
	if (!parse_v4_tcp(skb, &saddr, &daddr, &sport, &dport, &flags))
		return TC_ACT_OK;

	// Packets carrying proxy_mark have already been processed by
	// dae0_ingress (case (a): proxy reply to client). Let them pass.
	if (skb->mark == p->proxy_mark)
		return TC_ACT_OK;

	// Only catch nginx's reply to the proxy's forged onward connection.
	// Distinguishing feature: src=nginx_ip and the source port is one
	// of the proxy_ports (i.e. the connection was made TO :80).
	if (saddr != p->nginx_ip || !port_is_proxied(sport))
		return TC_ACT_OK;

	// Rewrite dst MAC to dae0peer so the redirect lands cleanly.
	(void)bpf_skb_store_bytes(skb,
		offsetof(struct ethhdr, h_dest),
		p->dae0peer_mac, 6, 0);
	return bpf_redirect(p->dae0_ifindex, 0);
}

// eth0 ingress: catch flows involving nginx and bounce them into chaosns via dae0.
SEC("tc/eth0_ingress")
int tc_eth0_ingress(struct __sk_buff *skb)
{
	struct chaos_params *p = get_params();
	if (!p)
		return TC_ACT_OK;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data + ETH_HLEN > data_end)
		return TC_ACT_OK;
	struct ethhdr *eth = data;

	// Magic source MAC signaling "this is proxy-originated, let it pass".
	if (eth->h_source[0] == 0x02 &&
	    eth->h_source[1] == 0xce &&
	    eth->h_source[2] == 0x05 &&
	    eth->h_source[3] == 0xc1 &&
	    eth->h_source[4] == 0xc1 &&
	    eth->h_source[5] == 0xc1)
		return TC_ACT_OK;

	__u32 saddr, daddr; __u16 sport, dport; __u8 flags;
	if (!parse_v4_tcp(skb, &saddr, &daddr, &sport, &dport, &flags))
		return TC_ACT_OK;

	// Forward path (client → nginx): dst is nginx_ip + dport in proxy_ports.
	int forward = (daddr == p->nginx_ip) && port_is_proxied(dport);
	// Reply path (nginx → client): src is nginx_ip.
	int reply   = (saddr == p->nginx_ip);
	if (!forward && !reply)
		return TC_ACT_OK;

	// On the forward path, capture the original Ethernet header so we
	// can restore it on the reverse direction in dae0_ingress.
	if (forward) {
		struct flow_key fk = {
			.client_ip   = saddr,
			.nginx_ip    = daddr,
			.client_port = sport,
			.nginx_port  = dport,
		};
		struct l2_info l2 = {};
		__builtin_memcpy(l2.orig_smac, eth->h_source, 6);
		__builtin_memcpy(l2.orig_dmac, eth->h_dest,   6);
		bpf_map_update_elem(&flow_l2, &fk, &l2, BPF_ANY);
	}

	// Rewrite h_dest to dae0peer's MAC so bpf_redirect lands on the peer.
	if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
				p->dae0peer_mac, 6, 0) < 0)
		return TC_ACT_OK;

	return bpf_redirect(p->dae0_ifindex, 0);
}

// dae0 ingress: chaosns has sent something out — either proxy's forged
// outbound (mark==PROXY_MARK, dst=nginx) or proxy's reply to client.
// Both need to leave via target eth0 with the right MAC addresses so
// the docker bridge accepts the frame.
SEC("tc/dae0_ingress")
int tc_dae0_ingress(struct __sk_buff *skb)
{
	struct chaos_params *p = get_params();
	if (!p)
		return TC_ACT_OK;

	__u32 saddr, daddr; __u16 sport, dport; __u8 flags;
	if (!parse_v4_tcp(skb, &saddr, &daddr, &sport, &dport, &flags))
		return bpf_redirect(p->eth0_ifindex, 0);

	// Two outbound shapes we care about, both going out target eth0:
	//   (a) proxy reply to client: src=nginx_ip, dst=client_ip
	//       Look up flow_l2[(client=dst, nginx=src, client_port=dport, nginx_port=sport)]
	//       and restore the original ethhdr.
	//   (b) proxy forged onward to nginx: src=client_ip, dst=nginx_ip, mark==PROXY_MARK
	//       L2 doesn't matter as much because eth0 -> docker bridge will
	//       still resolve via normal ARP; but we still want the source MAC
	//       to be eth0's own MAC so docker bridge accepts it. Easiest: try
	//       a flow_l2 lookup on the reversed tuple; if hit, use orig_dmac
	//       as our smac and a broadcast/arp-resolved gateway dmac is too
	//       complex — instead, fall back to the original ethhdr the proxy
	//       sent: src=dae0peer_mac, dst=dae0_mac. Docker bridge will see
	//       a strange src MAC but will still bridge to nginx since dst_ip
	//       is local. We rewrite dmac to broadcast to force ARP-like flooding
	//       — actually simpler: leave it alone for now, see if (a) alone fixes curl.
	if (saddr == p->nginx_ip) {
		// Case (a): proxy reply to client.
		// Original inbound:  src_mac = client_mac, dst_mac = eth0_mac.
		// Reply out should be:  src_mac = eth0_mac, dst_mac = client_mac.
		struct flow_key fk = {
			.client_ip   = daddr,
			.nginx_ip    = saddr,
			.client_port = dport,
			.nginx_port  = sport,
		};
		struct l2_info *l2 = bpf_map_lookup_elem(&flow_l2, &fk);
		if (l2) {
			(void)bpf_skb_store_bytes(skb,
				offsetof(struct ethhdr, h_source),
				l2->orig_dmac, 6, 0);
			(void)bpf_skb_store_bytes(skb,
				offsetof(struct ethhdr, h_dest),
				l2->orig_smac, 6, 0);
		}
		// Tag the packet so eth0_egress recognises this as "already
		// processed reply" and lets it through. Otherwise eth0_egress
		// would mis-classify it as nginx's own reply (same 5-tuple,
		// same MACs) and bounce it back into chaosns.
		skb->mark = p->proxy_mark;
	} else if (daddr == p->nginx_ip) {
		// Case (b): proxy forged onward to nginx (dst=nginx_ip), same
		// netns. We need to deliver this packet to the local nginx
		// listener via eth0 ingress path. Two L2 changes are required:
		//   - src MAC = magic, so eth0_ingress recognizes it and lets
		//     it pass (avoiding loopback into chaosns).
		//   - dst MAC = eth0's own MAC (saved as orig_dmac from any
		//     prior inbound flow), so eth_type_trans (called by
		//     dev_forward_skb after the redirect) classifies it as
		//     PACKET_HOST instead of PACKET_OTHERHOST and the local
		//     stack accepts it.
		__u8 magic_smac[6] = {0x02, 0xce, 0x05, 0xc1, 0xc1, 0xc1};
		(void)bpf_skb_store_bytes(skb,
			offsetof(struct ethhdr, h_source),
			magic_smac, 6, 0);
		// dst MAC = eth0's own MAC, configured by loader at startup.
		(void)bpf_skb_store_bytes(skb,
			offsetof(struct ethhdr, h_dest),
			p->eth0_mac, 6, 0);
		return bpf_redirect(p->eth0_ifindex, BPF_F_INGRESS);
	}
	return bpf_redirect(p->eth0_ifindex, 0);
}

// dae0peer ingress (in chaosns): mark and (for SYNs) assign to listener.
SEC("tc/dae0peer_ingress")
int tc_dae0peer_ingress(struct __sk_buff *skb)
{
	__u32 saddr, daddr; __u16 sport, dport; __u8 flags;
	if (!parse_v4_tcp(skb, &saddr, &daddr, &sport, &dport, &flags))
		return TC_ACT_OK;

	// Mark every packet so the chaosns fwmark route ('local default dev lo'
	// for fwmark TPROXY_MARK) treats any dst as locally-deliverable.
	skb->mark = TPROXY_MARK;

	// For SYN (new connection) explicitly assign to the listener.
	// For established traffic the kernel finds the child socket via 5-tuple
	// lookup; no assignment needed.
	if ((flags & (TCPH_SYN | TCPH_ACK)) == TCPH_SYN)
		(void)assign_listener(skb);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
