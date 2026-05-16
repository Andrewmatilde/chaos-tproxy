//! pingora framework adapter — the only place that talks to
//! pingora's `ServerApp` / `Server` / `ListeningService` APIs.
//!
//! Per accepted TCP connection, `process_new` does the cheap L4
//! sniff and routes into one of three paths:
//!
//!   1. peek bytes don't look like HTTP → [`l4_tunnel`]
//!      (SSH / TLS / arbitrary TCP)
//!   2. peek starts with `PRI ` → HTTP/2 connection preface →
//!      also `l4_tunnel`. H2 is passed through untouched; chaos
//!      rules deliberately do NOT fire on H2.
//!   3. otherwise → [`crate::proxy::inbound::InboundConn::serve`],
//!      which owns the per-TCP keep-alive loop and per-request
//!      orchestration.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use pingora_core::apps::ServerApp;
use pingora_core::listeners::TcpSocketOptions;
use pingora_core::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use pingora_core::protocols::Stream;
use pingora_core::server::configuration::ServerConf;
use pingora_core::server::{Server, ShutdownWatch};
use pingora_core::services::listening::Service as ListeningService;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tracing::{debug, error};

use crate::proxy::config::HTTPConfig;
use crate::proxy::inbound::InboundConn;
use crate::proxy::transparent_socket::TransparentSocket;

pub struct ChaosCodecApp {
    pub http_config: Arc<HTTPConfig>,
}

impl ChaosCodecApp {
    pub fn new(http_config: Arc<HTTPConfig>) -> Self {
        Self { http_config }
    }
}

#[async_trait]
impl ServerApp for ChaosCodecApp {
    async fn process_new(
        self: &Arc<Self>,
        mut stream: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let (peer, target) = match stream_addrs(&stream) {
            Some(a) => a,
            None => {
                debug!("missing socket addrs on accepted stream; dropping");
                return None;
            }
        };

        // L4 fallback peek: 8 bytes is enough — we need 4 for the
        // H2 preface check and 1 for the first-letter sniff. Larger
        // peek windows deadlock on minimal wrk-style requests where
        // the first packet carries fewer bytes than the window.
        let mut sniff = [0u8; 8];
        match stream.try_peek(&mut sniff).await {
            Ok(true) => {
                if !looks_like_http(&sniff) {
                    debug!("non-HTTP on {:?} -> L4 tunnel to {:?}", peer, target);
                    let _ = l4_tunnel(stream, peer, target, self.http_config.proxy_mark).await;
                    return None;
                }
                if sniff.starts_with(b"PRI ") {
                    debug!("HTTP/2 on {:?} -> transparent L4 passthrough to {:?}", peer, target);
                    let _ = l4_tunnel(stream, peer, target, self.http_config.proxy_mark).await;
                    return None;
                }
            }
            Ok(false) => {}
            Err(e) => {
                debug!("peek failed: {}", e);
                return None;
            }
        }

        let conn = InboundConn::new(self.http_config.clone(), peer, target);
        if let Err(e) = conn.serve(stream).await {
            let msg = e.to_string();
            if !msg.contains("ConnectionClosed") && !msg.contains("shutting down") {
                error!("h1 request: {}", e);
            }
        }
        None
    }

    async fn cleanup(&self) {}
}

/// Boot the pingora `Server` with `ChaosCodecApp` on a single
/// transparent listening socket. Blocks the current thread.
pub fn run(http_config: Arc<HTTPConfig>) -> anyhow::Result<()> {
    let _ = tracing_log::LogTracer::init();

    let listen_port = http_config.listen_port;
    let app = ChaosCodecApp::new(http_config);

    let cores = num_cpus::get().max(1);
    let mut conf = ServerConf::default();
    conf.threads = cores;
    conf.listener_tasks_per_fd = cores;
    tracing::info!(
        "ChaosCodec ServerConf: threads={} listener_tasks_per_fd={}",
        cores,
        cores
    );

    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let mut svc = ListeningService::new("chaos-codec".into(), app);
    let mut sock_opts = TcpSocketOptions::default();
    sock_opts.ip_transparent = Some(true);
    sock_opts.so_reuseport = Some(true);
    svc.add_tcp_with_settings(&format!("0.0.0.0:{}", listen_port), sock_opts);
    svc.threads = Some(cores);

    server.add_service(svc);
    tracing::info!("ChaosCodec proxy listening on 0.0.0.0:{}", listen_port);
    server.run_forever();
}

// ---------------------------------------------------------------------
// L4 tunnel + sniff helpers (stateless, framework-adjacent)
// ---------------------------------------------------------------------

/// Cheap "is this an HTTP request?" sniff used to decide between the
/// codec path and the L4 tunnel fallback.
///
/// HTTP request-lines (RFC 9112 §2.1) start with a method token,
/// which per RFC 9110 §9.1 is a token of `tchar`s — in practice
/// always uppercase ASCII for the IANA-registered methods, the H2
/// preface (`PRI`), and the common extensions (PROPFIND, PURGE, etc).
/// Anything that doesn't start with an uppercase ASCII letter is
/// either binary (TLS ClientHello `0x16…`), or a lowercase HTTP
/// method we don't handle anyway.
fn looks_like_http(buf: &[u8]) -> bool {
    !buf.is_empty() && buf[0].is_ascii_uppercase()
}

fn stream_addrs(stream: &Stream) -> Option<(SocketAddr, SocketAddr)> {
    let sd = stream.get_socket_digest()?;
    let peer = to_std(sd.peer_addr()?)?;
    let local = to_std(sd.local_addr()?)?;
    Some((peer, local))
}

fn to_std(addr: &PingoraSocketAddr) -> Option<SocketAddr> {
    match addr {
        PingoraSocketAddr::Inet(a) => Some(*a),
        _ => None,
    }
}

async fn l4_tunnel(
    mut downstream: Stream,
    addr_remote: SocketAddr,
    addr_local: SocketAddr,
    proxy_mark: Option<u32>,
) -> Result<()> {
    debug!(
        "L4 fallback: tunneling raw bytes remote={} -> target={}",
        addr_remote, addr_local
    );
    let sock = TransparentSocket::new_with_mark(addr_remote, proxy_mark);
    let mut upstream = sock.conn(addr_local).await?;
    let _ = downstream.flush().await;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}
