//! Pingora-based HTTP proxy backend.
//!
//! Drop-in replacement for [`crate::proxy::http::server::HttpServer`]
//! backed by `pingora::proxy::ProxyHttp`.
//!
//! The proxy process is expected to be launched inside the right netns
//! already (chaosns for the BPF loader, or the target netns directly).
//! It binds `0.0.0.0:listen_port` itself — no listener-fd handoff from
//! the loader.
//!
//! Transparent-proxy semantics are preserved by:
//!   * SO_ORIGINAL_DST for the pre-redirect destination (BPF/iptables
//!     loaders both set this up so `getsockopt(SO_ORIGINAL_DST)` works).
//!   * Upstream socket is configured via pingora's
//!     `upstream_tcp_sock_tweak_hook` to set IP_TRANSPARENT + SO_MARK,
//!     and `PeerOptions.bind_to` to forge the original client
//!     (ip, port) as the source of the onward connection.

use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::connectors::l4::BindTo;
use pingora_core::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use pingora_core::server::configuration::ServerConf;
use pingora_core::server::Server;
use pingora_core::services::listening::Service as ListeningService;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use tracing::debug;

use crate::handler::http::rule::Target;
use crate::proxy::http::config::HTTPConfig;

pub struct ChaosProxy {
    http_config: Arc<HTTPConfig>,
}

impl ChaosProxy {
    pub fn new(http_config: Arc<HTTPConfig>) -> Self {
        Self { http_config }
    }
}

#[derive(Default)]
pub struct Ctx {
    target: Option<SocketAddr>,
    remote: Option<SocketAddr>,
}

#[async_trait]
impl ProxyHttp for ChaosProxy {
    type CTX = Ctx;
    fn new_ctx(&self) -> Self::CTX {
        Ctx::default()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        eprintln!(
            "DBG request_filter: server_addr={:?} client_addr={:?}",
            session.server_addr(),
            session.client_addr()
        );
        if ctx.target.is_none() {
            ctx.target = session.server_addr().and_then(to_std_addr);
            ctx.remote = session.client_addr().and_then(to_std_addr);
            debug!(
                "Accept streaming: remote={:?}, local={:?}",
                ctx.remote, ctx.target
            );
        }

        let role_ok = self.role_ok(ctx);
        for rule in self.http_config.rules.iter() {
            if !role_ok || !matches!(rule.target, Target::Request) {
                continue;
            }
            if !selector_matches_request(ctx, session, &rule.selector) {
                continue;
            }
            debug!("request matched, rule({:?})", rule);
            if let Some(delay) = rule.actions.delay {
                tokio::time::sleep(delay).await;
            }
            if rule.actions.abort {
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(502),
                    "chaos abort",
                ));
            }
            // body mutations (replace/patch) TODO in a follow-up
        }
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        let target = ctx.target.ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "missing target addr",
            )
        })?;

        let mut peer = HttpPeer::new(target, false, String::new());

        if let Some(src) = ctx.remote {
            let mut bind = BindTo::default();
            bind.addr = Some(src);
            peer.options.bind_to = Some(bind);
        }
        let proxy_mark = self.http_config.proxy_mark;
        peer.options.upstream_tcp_sock_tweak_hook = Some(Arc::new(move |socket| {
            set_ip_transparent(socket.as_raw_fd()).map_err(|e| {
                pingora_core::Error::explain(
                    pingora_core::ErrorType::SocketError,
                    format!("IP_TRANSPARENT: {e}"),
                )
            })?;
            if let Some(m) = proxy_mark {
                set_so_mark(socket.as_raw_fd(), m).map_err(|e| {
                    pingora_core::Error::explain(
                        pingora_core::ErrorType::SocketError,
                        format!("SO_MARK: {e}"),
                    )
                })?;
            }
            Ok(())
        }));

        Ok(Box::new(peer))
    }
}

impl ChaosProxy {
    fn role_ok(&self, ctx: &Ctx) -> bool {
        match (&self.http_config.role, ctx.remote, ctx.target) {
            (None, _, _) => true,
            (Some(role), Some(r), Some(t)) => {
                crate::handler::http::selector::select_role(&r.ip(), &t.ip(), role)
            }
            _ => false,
        }
    }
}

fn selector_matches_request(
    ctx: &Ctx,
    session: &Session,
    selector: &crate::handler::http::selector::Selector,
) -> bool {
    if let Some(want_port) = selector.port {
        let actual = ctx.target.map(|t| t.port()).unwrap_or(0);
        if actual != want_port {
            return false;
        }
    }

    let req = session.req_header();

    if let Some(ref want_method) = selector.method {
        if req.method.as_str() != want_method.as_str() {
            return false;
        }
    }

    if let Some(ref want_path) = selector.path {
        let actual = req.uri.path();
        if !want_path.matches(actual) {
            return false;
        }
    }

    if let Some(ref want) = selector.request_headers {
        for (k, v) in want.iter() {
            let k_str = k.as_str();
            match req.headers.get(k_str) {
                Some(hv) if hv.as_bytes() == v.as_bytes() => {}
                _ => return false,
            }
        }
    }

    true
}

fn to_std_addr(addr: &PingoraSocketAddr) -> Option<SocketAddr> {
    match addr {
        PingoraSocketAddr::Inet(a) => Some(*a),
        _ => None,
    }
}

fn set_ip_transparent(fd: RawFd) -> std::io::Result<()> {
    use std::mem;
    unsafe {
        let enable: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &enable as *const _ as *const _,
            mem::size_of_val(&enable) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn set_so_mark(fd: RawFd, mark: u32) -> std::io::Result<()> {
    use std::mem;
    unsafe {
        let m: libc::c_uint = mark as libc::c_uint;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &m as *const _ as *const _,
            mem::size_of_val(&m) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Run the pingora-based proxy. Blocks the current thread — pingora's
/// `Server::run_forever` takes over.
pub fn run(http_config: Arc<HTTPConfig>) -> anyhow::Result<()> {
    // Bridge `log` crate output (used by pingora internally) into our
    // tracing subscriber. Without this pingora's info!/error! calls
    // go to /dev/null.
    let _ = tracing_log::LogTracer::init();

    let listen_port = http_config.listen_port;
    let proxy = ChaosProxy::new(http_config);

    // Build a multi-core ServerConf. The default `Server::new(None)`
    // gives us threads=1, listener_tasks_per_fd=1 — single-threaded.
    // We bump both to all cores and raise the upstream keepalive pool
    // so wrk-style sustained load can actually reuse connections.
    let cores = num_cpus::get().max(1);
    let mut conf = ServerConf::default();
    conf.threads = cores;
    conf.listener_tasks_per_fd = cores;
    conf.upstream_keepalive_pool_size = 1024;
    tracing::info!(
        "Pingora ServerConf: threads={} listener_tasks_per_fd={}",
        cores,
        cores
    );

    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let mut svc = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    let mut sock_opts = pingora_core::listeners::TcpSocketOptions::default();
    sock_opts.ip_transparent = Some(true);
    // SO_REUSEPORT so all worker threads can accept on the same port
    // without serialising through one accept syscall.
    sock_opts.so_reuseport = Some(true);
    svc.add_tcp_with_settings(&format!("0.0.0.0:{}", listen_port), sock_opts);
    // Bump the number of threads pingora allocates to this specific
    // service (overrides ServerConf.threads when set).
    svc.threads = Some(cores);

    server.add_service(svc);
    tracing::info!("Pingora proxy listening on 0.0.0.0:{}", listen_port);
    server.run_forever();
}

// Silence unused-import warnings from the ListeningService import which
// is here so that future TLS/TCP options can reach it cleanly.
#[allow(dead_code)]
fn _silence<T>(_: ListeningService<T>) {}
