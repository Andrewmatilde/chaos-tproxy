//! Per-inbound-connection state + per-request orchestration.
//!
//! [`InboundConn`] owns one accepted HTTP/1 TCP connection:
//!   * the chaos config (shared via `Arc`)
//!   * the two endpoints of the original 5-tuple
//!   * an upstream-slot that pins one upstream `Stream` to this
//!     inbound for keep-alive, so the
//!     `(client_ip, client_port, target_ip, target_port)` 5-tuple
//!     stays stable across requests on the same inbound TCP
//!
//! `serve` drives the H1 keep-alive loop; `handle_request` runs one
//! full request/response cycle (rule matching, upstream forward,
//! response write — either codec-buffered or splice fast-path).

use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http::header::HOST;
use http::uri::{PathAndQuery, Scheme, Uri};
use http::{Request, Response, StatusCode};
use pingora_core::protocols::http::ServerSession;
use pingora_core::protocols::Stream;
use pingora_http::ResponseHeader as PingoraResponseHeader;
use tracing::{debug, error, trace};

use crate::handler::http::action::{apply_request_action, apply_response_action};
use crate::handler::http::rule::{Rule, Target};
use crate::handler::http::selector::{select_request, select_response, select_role};
use crate::proxy::bridge::{pingora_to_http_request, pingora_to_http_response};
use crate::proxy::config::HTTPConfig;
use crate::proxy::upstream;

/// Body size at or above which we try `splice(2)` instead of
/// userspace buffering. Empirically tuned: below ~128 KiB the saved
/// memcpy doesn't beat the fixed pipe2 + first-chunk-drain overhead.
pub(crate) const SPLICE_RESPONSE_MIN_BYTES: usize = 128 * 1024;

pub struct InboundConn {
    http_config: Arc<HTTPConfig>,
    peer: SocketAddr,
    target: SocketAddr,
    upstream_slot: Option<Stream>,
}

impl InboundConn {
    pub fn new(http_config: Arc<HTTPConfig>, peer: SocketAddr, target: SocketAddr) -> Self {
        Self {
            http_config,
            peer,
            target,
            upstream_slot: None,
        }
    }

    /// HTTP/1 keep-alive loop. Each iteration builds a fresh
    /// `ServerSession` from the recovered stream returned by
    /// `session.finish()`, drives one full request, and continues
    /// until the peer closes or an error occurs.
    pub async fn serve(mut self, mut stream: Stream) -> Result<()> {
        loop {
            let mut session = ServerSession::new_http1(stream);
            session.set_keepalive(Some(60));
            match self.handle_request(session).await? {
                Some(s) => stream = s,
                None => return Ok(()),
            }
        }
    }

    /// One full HTTP request/response cycle.
    async fn handle_request(&mut self, mut session: ServerSession) -> Result<Option<Stream>> {
        // Parse failures here drop the connection. The upfront
        // `looks_like_http` peek already catches genuinely non-HTTP
        // traffic; the remaining "passed peek but malformed HTTP"
        // cases (scanners, half-written clients, exotic ASCII
        // protocols) are rare enough in chaos-test environments
        // that we deliberately don't recover from them.
        match session.read_request().await {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(e) => {
                debug!("read_request: {}", e);
                return Ok(None);
            }
        }

        let role_ok = self.role_ok();
        let req_header = session.req_header().clone();
        let body_bytes = read_request_body_all(&mut session).await?;
        let mut request = pingora_to_http_request(&req_header, body_bytes)?;

        let port = self.target.port();
        let matched_req: Vec<&Rule> = self
            .http_config
            .rules
            .iter()
            .filter(|rule| {
                role_ok
                    && matches!(rule.target, Target::Request)
                    && select_request(port, &request, &rule.selector)
            })
            .collect();
        for rule in matched_req {
            debug!("request matched rule({:?})", rule);
            request = apply_request_action(request, &rule.actions).await?;
        }
        fixup_request_uri(&mut request, self.target)?;

        let uri = request.uri().clone();
        let method = request.method().clone();
        let req_headers = request.headers().clone();

        let (mut up, resp_header_pg) = match upstream::forward(
            &mut self.upstream_slot,
            self.peer,
            self.target,
            self.http_config.proxy_mark,
            request,
        )
        .await
        {
            Ok(x) => x,
            Err(e) => {
                error!("upstream forward failed: {}", e);
                self.upstream_slot = None;
                let resp = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Bytes::new())?;
                return write_response_buffered_and_finish(session, resp).await;
            }
        };

        let probe_resp = pingora_to_http_response(&resp_header_pg, Bytes::new())?;
        // Inline filter (rather than going through a `&self` method)
        // so the borrow checker can see that `self.http_config.rules`
        // and `self.upstream_slot` are disjoint fields.
        let matched: Vec<&Rule> = self
            .http_config
            .rules
            .iter()
            .filter(|rule| {
                role_ok
                    && matches!(rule.target, Target::Response)
                    && select_response(
                        port,
                        &uri,
                        &method,
                        &req_headers,
                        &probe_resp,
                        &rule.selector,
                    )
            })
            .collect();
        let any_body_rule = matched.iter().any(|r| rule_touches_body(r));

        let upstream_cl = resp_header_pg
            .headers
            .get("content-length")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .and_then(|s| s.trim().parse::<usize>().ok());
        let has_te_chunked = resp_header_pg
            .headers
            .get("transfer-encoding")
            .map(|v| v.as_bytes().eq_ignore_ascii_case(b"chunked"))
            .unwrap_or(false);

        // Splice fast-path: only when the inbound is H1 (H2 body
        // bytes are framed) and we don't need to inspect the body.
        if !session.is_http2() && !any_body_rule && !has_te_chunked {
            if let Some(cl) = upstream_cl {
                if cl >= SPLICE_RESPONSE_MIN_BYTES {
                    return upstream::splice_response(
                        session,
                        up,
                        &mut self.upstream_slot,
                        &resp_header_pg,
                        &matched,
                        cl,
                    )
                    .await;
                }
            }
        }

        // Buffered path: drain upstream body, build hyper Response,
        // run rules, write back via the codec.
        let resp_body = upstream::read_body_all(&mut up).await?;
        let mut response = pingora_to_http_response(&resp_header_pg, resp_body)?;
        up.respect_keepalive();
        if let Some(reused) = up.reuse().await {
            self.upstream_slot = Some(reused);
        }
        for rule in &matched {
            debug!("response matched rule({:?})", rule);
            response = apply_response_action(response, &rule.actions).await?;
        }
        write_response_buffered_and_finish(session, response).await
    }

    fn role_ok(&self) -> bool {
        match &self.http_config.role {
            None => true,
            Some(role) => select_role(&self.peer.ip(), &self.target.ip(), role),
        }
    }
}

// ---------------------------------------------------------------------
// Crate-internal helpers shared with upstream.rs
// ---------------------------------------------------------------------

/// `true` iff this rule needs to inspect or mutate the body.
pub(crate) fn rule_touches_body(rule: &Rule) -> bool {
    let replace_body = rule
        .actions
        .replace
        .as_ref()
        .map_or(false, |r| r.body.is_some());
    let patch_body = rule
        .actions
        .patch
        .as_ref()
        .map_or(false, |p| p.body.is_some());
    replace_body || patch_body
}

pub(crate) async fn write_response_buffered_and_finish(
    mut session: ServerSession,
    response: Response<Bytes>,
) -> Result<Option<Stream>> {
    let (parts, body_bytes) = response.into_parts();
    let mut resp_header =
        PingoraResponseHeader::build(parts.status.as_u16(), Some(parts.headers.len()))
            .map_err(|e| anyhow!("build response header: {}", e))?;
    for (k, v) in parts.headers.iter() {
        resp_header
            .append_header(k.as_str().to_string(), v.as_bytes())
            .map_err(|e| anyhow!("append header {}: {}", k, e))?;
    }
    let cl = body_bytes.len().to_string();
    resp_header
        .insert_header("content-length", cl.as_bytes())
        .map_err(|e| anyhow!("insert content-length: {}", e))?;
    resp_header.remove_header("transfer-encoding");

    session
        .write_response_header(Box::new(resp_header))
        .await
        .map_err(|e| anyhow!("write response header: {}", e))?;
    if !body_bytes.is_empty() {
        session
            .write_response_body(body_bytes, true)
            .await
            .map_err(|e| anyhow!("write response body: {}", e))?;
    }
    finish_inbound(session).await
}

pub(crate) async fn finish_inbound(session: ServerSession) -> Result<Option<Stream>> {
    match session.finish().await {
        Ok(Some(s)) => {
            trace!("h1 keepalive: reusing inbound stream");
            Ok(Some(s))
        }
        Ok(None) => Ok(None),
        Err(e) => {
            debug!("finish: {}", e);
            Ok(None)
        }
    }
}

async fn read_request_body_all(session: &mut ServerSession) -> Result<Bytes> {
    let mut acc = bytes::BytesMut::new();
    while let Some(chunk) = session
        .read_request_body()
        .await
        .map_err(|e| anyhow!("read body: {}", e))?
    {
        acc.extend_from_slice(&chunk);
    }
    Ok(acc.freeze())
}

fn fixup_request_uri(request: &mut Request<Bytes>, target: SocketAddr) -> Result<()> {
    let mut parts = request.uri().clone().into_parts();
    parts.authority = match request.headers().get(HOST) {
        Some(v) => Some(v.as_bytes().try_into()?),
        None => target.to_string().parse().ok(),
    };
    if parts.path_and_query.is_none() {
        parts.path_and_query = Some(PathAndQuery::from_static("/"));
    }
    parts.scheme = Some(Scheme::HTTP);
    *request.uri_mut() = Uri::from_parts(parts)?;
    Ok(())
}
