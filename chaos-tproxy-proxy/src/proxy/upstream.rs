//! Upstream side of the proxy: build & send the upstream HTTP/1
//! request, read the response header, and either drain the body
//! through the codec or splice it directly between the inbound and
//! upstream TCP sockets when the body is large and no body-mutating
//! rule matches.

use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http::Request;
use pingora_core::protocols::http::v1::client::HttpSession as UpstreamSession;
use pingora_core::protocols::http::ServerSession;
use pingora_core::protocols::Stream;
use pingora_http::{RequestHeader as PingoraRequestHeader, ResponseHeader as PingoraResponseHeader};
use tracing::debug;

use crate::handler::http::action::apply_response_action;
use crate::handler::http::rule::Rule;
use crate::proxy::bridge::{http_version_to_pingora, pingora_to_http_response};
use crate::proxy::inbound::finish_inbound;
use crate::proxy::splice::splice_n;
use crate::proxy::transparent_socket::TransparentSocket;

/// Send the request upstream and read back the response header, but
/// stop short of draining the response body. Returns the live
/// [`UpstreamSession`] so the caller can choose either codec-driven
/// drain (small bodies, mutated bodies) or `splice(2)` (big bodies).
///
/// `slot` carries an idle upstream Stream from a previous request on
/// the same inbound connection so the
/// `(client_ip, client_port, target_ip, target_port)` 5-tuple stays
/// pinned and we avoid bind+connect per request.
pub async fn forward(
    slot: &mut Option<Stream>,
    addr_src: SocketAddr,
    addr_target: SocketAddr,
    proxy_mark: Option<u32>,
    request: Request<Bytes>,
) -> Result<(UpstreamSession, PingoraResponseHeader)> {
    let stream = match slot.take() {
        Some(s) => s,
        None => connect(addr_src, addr_target, proxy_mark).await?,
    };
    let mut up = UpstreamSession::new(stream);

    let (parts, body_bytes) = request.into_parts();

    let mut req_header = PingoraRequestHeader::build(
        parts.method.as_str(),
        parts.uri.to_string().as_bytes(),
        Some(parts.headers.len() + 2),
    )
    .map_err(|e| anyhow!("build req header: {}", e))?;
    req_header.set_version(http_version_to_pingora(parts.version));
    for (k, v) in parts.headers.iter() {
        let name = k.as_str();
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        req_header
            .append_header(name.to_string(), v.as_bytes())
            .map_err(|e| anyhow!("append upstream header {}: {}", k, e))?;
    }
    let cl = body_bytes.len().to_string();
    req_header
        .insert_header("content-length", cl.as_bytes())
        .map_err(|e| anyhow!("insert upstream content-length: {}", e))?;

    up.write_request_header(Box::new(req_header))
        .await
        .map_err(|e| anyhow!("write upstream req header: {}", e))?;
    if !body_bytes.is_empty() {
        up.write_body(&body_bytes)
            .await
            .map_err(|e| anyhow!("write upstream req body: {}", e))?;
    }
    up.finish_body()
        .await
        .map_err(|e| anyhow!("finish upstream req body: {}", e))?;

    up.read_response()
        .await
        .map_err(|e| anyhow!("read upstream resp: {}", e))?;
    let resp_header = up
        .resp_header()
        .ok_or_else(|| anyhow!("missing upstream response header"))?
        .clone();
    Ok((up, resp_header))
}

/// Open a fresh upstream TCP connection forging
/// `(client_ip, client_port)` as the source (full L4 transparency).
async fn connect(
    addr_src: SocketAddr,
    addr_target: SocketAddr,
    proxy_mark: Option<u32>,
) -> Result<Stream> {
    let sock = TransparentSocket::new_with_mark(addr_src, proxy_mark);
    let tcp = sock.conn(addr_target).await?;
    let l4: pingora_core::protocols::l4::stream::Stream = tcp.into();
    Ok(Box::new(l4))
}

pub(crate) async fn read_body_all(up: &mut UpstreamSession) -> Result<Bytes> {
    let mut acc = bytes::BytesMut::new();
    while let Some(chunk) = up
        .read_body_bytes()
        .await
        .map_err(|e| anyhow!("read upstream body: {}", e))?
    {
        acc.extend_from_slice(&chunk);
    }
    Ok(acc.freeze())
}

/// Splice fast-path: write the response header to inbound, drain any
/// body bytes pingora already pre-read into its codec buffer, then
/// splice the remaining `cl - drained` bytes straight from the
/// upstream fd into the inbound fd via a kernel pipe.
pub(crate) async fn splice_response(
    mut session: ServerSession,
    mut up: UpstreamSession,
    upstream_slot: &mut Option<Stream>,
    upstream_resp_header: &PingoraResponseHeader,
    matched_resp_rules: &[&Rule],
    cl: usize,
) -> Result<Option<Stream>> {
    // Header-only rule application so we still honor non-body
    // mutations (status / replace.headers / patch.headers).
    let mut response = pingora_to_http_response(upstream_resp_header, Bytes::new())?;
    for rule in matched_resp_rules {
        debug!("response matched rule({:?}) [splice path]", rule);
        response = apply_response_action(response, &rule.actions).await?;
    }
    let (parts, _empty): (http::response::Parts, Bytes) = response.into_parts();

    // Build the inbound response header, preserving upstream's
    // Content-Length so framing matches the bytes we splice.
    let mut out = PingoraResponseHeader::build(parts.status.as_u16(), Some(parts.headers.len()))
        .map_err(|e| anyhow!("build response header: {}", e))?;
    for (k, v) in parts.headers.iter() {
        let name = k.as_str();
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out.append_header(name.to_string(), v.as_bytes())
            .map_err(|e| anyhow!("append response header {}: {}", k, e))?;
    }
    let cl_str = cl.to_string();
    out.insert_header("content-length", cl_str.as_bytes())
        .map_err(|e| anyhow!("insert CL: {}", e))?;

    session
        .write_response_header(Box::new(out))
        .await
        .map_err(|e| anyhow!("write response header: {}", e))?;

    // Drain whatever body bytes pingora has already buffered.
    // `read_body_bytes` will return the preread chunk (and may also
    // do one more read for what's already in socket recv buf).
    let mut drained: usize = 0;
    while drained < cl {
        match up
            .read_body_bytes()
            .await
            .map_err(|e| anyhow!("read upstream body chunk: {}", e))?
        {
            Some(chunk) => {
                let len = chunk.len();
                drained += len;
                session
                    .write_response_body(chunk, false)
                    .await
                    .map_err(|e| anyhow!("write drained chunk: {}", e))?;
                // Stop draining once we've seen at least one chunk —
                // we just want to clear whatever pingora pre-read.
                break;
            }
            None => {
                // Body finished entirely within the pre-read window;
                // no splice needed.
                break;
            }
        }
    }

    let remaining = cl.saturating_sub(drained);
    if remaining > 0 {
        splice_via_tcp_streams(&mut up, &mut session, remaining).await?;
    }

    // Tell pingora's BodyWriter that the configured Content-Length
    // bytes are all "written" (via splice). Without this the next
    // step returns PrematureBodyEnd. See pingora patch on
    // BodyWriter::mark_content_length_complete.
    session.mark_response_body_complete();
    session
        .write_response_body(Bytes::new(), true)
        .await
        .map_err(|e| anyhow!("finalize inbound body: {}", e))?;

    up.respect_keepalive();
    if let Some(reused) = up.reuse().await {
        *upstream_slot = Some(reused);
    }
    finish_inbound(session).await
}

/// Reach the inner tokio TcpStreams of both inbound and upstream
/// sessions and splice `n` bytes between them. Both sessions must be
/// H1 over TCP. Uses each TcpStream's own `poll_read_ready` /
/// `poll_write_ready`, so no spawn_blocking and no double-registering
/// the fd with tokio's reactor.
async fn splice_via_tcp_streams(
    up: &mut UpstreamSession,
    session: &mut ServerSession,
    n: usize,
) -> Result<()> {
    use pingora_core::protocols::l4::stream::Stream as L4Stream;

    let in_stream: &mut Stream = session
        .stream_mut()
        .ok_or_else(|| anyhow!("inbound is not H1 — cannot splice"))?;
    let in_l4: &mut L4Stream = in_stream
        .as_any_mut()
        .downcast_mut::<L4Stream>()
        .ok_or_else(|| anyhow!("inbound stream is not l4::Stream"))?;
    let in_tcp: &mut tokio::net::TcpStream = in_l4
        .tcp_stream_mut()
        .ok_or_else(|| anyhow!("inbound is not TCP"))?;

    let up_stream: &mut Stream = up.stream_mut();
    let up_l4: &mut L4Stream = up_stream
        .as_any_mut()
        .downcast_mut::<L4Stream>()
        .ok_or_else(|| anyhow!("upstream stream is not l4::Stream"))?;
    let up_tcp: &mut tokio::net::TcpStream = up_l4
        .tcp_stream_mut()
        .ok_or_else(|| anyhow!("upstream is not TCP"))?;

    splice_n(up_tcp, in_tcp, n)
        .await
        .map_err(|e| anyhow!("splice: {}", e))
}
