//! Conversion bridges between `pingora_http` (used by the inbound +
//! upstream codecs) and `http` 0.2 types (used by the chaos action
//! engine, deliberately kept stable across the pingora migration).
//!
//! The action engine works in terms of `http::Request<Bytes>` /
//! `http::Response<Bytes>`; codecs work in terms of
//! `pingora_http::{RequestHeader, ResponseHeader}` + raw `Bytes`
//! bodies. These helpers move data across that boundary.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http::{Request, Response};
use pingora_http::{RequestHeader as PingoraRequestHeader, ResponseHeader as PingoraResponseHeader};

pub fn pingora_to_http_request(
    src: &PingoraRequestHeader,
    body: Bytes,
) -> Result<Request<Bytes>> {
    let method = http::Method::from_bytes(src.method.as_str().as_bytes())?;
    let uri: http::Uri = src.uri.to_string().parse()?;
    let version = pingora_version_to_http(src.version);

    let mut builder = Request::builder().method(method).uri(uri).version(version);
    {
        let headers = builder
            .headers_mut()
            .ok_or_else(|| anyhow!("request builder borrow"))?;
        for (k, v) in src.headers.iter() {
            let name = http::header::HeaderName::from_bytes(k.as_str().as_bytes())?;
            let value = http::header::HeaderValue::from_bytes(v.as_bytes())?;
            headers.append(name, value);
        }
    }
    Ok(builder.body(body)?)
}

pub fn pingora_to_http_response(
    src: &PingoraResponseHeader,
    body: Bytes,
) -> Result<Response<Bytes>> {
    let status = http::StatusCode::from_u16(src.status.as_u16())?;
    let version = pingora_version_to_http(src.version);
    let mut builder = Response::builder().status(status).version(version);
    {
        let headers = builder
            .headers_mut()
            .ok_or_else(|| anyhow!("response builder borrow"))?;
        for (k, v) in src.headers.iter() {
            let name = http::header::HeaderName::from_bytes(k.as_str().as_bytes())?;
            let value = http::header::HeaderValue::from_bytes(v.as_bytes())?;
            headers.append(name, value);
        }
    }
    Ok(builder.body(body)?)
}

pub fn pingora_version_to_http(v: pingora_http::Version) -> http::Version {
    match v {
        x if x == pingora_http::Version::HTTP_09 => http::Version::HTTP_09,
        x if x == pingora_http::Version::HTTP_10 => http::Version::HTTP_10,
        x if x == pingora_http::Version::HTTP_11 => http::Version::HTTP_11,
        x if x == pingora_http::Version::HTTP_2 => http::Version::HTTP_2,
        _ => http::Version::HTTP_11,
    }
}

pub fn http_version_to_pingora(v: http::Version) -> pingora_http::Version {
    match v {
        http::Version::HTTP_09 => pingora_http::Version::HTTP_09,
        http::Version::HTTP_10 => pingora_http::Version::HTTP_10,
        http::Version::HTTP_11 => pingora_http::Version::HTTP_11,
        http::Version::HTTP_2 => pingora_http::Version::HTTP_2,
        _ => pingora_http::Version::HTTP_11,
    }
}
