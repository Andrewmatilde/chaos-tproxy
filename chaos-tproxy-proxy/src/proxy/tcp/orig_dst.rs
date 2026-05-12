//! Recover the original destination of an accepted TCP connection.
//!
//! When the connection arrives via `iptables -t nat REDIRECT --to-ports N`,
//! the kernel has rewritten the destination port to N. `local_addr()` on
//! the accepted socket reports the rewritten address, not what the client
//! tried to connect to. `getsockopt(SOL_IP, SO_ORIGINAL_DST)` is the
//! conntrack-backed way to recover the pre-NAT destination.
//!
//! For non-NAT (TPROXY) deployments `local_addr()` is already correct;
//! `original_dst` falls back to it when SO_ORIGINAL_DST is unavailable
//! (errno ENOPROTOOPT, or no conntrack entry).

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;

use tokio::net::TcpStream;

const SO_ORIGINAL_DST: libc::c_int = 80;

/// Best-effort: try SO_ORIGINAL_DST first, fall back to `local_addr()`.
pub fn original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    if let Ok(addr) = orig_dst_v4(stream) {
        return Ok(addr);
    }
    stream.local_addr()
}

fn orig_dst_v4(stream: &TcpStream) -> io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    // sockaddr_in is in network byte order on the wire-facing fields.
    let port = u16::from_be(addr.sin_port);
    let octets = addr.sin_addr.s_addr.to_ne_bytes();
    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}
