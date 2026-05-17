use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::{io, mem};

use tokio::net::{TcpSocket, TcpStream};

/// A socket generator with IP_TRANSPARENT flag.
/// User can Clone this instead of clone a linux socket which may bring mistake.
#[derive(Debug, Clone)]
pub struct TransparentSocket {
    addr: SocketAddr,
    mark: Option<u32>,
}

impl TransparentSocket {
    pub fn new(addr: SocketAddr) -> TransparentSocket {
        Self { addr, mark: None }
    }

    pub fn new_with_mark(addr: SocketAddr, mark: Option<u32>) -> TransparentSocket {
        Self { addr, mark }
    }

    pub fn bind(addr: SocketAddr) -> io::Result<TcpSocket> {
        let socket = TransparentSocket::set_socket(None)?;
        socket.bind(addr)?;
        Ok(socket)
    }

    pub async fn conn(&self, dist: SocketAddr) -> io::Result<TcpStream> {
        let socket = TransparentSocket::set_socket(self.mark)?;
        // Fully transparent: preserve the original client's (ip, port).
        // The upstream's 5-tuple is
        //   (client_ip, client_port, upstream_ip, upstream_port)
        // which is necessarily unique across concurrent clients. The
        // BPF datapath bypasses netfilter/conntrack so this 5-tuple
        // can co-exist with the listener-side child socket (which has
        // a different upstream_port and lives in a separate netns).
        socket.bind(self.addr)?;
        socket.connect(dist).await
    }

    fn set_socket(mark: Option<u32>) -> io::Result<TcpSocket> {
        let socket = TcpSocket::new_v4()?;
        TransparentSocket::set_ip_transparent(&socket)?;
        socket.set_reuseaddr(true)?;
        if let Some(m) = mark {
            TransparentSocket::set_mark(&socket, m)?;
        }
        Ok(socket)
    }

    /// Set IP_TRANSPARENT for use of tproxy.
    /// User may need to get root privilege to use it.
    fn set_ip_transparent(socket: &TcpSocket) -> io::Result<()> {
        unsafe {
            let socket_fd = socket.as_raw_fd();
            let enable: libc::c_int = 1;
            let ret = libc::setsockopt(
                socket_fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            );

            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        };
        Ok(())
    }

    /// Set SO_MARK so the eBPF egress program can recognise and skip
    /// the proxy's onward connections (avoids redirect loop).
    fn set_mark(socket: &TcpSocket, mark: u32) -> io::Result<()> {
        unsafe {
            let socket_fd = socket.as_raw_fd();
            let m: libc::c_uint = mark as libc::c_uint;
            let ret = libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &m as *const _ as *const _,
                mem::size_of_val(&m) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        };
        Ok(())
    }
}
