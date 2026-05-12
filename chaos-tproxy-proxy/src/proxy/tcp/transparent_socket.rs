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

    /// Create a socket generator that, in addition to IP_TRANSPARENT, also
    /// sets SO_MARK on every outbound connection. The mark is used by the
    /// iptables-redirect deploy path (and equally by the BPF-redirect path)
    /// to recognise and exempt the proxy's own onward traffic so it isn't
    /// recursively captured.
    pub fn new_with_mark(addr: SocketAddr, mark: Option<u32>) -> TransparentSocket {
        Self { addr, mark }
    }

    pub fn bind(addr: SocketAddr) -> io::Result<TcpSocket> {
        let socket = TransparentSocket::set_socket(None)?;
        socket.bind(addr)?;
        Ok(socket)
    }

    pub async fn conn(&self, dist: SocketAddr) -> io::Result<TcpStream> {
        // Fully transparent: preserve the original client's (ip, port).
        // This works because the proxy and the upstream live in
        // separate netns (chaosns vs target netns), so their conntrack
        // tables are independent — using the original 5-tuple on the
        // outbound side does not collide with the inbound 5-tuple that
        // landed in the proxy via TPROXY.
        let socket = TransparentSocket::set_socket(self.mark)?;
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
