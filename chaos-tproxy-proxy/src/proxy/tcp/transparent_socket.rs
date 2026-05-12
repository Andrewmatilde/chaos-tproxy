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
        // When a proxy_mark is set (eBPF-loader / sidecar mode), the
        // proxy is co-located with the upstream service. Reusing the
        // client's source port produces a 5-tuple collision with the
        // listener's accepted child socket, which makes the upstream
        // SYN look like a duplicate. Bind to client IP with port 0
        // so the kernel picks a free ephemeral port for us.
        let bind_addr = if self.mark.is_some() {
            SocketAddr::new(self.addr.ip(), 0)
        } else {
            self.addr
        };
        socket.bind(bind_addr)?;
        socket.connect(dist).await
    }

    fn set_socket(mark: Option<u32>) -> io::Result<TcpSocket> {
        let socket = TcpSocket::new_v4()?;
        TransparentSocket::set_ip_transparent(&socket)?;
        socket.set_reuseaddr(true)?;
        if let Some(m) = mark {
            TransparentSocket::set_mark(&socket, m)?;
            TransparentSocket::set_bind_no_port(&socket)?;
        }
        Ok(socket)
    }

    /// IP_BIND_ADDRESS_NO_PORT (Linux 4.2+, constant 24): defer source-
    /// port allocation until connect() so the kernel picks a port not
    /// in TIME_WAIT for the specific 4-tuple. Without this, transparent
    /// bind hits EADDRINUSE immediately under any non-trivial load.
    fn set_bind_no_port(socket: &TcpSocket) -> io::Result<()> {
        const IP_BIND_ADDRESS_NO_PORT: libc::c_int = 24;
        unsafe {
            let fd = socket.as_raw_fd();
            let enable: libc::c_int = 1;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_IP,
                IP_BIND_ADDRESS_NO_PORT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        };
        Ok(())
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
