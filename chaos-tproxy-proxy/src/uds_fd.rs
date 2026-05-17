use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::{mem, ptr};

/// Send a single file descriptor over a Unix Domain Socket at `path`
/// via SCM_RIGHTS. The receiver (the eBPF loader) reads this with
/// recvmsg(MSG_CMSG_CLOEXEC) on its already-connected socket.
///
/// This is a one-shot helper. We open a fresh connection to `path`,
/// send a single byte payload + the fd in the ancillary data, then
/// close. The Go loader's accept goroutine receives this on the same
/// listener that delivered the JSON config — see Spawner.pushConfig.
pub fn send_fd(path: &Path, fd: RawFd) -> io::Result<()> {
    let socket_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if socket_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_bytes = path.to_string_lossy();
    let path_bytes = path_bytes.as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        unsafe { libc::close(socket_fd) };
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "uds path too long",
        ));
    }
    for (i, b) in path_bytes.iter().enumerate() {
        addr.sun_path[i] = *b as libc::c_char;
    }

    let addr_len = (mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;
    let ret = unsafe {
        libc::connect(
            socket_fd,
            &addr as *const _ as *const libc::sockaddr,
            addr_len,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(socket_fd) };
        return Err(e);
    }

    let mut payload: [u8; 1] = [0];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut cmsg_buf: Vec<u8> = vec![0; cmsg_space];

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = ptr::null_mut();
    msg.msg_namelen = 0;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
        ptr::write(data, fd);
    }

    let n = unsafe { libc::sendmsg(socket_fd, &msg, 0) };
    let err = if n < 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };

    unsafe { libc::close(socket_fd) };
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
