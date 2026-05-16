//! Non-blocking `splice(2)`-based socket-to-socket body copy,
//! driven by the tokio TcpStream's own `poll_read_ready` /
//! `poll_write_ready`.
//!
//! Stays on the main async task: when splice returns `EAGAIN` on
//! the read side we await `from.readable()`, and likewise on the
//! write side we await `to.writable()`. There's no thread-pool hop
//! and no risk of double-registering the fd with tokio's reactor
//! since we reuse the TcpStream's existing registration.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

use tokio::net::TcpStream;

/// Pipe capacity used as the splice batch size. 1 MiB is the Linux
/// default and the largest splice batch the kernel will accept in one
/// go on this hardware.
const SPLICE_BATCH: usize = 1 << 20;

/// Splice exactly `n` bytes from `from` to `to` via a kernel pipe.
/// Yields back to the runtime on EAGAIN — does not block a worker.
pub async fn splice_n(from: &mut TcpStream, to: &mut TcpStream, n: usize) -> io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    let (pipe_r, pipe_w) = make_pipe()?;
    let pr_fd = pipe_r.as_raw_fd();
    let pw_fd = pipe_w.as_raw_fd();
    let from_fd = from.as_raw_fd();
    let to_fd = to.as_raw_fd();

    let mut remaining = n;
    // Bytes currently sitting in the pipe (read from upstream but
    // not yet handed to inbound). Drain these first before pulling
    // more from upstream.
    let mut in_pipe: usize = 0;

    while remaining > 0 || in_pipe > 0 {
        // Drain pipe → to_fd first; the pipe has finite capacity so
        // we must keep it from filling up before pulling more.
        if in_pipe > 0 {
            match splice_once(pr_fd, to_fd, in_pipe) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "splice pipe→sock returned 0",
                    ));
                }
                Ok(written) => {
                    in_pipe -= written;
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    to.writable().await?;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        // Pipe is empty (or we just drained it). If there's still
        // body left in the upstream, pull more.
        if remaining == 0 {
            break;
        }
        let want = remaining.min(SPLICE_BATCH);
        match splice_once(from_fd, pw_fd, want) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "splice sock→pipe returned 0 (upstream closed)",
                ));
            }
            Ok(got) => {
                in_pipe += got;
                remaining -= got;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                from.readable().await?;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// One `splice(2)` syscall. Non-blocking — returns `WouldBlock` if
/// kernel reports `EAGAIN`.
fn splice_once(from_fd: RawFd, to_fd: RawFd, len: usize) -> io::Result<usize> {
    let n = unsafe {
        libc::splice(
            from_fd,
            ptr::null_mut(),
            to_fd,
            ptr::null_mut(),
            len,
            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MORE,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn make_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let r = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two fresh fds we now own.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((read, write))
}
