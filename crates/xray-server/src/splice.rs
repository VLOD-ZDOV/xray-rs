//! Zero-copy stream relay using Linux `splice(2)`.

#![forbid(unsafe_code)]
#![allow(dead_code)]

#[cfg(target_os = "linux")]
use std::future::poll_fn;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::task::{ready, Poll};

#[cfg(target_os = "linux")]
use nix::fcntl::{OFlag, SpliceFFlags};
#[cfg(target_os = "linux")]
use tokio::io::Interest;
#[cfg(target_os = "linux")]
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
const PIPE_CAPACITY: usize = 1024 * 1024;

#[cfg(target_os = "linux")]
struct Pipe {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl Pipe {
    fn new() -> io::Result<Self> {
        let (read_fd, write_fd) = nix::unistd::pipe2(OFlag::O_NONBLOCK | OFlag::O_CLOEXEC)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        // Set pipe buffer capacity to 1 MB for high throughput
        let _ = nix::fcntl::fcntl(
            &write_fd,
            nix::fcntl::FcntlArg::F_SETPIPE_SZ(PIPE_CAPACITY as i32),
        );
        Ok(Self { read_fd, write_fd })
    }
}

#[cfg(target_os = "linux")]
fn is_refused(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EPERM | libc::EOPNOTSUPP)
    )
}

#[cfg(target_os = "linux")]
pub async fn splice_half(
    from: &TcpStream,
    to: &TcpStream,
    activity: &crate::vless::Activity,
    count: impl Fn(usize),
) -> io::Result<()> {
    let pipe = Pipe::new()?;
    let mut in_pipe = 0;

    loop {
        let step = poll_fn(|cx| {
            loop {
                if in_pipe == 0 {
                    ready!(from.poll_read_ready(cx))?;
                    let fill = || {
                        nix::fcntl::splice(
                            from.as_fd(),
                            None,
                            pipe.write_fd.as_fd(),
                            None,
                            PIPE_CAPACITY,
                            SpliceFFlags::SPLICE_F_NONBLOCK | SpliceFFlags::SPLICE_F_MOVE,
                        )
                        .map_err(|e| io::Error::from_raw_os_error(e as i32))
                    };
                    match from.try_io(Interest::READABLE, fill) {
                        Ok(0) => return Poll::Ready(Ok(None)), // EOF
                        Ok(n) => in_pipe = n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) if is_refused(&e) => return Poll::Ready(Err(e)),
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }

                ready!(to.poll_write_ready(cx))?;
                let drain = || {
                    nix::fcntl::splice(
                        pipe.read_fd.as_fd(),
                        None,
                        to.as_fd(),
                        None,
                        in_pipe,
                        SpliceFFlags::SPLICE_F_NONBLOCK | SpliceFFlags::SPLICE_F_MOVE,
                    )
                    .map_err(|e| io::Error::from_raw_os_error(e as i32))
                };
                match to.try_io(Interest::WRITABLE, drain) {
                    Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Ok(n) => {
                        in_pipe -= n;
                        return Poll::Ready(Ok(Some(n)));
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) if is_refused(&e) => return Poll::Ready(Err(e)),
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        });

        match step.await? {
            Some(n) => {
                count(n);
                activity.touch();
            }
            None => {
                // Outbound EOF, flush remaining
                break;
            }
        }
    }
    Ok(())
}
