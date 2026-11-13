//! Socket options without a typed setter: `TCP_WINDOW_CLAMP` and
//! `customSockopt`, through the transport's run-time setsockopt.

use std::io;

/// A borrowable socket: a file descriptor on Unix, a SOCKET on Windows.
#[cfg(unix)]
pub use std::os::fd::AsFd as AsSock;
#[cfg(windows)]
pub use std::os::windows::io::AsSocket as AsSock;

#[cfg(unix)]
pub fn setsockopt_int(fd: &impl AsSock, level: i32, opt: i32, val: i32) -> io::Result<()> {
    xray_transport::sockopt_sys::set_int(fd.as_fd(), level, opt, val)
}

#[cfg(unix)]
pub fn setsockopt_bytes(fd: &impl AsSock, level: i32, opt: i32, val: &[u8]) -> io::Result<()> {
    xray_transport::sockopt_sys::set_bytes(fd.as_fd(), level, opt, val)
}

#[cfg(unix)]
#[allow(dead_code)]
pub fn getsockopt_int(fd: &impl AsSock, level: i32, opt: i32) -> io::Result<i32> {
    xray_transport::sockopt_sys::get_int(fd.as_fd(), level, opt)
}

#[cfg(not(unix))]
pub fn setsockopt_int(_: &impl AsSock, _: i32, _: i32, _: i32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "not supported on this platform",
    ))
}

#[cfg(not(unix))]
pub fn setsockopt_bytes(_: &impl AsSock, _: i32, _: i32, _: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "not supported on this platform",
    ))
}

pub fn set_tcp_window_clamp(fd: &impl AsSock, clamp: u32) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_WINDOW_CLAMP, clamp as i32)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, clamp);
        Ok(())
    }
}
