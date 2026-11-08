//! Socket options without a typed setter: `TCP_WINDOW_CLAMP` and
//! `customSockopt`, through the transport's run-time setsockopt.

use std::io;
use std::os::fd::AsFd;

use xray_transport::sockopt_sys;

pub fn setsockopt_int(fd: &impl AsFd, level: i32, opt: i32, val: i32) -> io::Result<()> {
    sockopt_sys::set_int(fd.as_fd(), level, opt, val)
}

pub fn setsockopt_bytes(fd: &impl AsFd, level: i32, opt: i32, val: &[u8]) -> io::Result<()> {
    sockopt_sys::set_bytes(fd.as_fd(), level, opt, val)
}

#[allow(dead_code)]
pub fn getsockopt_int(fd: &impl AsFd, level: i32, opt: i32) -> io::Result<i32> {
    sockopt_sys::get_int(fd.as_fd(), level, opt)
}

pub fn set_tcp_window_clamp(fd: &impl AsFd, clamp: u32) -> io::Result<()> {
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
