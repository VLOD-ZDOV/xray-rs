//! Minimal isolated setsockopt wrapper for options not available in safe crates:
//! `TCP_WINDOW_CLAMP` and dynamic `customSockopt` (runtime level/opt/value).

use std::io;
use std::os::fd::{AsFd, AsRawFd};

/// Set an integer socket option via `libc::setsockopt`.
#[allow(unsafe_code)]
pub fn setsockopt_int(fd: &impl AsFd, level: i32, opt: i32, val: i32) -> io::Result<()> {
    let raw_fd = fd.as_fd().as_raw_fd();
    let optval = val as libc::c_int;
    // SAFETY: `raw_fd` is borrowed from a valid open socket descriptor `fd`.
    // `optval` is a local stack variable of size `sizeof(libc::c_int)`, matching
    // the passed size `std::mem::size_of::<libc::c_int>() as libc::socklen_t`.
    let ret = unsafe {
        libc::setsockopt(
            raw_fd,
            level as libc::c_int,
            opt as libc::c_int,
            &optval as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Set a string/bytes socket option via `libc::setsockopt`.
#[allow(unsafe_code)]
pub fn setsockopt_bytes(fd: &impl AsFd, level: i32, opt: i32, val: &[u8]) -> io::Result<()> {
    let raw_fd = fd.as_fd().as_raw_fd();
    // SAFETY: `raw_fd` is borrowed from a valid open socket descriptor `fd`.
    // `val.as_ptr()` points to a valid contiguous byte slice of length `val.len()`.
    let ret = unsafe {
        libc::setsockopt(
            raw_fd,
            level as libc::c_int,
            opt as libc::c_int,
            val.as_ptr() as *const libc::c_void,
            val.len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Get an integer socket option via `libc::getsockopt`.
#[allow(unsafe_code)]
#[allow(dead_code)]
pub fn getsockopt_int(fd: &impl AsFd, level: i32, opt: i32) -> io::Result<i32> {
    let raw_fd = fd.as_fd().as_raw_fd();
    let mut optval: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `raw_fd` is borrowed from a valid open socket descriptor `fd`.
    // `optval` is a local stack variable of size `sizeof(libc::c_int)`, matching
    // `len` initialized to `std::mem::size_of::<libc::c_int>() as libc::socklen_t`.
    let ret = unsafe {
        libc::getsockopt(
            raw_fd,
            level as libc::c_int,
            opt as libc::c_int,
            &mut optval as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(optval)
    }
}

/// Set Linux TCP_WINDOW_CLAMP on the given socket descriptor.
#[allow(unsafe_code)]
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
