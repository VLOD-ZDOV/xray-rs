//! `setsockopt`/`getsockopt` with a level and option number read at run time,
//! as `customSockopt` needs, without `unsafe` here: nix's typed socket options
//! make the system call. nix fixes the option number at compile time, so each
//! number up to 255 gets its own type; the level and value are read at run time.

use std::cell::Cell;
use std::io;
use std::os::fd::BorrowedFd;

use libc::{c_int, c_void, socklen_t};
use nix::sys::socket::sockopt::{GetStruct, Set};
use nix::sys::socket::{getsockopt, setsockopt};

thread_local! {
    static LEVEL: Cell<c_int> = const { Cell::new(0) };
}

fn level() -> c_int {
    LEVEL.with(Cell::get)
}

/// The bytes as they are; an empty value passes a null pointer, as Go's
/// `SetsockoptString` does.
pub struct Bytes<'a>(&'a [u8]);

impl<'a> Set<'a, Vec<u8>> for Bytes<'a> {
    fn new(value: &'a Vec<u8>) -> Self {
        Bytes(value)
    }

    fn ffi_ptr(&self) -> *const c_void {
        if self.0.is_empty() {
            std::ptr::null()
        } else {
            self.0.as_ptr().cast()
        }
    }

    fn ffi_len(&self) -> socklen_t {
        self.0.len() as socklen_t
    }
}

macro_rules! options {
    ($($name:ident $number:literal),* $(,)?) => {
        $(
            #[derive(Clone, Copy)]
            struct $name;
            impl $name {
                const NUMBER: c_int = $number;
            }
            nix::setsockopt_impl!($name, level(), $name::NUMBER, Vec<u8>, Bytes<'_>);
            nix::getsockopt_impl!($name, level(), $name::NUMBER, c_int, GetStruct<c_int>);
        )*

        fn set(fd: BorrowedFd<'_>, opt: c_int, value: &Vec<u8>) -> nix::Result<()> {
            match opt {
                $($number => setsockopt(&fd, $name, value),)*
                _ => Err(nix::errno::Errno::ENOPROTOOPT),
            }
        }

        fn get(fd: BorrowedFd<'_>, opt: c_int) -> nix::Result<c_int> {
            match opt {
                $($number => getsockopt(&fd, $name),)*
                _ => Err(nix::errno::Errno::ENOPROTOOPT),
            }
        }
    };
}

options!(
    O0 0, O1 1, O2 2, O3 3, O4 4, O5 5, O6 6, O7 7,
    O8 8, O9 9, O10 10, O11 11, O12 12, O13 13, O14 14, O15 15,
    O16 16, O17 17, O18 18, O19 19, O20 20, O21 21, O22 22, O23 23,
    O24 24, O25 25, O26 26, O27 27, O28 28, O29 29, O30 30, O31 31,
    O32 32, O33 33, O34 34, O35 35, O36 36, O37 37, O38 38, O39 39,
    O40 40, O41 41, O42 42, O43 43, O44 44, O45 45, O46 46, O47 47,
    O48 48, O49 49, O50 50, O51 51, O52 52, O53 53, O54 54, O55 55,
    O56 56, O57 57, O58 58, O59 59, O60 60, O61 61, O62 62, O63 63,
    O64 64, O65 65, O66 66, O67 67, O68 68, O69 69, O70 70, O71 71,
    O72 72, O73 73, O74 74, O75 75, O76 76, O77 77, O78 78, O79 79,
    O80 80, O81 81, O82 82, O83 83, O84 84, O85 85, O86 86, O87 87,
    O88 88, O89 89, O90 90, O91 91, O92 92, O93 93, O94 94, O95 95,
    O96 96, O97 97, O98 98, O99 99, O100 100, O101 101, O102 102, O103 103,
    O104 104, O105 105, O106 106, O107 107, O108 108, O109 109, O110 110, O111 111,
    O112 112, O113 113, O114 114, O115 115, O116 116, O117 117, O118 118, O119 119,
    O120 120, O121 121, O122 122, O123 123, O124 124, O125 125, O126 126, O127 127,
    O128 128, O129 129, O130 130, O131 131, O132 132, O133 133, O134 134, O135 135,
    O136 136, O137 137, O138 138, O139 139, O140 140, O141 141, O142 142, O143 143,
    O144 144, O145 145, O146 146, O147 147, O148 148, O149 149, O150 150, O151 151,
    O152 152, O153 153, O154 154, O155 155, O156 156, O157 157, O158 158, O159 159,
    O160 160, O161 161, O162 162, O163 163, O164 164, O165 165, O166 166, O167 167,
    O168 168, O169 169, O170 170, O171 171, O172 172, O173 173, O174 174, O175 175,
    O176 176, O177 177, O178 178, O179 179, O180 180, O181 181, O182 182, O183 183,
    O184 184, O185 185, O186 186, O187 187, O188 188, O189 189, O190 190, O191 191,
    O192 192, O193 193, O194 194, O195 195, O196 196, O197 197, O198 198, O199 199,
    O200 200, O201 201, O202 202, O203 203, O204 204, O205 205, O206 206, O207 207,
    O208 208, O209 209, O210 210, O211 211, O212 212, O213 213, O214 214, O215 215,
    O216 216, O217 217, O218 218, O219 219, O220 220, O221 221, O222 222, O223 223,
    O224 224, O225 225, O226 226, O227 227, O228 228, O229 229, O230 230, O231 231,
    O232 232, O233 233, O234 234, O235 235, O236 236, O237 237, O238 238, O239 239,
    O240 240, O241 241, O242 242, O243 243, O244 244, O245 245, O246 246, O247 247,
    O248 248, O249 249, O250 250, O251 251, O252 252, O253 253, O254 254, O255 255,
);

fn with_level<T>(level: c_int, call: impl FnOnce() -> nix::Result<T>) -> io::Result<T> {
    LEVEL.with(|cell| cell.set(level));
    call().map_err(io::Error::from)
}

/// Sets an `int` option. Option numbers past 255 fail with `ENOPROTOOPT`.
pub fn set_int(fd: BorrowedFd<'_>, level: c_int, opt: c_int, value: c_int) -> io::Result<()> {
    let value = value.to_ne_bytes().to_vec();
    with_level(level, || set(fd, opt, &value))
}

/// Sets an option to `value`'s bytes, without a terminator.
pub fn set_bytes(fd: BorrowedFd<'_>, level: c_int, opt: c_int, value: &[u8]) -> io::Result<()> {
    let value = value.to_vec();
    with_level(level, || set(fd, opt, &value))
}

/// Reads an `int` option.
pub fn get_int(fd: BorrowedFd<'_>, level: c_int, opt: c_int) -> io::Result<c_int> {
    with_level(level, || get(fd, opt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn options_round_trip_through_a_run_time_level_and_number() {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_fd();
        set_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1).unwrap();
        assert_eq!(
            get_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY).unwrap(),
            1
        );
        set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1).unwrap();
        assert_eq!(
            get_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(),
            1
        );
        set_bytes(fd, libc::IPPROTO_TCP, libc::TCP_CONGESTION, b"reno").unwrap();
        assert_eq!(
            set_int(fd, libc::SOL_SOCKET, 300, 1)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOPROTOOPT)
        );
    }
}
