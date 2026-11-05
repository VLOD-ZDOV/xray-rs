#![forbid(unsafe_code)]

//! WireGuard client transport and an independently bounded userspace IP interface.
mod client;
mod config;
mod io;
mod stack;

pub use client::{Client, Error, Options, TcpStream, UdpSession};
pub use config::{Config, PeerConfig};
