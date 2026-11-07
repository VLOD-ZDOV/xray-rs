#![forbid(unsafe_code)]

//! WireGuard client transport and an independently bounded userspace IP interface.
mod client;
mod config;
mod io;
pub mod server;
mod stack;

pub use client::{Client, Error, Options, TcpStream, UdpSession};
pub use config::{Config, PeerConfig};
pub use gotatun::packet::{Ip, Packet};
pub use server::{IncomingTcpStream, IncomingUdpSession, Server, ServerConfig, ServerPeerConfig};
