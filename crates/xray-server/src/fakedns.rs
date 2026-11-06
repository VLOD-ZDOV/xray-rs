#![forbid(unsafe_code)]

//! Server-side FakeDNS state management and lookups.

use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};
pub use xray_transport::fake_dns::{FakeDnsMulti, FakeDnsPoolConfig};

static GLOBAL_FAKEDNS: OnceLock<RwLock<FakeDnsMulti>> = OnceLock::new();

pub fn init(multi: FakeDnsMulti) {
    let _ = GLOBAL_FAKEDNS.set(RwLock::new(multi));
}

#[allow(dead_code)]
pub fn is_initialized() -> bool {
    GLOBAL_FAKEDNS.get().is_some()
}

pub fn is_ip_in_pool(ip: &IpAddr) -> bool {
    GLOBAL_FAKEDNS
        .get()
        .map(|lock| {
            lock.read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_ip_in_pool(ip)
        })
        .unwrap_or(false)
}

pub fn get_domain_from_fake_ip(ip: &IpAddr) -> Option<String> {
    GLOBAL_FAKEDNS.get().and_then(|lock| {
        lock.write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_domain_from_fake_ip(ip)
    })
}

pub fn get_fake_ip_for_domain(domain: &str, ipv4: bool, ipv6: bool) -> Vec<IpAddr> {
    GLOBAL_FAKEDNS
        .get()
        .map(|lock| {
            lock.write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_fake_ip_for_domain(domain, ipv4, ipv6)
        })
        .unwrap_or_default()
}
