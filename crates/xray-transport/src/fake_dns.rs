#![forbid(unsafe_code)]

//! FakeDNS pool and IP mapper.
//!
//! Maps domain names to synthetic IPv4/IPv6 addresses from configured pools,
//! and resolves fake IPs back to their original domains during sniffing.
//! Matches Xray-core's `app/dns/fakedns` behavior, pool defaults, and error texts.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsPoolConfig {
    pub ip_pool: String,
    pub pool_size: usize,
}

impl Default for FakeDnsPoolConfig {
    fn default() -> Self {
        Self {
            ip_pool: "198.18.0.0/15".to_string(),
            pool_size: 65535,
        }
    }
}

pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let s = s.trim();
    let (ip_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| format!("Unable to parse CIDR for Fake DNS IP assignment: {s}"))?;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| format!("Unable to parse CIDR for Fake DNS IP assignment: {s}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| format!("Unable to parse CIDR for Fake DNS IP assignment: {s}"))?;
    match ip {
        IpAddr::V4(_) if prefix > 32 => Err(format!(
            "Unable to parse CIDR for Fake DNS IP assignment: {s}"
        )),
        IpAddr::V6(_) if prefix > 128 => Err(format!(
            "Unable to parse CIDR for Fake DNS IP assignment: {s}"
        )),
        _ => Ok((ip, prefix)),
    }
}

fn normalize_domain(domain: &str) -> String {
    let mut d = domain.trim().to_ascii_lowercase();
    if d.ends_with('.') {
        d.pop();
    }
    d
}

#[derive(Debug)]
struct FakeDnsLru {
    capacity: usize,
    counter: u64,
    order: BTreeSet<(u64, String)>,
    domain_to_entry: HashMap<String, (IpAddr, u64)>,
    ip_to_domain: HashMap<IpAddr, String>,
}

impl FakeDnsLru {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            counter: 0,
            order: BTreeSet::new(),
            domain_to_entry: HashMap::with_capacity(capacity),
            ip_to_domain: HashMap::with_capacity(capacity),
        }
    }

    fn get_by_domain(&mut self, domain: &str) -> Option<IpAddr> {
        if let Some((ip, old_counter)) = self.domain_to_entry.get_mut(domain) {
            let ip = *ip;
            self.order.remove(&(*old_counter, domain.to_string()));
            self.counter += 1;
            *old_counter = self.counter;
            self.order.insert((self.counter, domain.to_string()));
            Some(ip)
        } else {
            None
        }
    }

    fn get_by_ip(&mut self, ip: &IpAddr) -> Option<String> {
        if let Some(domain) = self.ip_to_domain.get(ip) {
            let domain = domain.clone();
            if let Some((_, old_counter)) = self.domain_to_entry.get_mut(&domain) {
                self.order.remove(&(*old_counter, domain.clone()));
                self.counter += 1;
                *old_counter = self.counter;
                self.order.insert((self.counter, domain.clone()));
            }
            Some(domain)
        } else {
            None
        }
    }

    fn contains_ip(&self, ip: &IpAddr) -> bool {
        self.ip_to_domain.contains_key(ip)
    }

    fn insert(&mut self, domain: String, ip: IpAddr) {
        if let Some((old_ip, old_counter)) = self.domain_to_entry.remove(&domain) {
            self.order.remove(&(old_counter, domain.clone()));
            self.ip_to_domain.remove(&old_ip);
        } else if self.domain_to_entry.len() >= self.capacity {
            if let Some(&(old_counter, ref old_domain)) = self.order.iter().next() {
                let old_domain = old_domain.clone();
                self.order.remove(&(old_counter, old_domain.clone()));
                if let Some((old_ip, _)) = self.domain_to_entry.remove(&old_domain) {
                    self.ip_to_domain.remove(&old_ip);
                }
            }
        }
        self.counter += 1;
        self.order.insert((self.counter, domain.clone()));
        self.domain_to_entry
            .insert(domain.clone(), (ip, self.counter));
        self.ip_to_domain.insert(ip, domain);
    }
}

#[derive(Debug)]
pub struct FakeDnsIpv4Pool {
    network_base: u32,
    mask: u32,
    first_offset: u64,
    allocation_span: u64,
    next_offset: u64,
    lru: FakeDnsLru,
}

impl FakeDnsIpv4Pool {
    pub fn new(net: Ipv4Addr, prefix: u8, pool_size: usize) -> Result<Self, String> {
        if prefix > 32 {
            return Err("invalid IPv4 prefix".to_string());
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network_base = u32::from(net) & mask;
        let address_count = 1u64 << (32 - prefix);
        let first_offset = if address_count > 2 { 1 } else { 0 };
        let allocation_span = if address_count > 2 {
            address_count - 2
        } else {
            address_count
        };
        if pool_size == 0 || (pool_size as u64) >= address_count {
            return Err("LRU size is bigger than subnet size".to_string());
        }
        let next_offset = rand::random::<u64>() % allocation_span.max(1);
        Ok(Self {
            network_base,
            mask,
            first_offset,
            allocation_span,
            next_offset,
            lru: FakeDnsLru::new(pool_size),
        })
    }

    pub fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask) == self.network_base
    }

    pub fn allocate(&mut self, domain: &str) -> IpAddr {
        let domain = normalize_domain(domain);
        if let Some(ip) = self.lru.get_by_domain(&domain) {
            return ip;
        }
        for _ in 0..self.allocation_span {
            let offset = self.first_offset + (self.next_offset % self.allocation_span);
            self.next_offset = (self.next_offset + 1) % self.allocation_span;
            let cand = Ipv4Addr::from(self.network_base + offset as u32);
            let cand_ip = IpAddr::V4(cand);
            if !self.lru.contains_ip(&cand_ip) {
                self.lru.insert(domain, cand_ip);
                return cand_ip;
            }
        }
        let offset = self.first_offset + (self.next_offset % self.allocation_span);
        self.next_offset = (self.next_offset + 1) % self.allocation_span;
        let cand = Ipv4Addr::from(self.network_base + offset as u32);
        let cand_ip = IpAddr::V4(cand);
        self.lru.insert(domain, cand_ip);
        cand_ip
    }

    pub fn get_domain(&mut self, ip: Ipv4Addr) -> Option<String> {
        if !self.contains_ip(ip) {
            return None;
        }
        self.lru.get_by_ip(&IpAddr::V4(ip))
    }
}

#[derive(Debug)]
pub struct FakeDnsIpv6Pool {
    network_base: u128,
    mask: u128,
    allocation_span: u64,
    next_offset: u64,
    lru: FakeDnsLru,
}

impl FakeDnsIpv6Pool {
    pub fn new(net: Ipv6Addr, prefix: u8, pool_size: usize) -> Result<Self, String> {
        if prefix > 128 {
            return Err("invalid IPv6 prefix".to_string());
        }
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        let network_base = u128::from(net) & mask;
        let rooms = 128 - prefix;
        if rooms < 64 && (pool_size == 0 || (pool_size as u64) >= (1u64 << rooms)) {
            return Err("LRU size is bigger than subnet size".to_string());
        }
        let allocation_span = if rooms >= 64 {
            u64::MAX
        } else {
            (1u64 << rooms).saturating_sub(1)
        };
        let next_offset = rand::random::<u64>() % allocation_span.max(1);
        Ok(Self {
            network_base,
            mask,
            allocation_span,
            next_offset,
            lru: FakeDnsLru::new(pool_size),
        })
    }

    pub fn contains_ip(&self, ip: Ipv6Addr) -> bool {
        (u128::from(ip) & self.mask) == self.network_base
    }

    pub fn allocate(&mut self, domain: &str) -> IpAddr {
        let domain = normalize_domain(domain);
        if let Some(ip) = self.lru.get_by_domain(&domain) {
            return ip;
        }
        let search_limit = 1024u64.min(self.allocation_span);
        for _ in 0..search_limit {
            let offset = self.next_offset % self.allocation_span;
            self.next_offset = self.next_offset.wrapping_add(1);
            let cand = Ipv6Addr::from(self.network_base + offset as u128 + 1);
            let cand_ip = IpAddr::V6(cand);
            if !self.lru.contains_ip(&cand_ip) {
                self.lru.insert(domain, cand_ip);
                return cand_ip;
            }
        }
        let offset = self.next_offset % self.allocation_span;
        self.next_offset = self.next_offset.wrapping_add(1);
        let cand = Ipv6Addr::from(self.network_base + offset as u128 + 1);
        let cand_ip = IpAddr::V6(cand);
        self.lru.insert(domain, cand_ip);
        cand_ip
    }

    pub fn get_domain(&mut self, ip: Ipv6Addr) -> Option<String> {
        if !self.contains_ip(ip) {
            return None;
        }
        self.lru.get_by_ip(&IpAddr::V6(ip))
    }
}

#[derive(Debug)]
pub enum FakeDnsPoolEnum {
    V4(FakeDnsIpv4Pool),
    V6(FakeDnsIpv6Pool),
}

impl FakeDnsPoolEnum {
    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(p), IpAddr::V4(v4)) => p.contains_ip(*v4),
            (Self::V6(p), IpAddr::V6(v6)) => p.contains_ip(*v6),
            _ => false,
        }
    }

    pub fn get_domain(&mut self, ip: &IpAddr) -> Option<String> {
        match (self, ip) {
            (Self::V4(p), IpAddr::V4(v4)) => p.get_domain(*v4),
            (Self::V6(p), IpAddr::V6(v6)) => p.get_domain(*v6),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct FakeDnsMulti {
    pools: Vec<FakeDnsPoolEnum>,
}

impl FakeDnsMulti {
    pub fn from_configs(configs: &[FakeDnsPoolConfig]) -> Result<Self, String> {
        if configs.is_empty() {
            return Err("no valid FakeDNS config".to_string());
        }
        let mut pools = Vec::new();
        for cfg in configs {
            let (ip, prefix) = parse_cidr(&cfg.ip_pool)?;
            match ip {
                IpAddr::V4(v4) => {
                    pools.push(FakeDnsPoolEnum::V4(FakeDnsIpv4Pool::new(
                        v4,
                        prefix,
                        cfg.pool_size,
                    )?));
                }
                IpAddr::V6(v6) => {
                    pools.push(FakeDnsPoolEnum::V6(FakeDnsIpv6Pool::new(
                        v6,
                        prefix,
                        cfg.pool_size,
                    )?));
                }
            }
        }
        Ok(Self { pools })
    }

    pub fn is_ip_in_pool(&self, ip: &IpAddr) -> bool {
        self.pools.iter().any(|p| p.contains_ip(ip))
    }

    pub fn get_domain_from_fake_ip(&mut self, ip: &IpAddr) -> Option<String> {
        for p in &mut self.pools {
            if let Some(domain) = p.get_domain(ip) {
                return Some(domain);
            }
        }
        None
    }

    pub fn get_fake_ip_for_domain(&mut self, domain: &str, ipv4: bool, ipv6: bool) -> Vec<IpAddr> {
        let mut res = Vec::new();
        for p in &mut self.pools {
            match p {
                FakeDnsPoolEnum::V4(v4) if ipv4 => res.push(v4.allocate(domain)),
                FakeDnsPoolEnum::V6(v6) if ipv6 => res.push(v6.allocate(domain)),
                _ => {}
            }
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_allocates_fake_ips() {
        let config = FakeDnsPoolConfig {
            ip_pool: "198.18.0.0/15".to_string(),
            pool_size: 10,
        };
        let mut multi = FakeDnsMulti::from_configs(&[config]).unwrap();

        let domain1 = "example.com";
        let ips1 = multi.get_fake_ip_for_domain(domain1, true, false);
        assert_eq!(ips1.len(), 1);
        let fake_ip1 = ips1[0];
        assert!(multi.is_ip_in_pool(&fake_ip1));

        // Re-query returns same IP
        let ips2 = multi.get_fake_ip_for_domain(domain1, true, false);
        assert_eq!(ips2, vec![fake_ip1]);

        // Reverse lookup
        let reversed = multi.get_domain_from_fake_ip(&fake_ip1);
        assert_eq!(reversed, Some("example.com".to_string()));

        // Outside IP returns false / None
        let outside: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!multi.is_ip_in_pool(&outside));
        assert_eq!(multi.get_domain_from_fake_ip(&outside), None);
    }

    #[test]
    fn lru_eviction_when_pool_is_full() {
        let config = FakeDnsPoolConfig {
            ip_pool: "198.18.0.0/28".to_string(), // 16 addresses, span 14
            pool_size: 2,
        };
        let mut multi = FakeDnsMulti::from_configs(&[config]).unwrap();

        let ip_a = multi.get_fake_ip_for_domain("a.com", true, false)[0];
        let ip_b = multi.get_fake_ip_for_domain("b.com", true, false)[0];
        assert_ne!(ip_a, ip_b);

        // a.com was least recently used, adding c.com should evict a.com
        let _ip_c = multi.get_fake_ip_for_domain("c.com", true, false)[0];
        assert_eq!(multi.get_domain_from_fake_ip(&ip_a), None);
        assert_eq!(
            multi.get_domain_from_fake_ip(&ip_b),
            Some("b.com".to_string())
        );
    }

    #[test]
    fn rejects_oversized_pool_size() {
        let config = FakeDnsPoolConfig {
            ip_pool: "198.18.0.0/30".to_string(), // 4 addresses, span 2
            pool_size: 4,                         // >= address count
        };
        let err = FakeDnsMulti::from_configs(&[config]).unwrap_err();
        assert_eq!(err, "LRU size is bigger than subnet size");
    }

    #[test]
    fn rejects_invalid_cidr() {
        let config = FakeDnsPoolConfig {
            ip_pool: "not-a-cidr".to_string(),
            pool_size: 10,
        };
        let err = FakeDnsMulti::from_configs(&[config]).unwrap_err();
        assert!(err.contains("Unable to parse CIDR for Fake DNS IP assignment"));
    }
}
