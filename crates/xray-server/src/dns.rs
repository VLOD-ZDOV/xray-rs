//! Built-in DNS resolver integration for xray-server.
//!
//! Provides static host mapping, configured upstream name servers,
//! query strategy filtering (IPv4/IPv6), and system resolver fallback.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use xray_config::{
    DnsConfig, DnsQueryStrategy as ConfigQueryStrategy, DnsServerConfig, DnsServerEndpoint,
};
use xray_transport::{
    ConfiguredDnsResolver, DnsQueryStrategy as TransportQueryStrategy, DnsResolver, NameServer,
    NameServerPolicy, NameServerTransport, SystemDnsResolver,
};

static GLOBAL_RESOLVER: OnceLock<Arc<dyn DnsResolver>> = OnceLock::new();

struct ServerEntry {
    is_fakedns: bool,
    domains: xray_routing::DomainMatcherSet,
    skip_fallback: bool,
}

static SERVER_ENTRIES: OnceLock<Vec<ServerEntry>> = OnceLock::new();
static QUERY_STRATEGY: OnceLock<ConfigQueryStrategy> = OnceLock::new();
static STATIC_HOSTS: OnceLock<xray_config::DomainHostIndex<xray_routing::DnsHostTarget>> =
    OnceLock::new();

fn map_transport(t: xray_config::DnsServerTransport) -> NameServerTransport {
    match t {
        xray_config::DnsServerTransport::Classic => NameServerTransport::Classic,
        xray_config::DnsServerTransport::TcpRouted => NameServerTransport::TcpRouted,
        xray_config::DnsServerTransport::TcpLocal => NameServerTransport::TcpLocal,
        xray_config::DnsServerTransport::TlsRouted => NameServerTransport::TlsRouted,
        xray_config::DnsServerTransport::HttpsRouted => NameServerTransport::HttpsRouted,
        xray_config::DnsServerTransport::HttpsLocal => NameServerTransport::HttpsLocal,
        xray_config::DnsServerTransport::QuicLocal => NameServerTransport::QuicLocal,
    }
}

pub fn init(config: Option<DnsConfig>) {
    let (resolver, entries, query_strategy, static_hosts) = if let Some(dns) = config {
        let mut entries = Vec::new();
        let mut name_servers: Vec<NameServerPolicy> = Vec::new();

        for s in dns.servers {
            let endpoint = s.endpoint();
            let is_fakedns = match &endpoint {
                DnsServerEndpoint::Domain { domain, .. } => domain.eq_ignore_ascii_case("fakedns"),
                _ => false,
            };

            let (domains, skip_fallback) = match &s {
                DnsServerConfig::Policy(p) => (p.domains.clone(), p.skip_fallback),
                _ => (xray_routing::DomainMatcherSet::default(), false),
            };

            entries.push(ServerEntry {
                is_fakedns,
                domains: domains.clone(),
                skip_fallback,
            });

            if !is_fakedns {
                let server = match endpoint {
                    DnsServerEndpoint::Ip(addr) => NameServer::Socket(addr),
                    DnsServerEndpoint::Domain { domain, port } => {
                        NameServer::Domain { domain, port }
                    }
                };
                let transport = map_transport(s.transport());
                let mut policy = NameServerPolicy::new(server);
                policy.transport = transport;
                if let DnsServerConfig::Policy(p) = s {
                    policy.tag = if p.tag.is_empty() { None } else { Some(p.tag) };
                    policy.https_path = p.https_path;
                    policy.domains = domains;
                    policy.expected_ips = p.expected_ips;
                    policy.unexpected_ips = p.unexpected_ips;
                    policy.skip_fallback = p.skip_fallback;
                    policy.final_query = p.final_query;
                    if p.timeout_ms > 0 {
                        policy.timeout = Some(Duration::from_millis(p.timeout_ms));
                    }
                }
                name_servers.push(policy);
            }
        }

        let query_strategy = match dns.query_strategy {
            ConfigQueryStrategy::UseIp => TransportQueryStrategy::UseIp,
            ConfigQueryStrategy::UseIpv4 => TransportQueryStrategy::UseIpv4,
            ConfigQueryStrategy::UseIpv6 => TransportQueryStrategy::UseIpv6,
        };

        let configured =
            ConfiguredDnsResolver::new(dns.hosts.clone(), Vec::new(), Arc::new(SystemDnsResolver))
                .with_name_server_policies(name_servers)
                .with_query_strategy(query_strategy)
                .with_name_server_fallback_policy(
                    dns.disable_fallback,
                    dns.disable_fallback_if_match,
                );

        (
            Arc::new(configured) as Arc<dyn DnsResolver>,
            entries,
            dns.query_strategy,
            Some(dns.hosts),
        )
    } else {
        (
            Arc::new(SystemDnsResolver) as Arc<dyn DnsResolver>,
            Vec::new(),
            ConfigQueryStrategy::UseIp,
            None,
        )
    };

    let _ = GLOBAL_RESOLVER.set(resolver);
    let _ = SERVER_ENTRIES.set(entries);
    let _ = QUERY_STRATEGY.set(query_strategy);
    if let Some(hosts) = static_hosts {
        let _ = STATIC_HOSTS.set(hosts);
    }
}

pub fn resolver() -> &'static Arc<dyn DnsResolver> {
    GLOBAL_RESOLVER.get_or_init(|| Arc::new(SystemDnsResolver))
}

pub async fn resolve_dns_query(domain: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
    if let Some(hosts) = STATIC_HOSTS.get() {
        if hosts.lookup(&normalized).is_some() {
            return resolve_via_resolver(domain, port).await;
        }
    }

    if let Some(entries) = SERVER_ENTRIES.get() {
        if !entries.is_empty() {
            let mut matched_entry: Option<&ServerEntry> = None;
            for entry in entries.iter().filter(|e| !e.domains.is_empty()) {
                if entry.domains.matches(&normalized) {
                    matched_entry = Some(entry);
                    break;
                }
            }
            if matched_entry.is_none() {
                for entry in entries.iter().filter(|e| e.domains.is_empty()) {
                    if !entry.skip_fallback {
                        matched_entry = Some(entry);
                        break;
                    }
                }
            }

            if let Some(entry) = matched_entry {
                if entry.is_fakedns {
                    let strategy = QUERY_STRATEGY
                        .get()
                        .copied()
                        .unwrap_or(ConfigQueryStrategy::UseIp);
                    let (ipv4, ipv6) = match strategy {
                        ConfigQueryStrategy::UseIp => (true, true),
                        ConfigQueryStrategy::UseIpv4 => (true, false),
                        ConfigQueryStrategy::UseIpv6 => (false, true),
                    };
                    let ips = crate::fakedns::get_fake_ip_for_domain(domain, ipv4, ipv6);
                    if !ips.is_empty() {
                        let mut addrs: Vec<SocketAddr> = ips
                            .into_iter()
                            .map(|ip| SocketAddr::new(ip, port))
                            .collect();
                        addrs.sort_by_key(SocketAddr::is_ipv6);
                        return Ok(addrs);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "no address for host",
                        ));
                    }
                }
            }
        }
    }

    resolve_via_resolver(domain, port).await
}

pub async fn resolve_all(domain: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    resolve_via_resolver(domain, port).await
}

async fn resolve_via_resolver(domain: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let r = resolver();
    match r.resolve_all(domain, port).await {
        Ok(lookup) => {
            let mut addrs: Vec<SocketAddr> = lookup.socket_addrs().to_vec();
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no address for host",
                ));
            }
            addrs.sort_by_key(SocketAddr::is_ipv6);
            Ok(addrs)
        }
        Err(e) => Err(io::Error::other(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use xray_config::{DomainHostIndex, DomainMatcher};
    use xray_routing::DnsHostTarget;

    #[tokio::test]
    async fn test_dns_hosts_resolution() {
        let mut hosts = DomainHostIndex::new();
        hosts.insert(
            DomainMatcher::Full("custom.local".to_string()),
            DnsHostTarget::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))),
        );

        let dns_config = DnsConfig {
            hosts,
            ..Default::default()
        };

        let configured =
            ConfiguredDnsResolver::new(dns_config.hosts, Vec::new(), Arc::new(SystemDnsResolver));

        let lookup = configured.resolve_all("custom.local", 80).await.unwrap();
        assert_eq!(
            lookup.socket_addrs(),
            &[SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)), 80)]
        );
    }
}
