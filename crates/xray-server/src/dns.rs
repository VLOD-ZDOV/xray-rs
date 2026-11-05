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
    let resolver: Arc<dyn DnsResolver> = if let Some(dns) = config {
        let name_servers: Vec<NameServerPolicy> = dns
            .servers
            .into_iter()
            .map(|s| {
                let endpoint = s.endpoint();
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
                    policy.domains = p.domains;
                    policy.expected_ips = p.expected_ips;
                    policy.unexpected_ips = p.unexpected_ips;
                    policy.skip_fallback = p.skip_fallback;
                    policy.final_query = p.final_query;
                    if p.timeout_ms > 0 {
                        policy.timeout = Some(Duration::from_millis(p.timeout_ms));
                    }
                }
                policy
            })
            .collect();

        let query_strategy = match dns.query_strategy {
            ConfigQueryStrategy::UseIp => TransportQueryStrategy::UseIp,
            ConfigQueryStrategy::UseIpv4 => TransportQueryStrategy::UseIpv4,
            ConfigQueryStrategy::UseIpv6 => TransportQueryStrategy::UseIpv6,
        };

        let configured =
            ConfiguredDnsResolver::new(dns.hosts, Vec::new(), Arc::new(SystemDnsResolver))
                .with_name_server_policies(name_servers)
                .with_query_strategy(query_strategy)
                .with_name_server_fallback_policy(
                    dns.disable_fallback,
                    dns.disable_fallback_if_match,
                );

        Arc::new(configured)
    } else {
        Arc::new(SystemDnsResolver)
    };

    let _ = GLOBAL_RESOLVER.set(resolver);
}

pub fn resolver() -> &'static Arc<dyn DnsResolver> {
    GLOBAL_RESOLVER.get_or_init(|| Arc::new(SystemDnsResolver))
}

pub async fn resolve_all(domain: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
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
