//! VLESS inbound over an arbitrary byte stream, relaying to the routed outbound.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

use crate::config::User;
use crate::outbound::{self, UdpLink};
use crate::routing::{self, Action, BlockAction, Decision, Query, Router};
use crate::stats::{self, Traffic};
use crate::{log, mux};
use xray_config::Network;
use xray_proxy::vless::{VisionStream, VisionStreamIo, DEFAULT_VISION_SEED};

use crate::config::VISION_FLOW;

#[derive(Clone, PartialEq, prost::Message)]
pub struct Addons {
    #[prost(string, tag = "1")]
    pub flow: String,
}

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// Xray policy level 0 defaults.
pub(crate) const CONN_IDLE: Duration = Duration::from_secs(300);
// How long to wait for the first payload when a rule needs to sniff it.
const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_HEADER: usize = 1 + 16 + 1 + 255 + 1 + 2 + 1 + 1 + 255;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
    Reverse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub version: u8,
    pub user: usize,
    pub command: Command,
    pub host: Host,
    pub port: u16,
    pub flow: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Incomplete,
    Invalid(&'static str),
}

/// Parses a request header. Returns the request and the header length.
pub fn parse_request(buf: &[u8], users: &[User]) -> Result<(Request, usize), ParseError> {
    let mut r = Cursor { buf, pos: 0 };
    let version = r.u8()?;
    if version != 0 {
        return Err(ParseError::Invalid("unsupported version"));
    }
    let id = r.take(16)?;
    let user = users
        .iter()
        .position(|u| u.id == id)
        .ok_or(ParseError::Invalid("unknown user"))?;
    let addons_len = r.u8()? as usize;
    let addons_bytes = r.take(addons_len)?;
    let flow = if addons_len > 0 {
        <Addons as prost::Message>::decode(addons_bytes)
            .ok()
            .map(|a| a.flow)
            .filter(|f| !f.is_empty())
    } else {
        None
    };
    let command = match r.u8()? {
        1 => Command::Tcp,
        2 => Command::Udp,
        // Mux carries no address: targets travel inside Mux.Cool frames.
        3 => {
            let host = Host::Domain("v1.mux.cool".into());
            return Ok((
                Request {
                    version,
                    user,
                    command: Command::Mux,
                    host,
                    port: 0,
                    flow,
                },
                r.pos,
            ));
        }
        4 => {
            let host = Host::Domain("v1.rvs.cool".into());
            return Ok((
                Request {
                    version,
                    user,
                    command: Command::Reverse,
                    host,
                    port: 0,
                    flow,
                },
                r.pos,
            ));
        }
        _ => return Err(ParseError::Invalid("unknown command")),
    };
    let port = u16::from_be_bytes(r.take(2)?.try_into().unwrap_or_default());
    let host = match r.u8()? {
        1 => Host::Ip(IpAddr::from(
            <[u8; 4]>::try_from(r.take(4)?).unwrap_or_default(),
        )),
        2 => {
            let len = r.u8()? as usize;
            let name =
                std::str::from_utf8(r.take(len)?).map_err(|_| ParseError::Invalid("bad domain"))?;
            match name.parse::<IpAddr>() {
                Ok(ip) => Host::Ip(ip),
                Err(_) => Host::Domain(name.to_owned()),
            }
        }
        3 => Host::Ip(IpAddr::from(
            <[u8; 16]>::try_from(r.take(16)?).unwrap_or_default(),
        )),
        _ => return Err(ParseError::Invalid("unknown address type")),
    };
    Ok((
        Request {
            version,
            user,
            command,
            host,
            port,
            flow,
        },
        r.pos,
    ))
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let out = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(ParseError::Incomplete)?;
        self.pos += n;
        Ok(out)
    }
}

/// Inbound `sniffing`: which first-packet sniffers may name the destination.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sniffing {
    pub http: bool,
    pub tls: bool,
    pub quic: bool,
    pub fakedns: bool,
    pub fakedns_other: bool,
    pub route_only: bool,
    pub metadata_only: bool,
    pub domains_excluded: std::sync::Arc<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SniffOutput {
    pub domain: String,
    pub protocol: &'static str,
    pub is_fake_ip: bool,
}

impl Sniffing {
    pub fn enabled(&self) -> bool {
        (self.http || self.tls || self.quic || self.fakedns || self.fakedns_other)
            && (!self.metadata_only || self.fakedns || self.fakedns_other)
    }

    pub fn is_excluded(&self, domain: &str) -> bool {
        self.domains_excluded.iter().any(|ex| {
            domain.eq_ignore_ascii_case(ex)
                || (domain.len() > ex.len()
                    && domain.ends_with(ex)
                    && domain.as_bytes()[domain.len() - ex.len() - 1] == b'.')
        })
    }

    pub fn sniff(&self, payload: &[u8], host: &Host) -> Option<SniffOutput> {
        if let Host::Ip(ip) = host {
            if self.fakedns || self.fakedns_other {
                if let Some(domain) = crate::fakedns::get_domain_from_fake_ip(ip) {
                    if !self.is_excluded(&domain) {
                        return Some(SniffOutput {
                            domain,
                            protocol: "fakedns",
                            is_fake_ip: true,
                        });
                    }
                }
            }
            if self.fakedns_other && crate::fakedns::is_ip_in_pool(ip) {
                if !self.metadata_only {
                    let sniffed = routing::sniff_tls_sni(payload)
                        .or_else(|| routing::sniff_http_host(payload));
                    if let Some(domain) = sniffed {
                        if !self.is_excluded(&domain) {
                            return Some(SniffOutput {
                                domain,
                                protocol: "fakedns+others",
                                is_fake_ip: true,
                            });
                        }
                    }
                }
                return None;
            }
        }

        if self.metadata_only {
            return None;
        }

        let tls = self.tls.then(|| routing::sniff_tls_sni(payload)).flatten();
        let sniffed = tls.map(|d| (d, "tls")).or_else(|| {
            self.http
                .then(|| routing::sniff_http_host(payload))
                .flatten()
                .map(|d| (d, "http"))
        });

        let (domain, protocol) = sniffed?;
        if self.is_excluded(&domain) {
            return None;
        }
        let is_fake_ip = match host {
            Host::Ip(ip) => crate::fakedns::is_ip_in_pool(ip),
            _ => false,
        };
        Some(SniffOutput {
            domain,
            protocol,
            is_fake_ip,
        })
    }

    #[allow(dead_code)]
    pub fn domain(&self, payload: &[u8]) -> Option<String> {
        if self.metadata_only {
            return None;
        }
        let tls = self.tls.then(|| routing::sniff_tls_sni(payload)).flatten();
        let domain = tls.or_else(|| {
            self.http
                .then(|| routing::sniff_http_host(payload))
                .flatten()
        });
        domain.filter(|d| !self.is_excluded(d))
    }

    /// Like Xray, the sniffed domain replaces the destination unless `routeOnly` is set.
    pub fn override_host(&self, payload: &[u8], host: &mut Host) {
        if let Some(sniffed) = self.sniff(payload, host) {
            let keep_original = self.route_only
                && sniffed.protocol != "fakedns"
                && sniffed.protocol != "fakedns+others"
                && !sniffed.is_fake_ip;
            if !keep_original {
                *host = Host::Domain(sniffed.domain);
            }
        }
    }
}

/// Waits briefly for the client's first bytes, which routing and sniffing inspect.
pub(crate) async fn read_first<R: AsyncRead + Unpin>(reader: &mut R, early: &mut Vec<u8>) {
    let mut chunk = vec![0u8; 4096];
    if let Ok(Ok(n)) = timeout(SNIFF_TIMEOUT, reader.read(&mut chunk)).await {
        early.extend_from_slice(&chunk[..n]);
    }
}

#[derive(Clone, Debug)]
pub struct HysteriaUser {
    pub auth: String,
    pub email: String,
    #[allow(dead_code)]
    pub level: u32,
}

pub struct Context {
    pub tag: String,
    pub port: u16,
    pub users: RwLock<Vec<User>>,
    pub ss_users: RwLock<Vec<crate::config::ShadowsocksUser>>,
    pub ss_method: RwLock<Option<String>>,
    pub ss_password: RwLock<Option<String>>,
    pub hysteria_users: RwLock<Vec<HysteriaUser>>,
    pub router: Arc<Router>,
    pub sniffing: Sniffing,
    pub fallbacks: Vec<crate::config::Fallback>,
    pub vmess_filter: Arc<std::sync::Mutex<xray_proxy::vmess::server::AuthIdFilter>>,
    pub ss2022_salt_pool: Arc<std::sync::Mutex<xray_proxy::shadowsocks2022::SaltPool>>,
    pub vless_encryption: Option<Arc<xray_vless_encryption::Server>>,
}

impl Context {
    /// HandlerService AddUser; errors use Xray's wording, which 3x-ui matches on.
    pub fn add_user(&self, user: User) -> Result<(), String> {
        let mut users = self.users.write().unwrap_or_else(PoisonError::into_inner);
        if !user.email.is_empty()
            && users
                .iter()
                .any(|u| u.email.eq_ignore_ascii_case(&user.email))
        {
            return Err(format!("User {} already exists.", user.email));
        }
        users.retain(|u| u.id != user.id);
        users.push(user);
        Ok(())
    }

    pub fn add_ss_user(
        &self,
        email: String,
        ss_user: crate::config::ShadowsocksUser,
    ) -> Result<(), String> {
        if email.is_empty() {
            return Err("Email must not be empty.".into());
        }
        // Lock order is users, then the protocol lists, as in remove_user.
        let mut users = self.users.write().unwrap_or_else(PoisonError::into_inner);
        let mut ss_users = self
            .ss_users
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if ss_users
            .iter()
            .any(|u| u.email.eq_ignore_ascii_case(&email))
        {
            return Err(format!("User {email} already exists."));
        }
        let level = ss_user.level;
        ss_users.push(ss_user);
        if !users.iter().any(|u| u.email.eq_ignore_ascii_case(&email)) {
            users.push(User {
                id: crate::config::user_id(&email),
                hash: [0u8; 56],
                email,
                level,
                flow: String::new(),
                reverse: None,
                testseed: DEFAULT_VISION_SEED,
            });
        }
        Ok(())
    }

    pub fn add_hysteria_user(&self, user: HysteriaUser) -> Result<(), String> {
        if !user.email.is_empty() {
            let h_users = self
                .hysteria_users
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            if h_users
                .iter()
                .any(|u| u.email.eq_ignore_ascii_case(&user.email))
            {
                return Err(format!("User {} already exists.", user.email));
            }
        }
        let mut users = self.users.write().unwrap_or_else(PoisonError::into_inner);
        let mut h_users = self
            .hysteria_users
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if !user.email.is_empty()
            && h_users
                .iter()
                .any(|u| u.email.eq_ignore_ascii_case(&user.email))
        {
            return Err(format!("User {} already exists.", user.email));
        }
        h_users.retain(|u| u.auth != user.auth);
        h_users.push(user.clone());
        if !user.email.is_empty()
            && !users
                .iter()
                .any(|u| u.email.eq_ignore_ascii_case(&user.email))
        {
            users.push(User {
                id: crate::config::user_id(&user.email),
                hash: [0u8; 56],
                email: user.email,
                level: user.level,
                flow: String::new(),
                reverse: None,
                testseed: DEFAULT_VISION_SEED,
            });
        }
        Ok(())
    }

    pub fn remove_user(&self, email: &str) -> Result<(), String> {
        if email.is_empty() {
            return Err("Email must not be empty.".into());
        }
        let mut users = self.users.write().unwrap_or_else(PoisonError::into_inner);
        let mut ss_users = self
            .ss_users
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let mut h_users = self
            .hysteria_users
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let before_u = users.len();
        users.retain(|u| !u.email.eq_ignore_ascii_case(email));
        let before_ss = ss_users.len();
        ss_users.retain(|u| !u.email.eq_ignore_ascii_case(email));
        let before_h = h_users.len();
        h_users.retain(|u| !u.email.eq_ignore_ascii_case(email));
        if users.len() == before_u && ss_users.len() == before_ss && h_users.len() == before_h {
            return Err(format!("User {email} not found."));
        }
        Ok(())
    }

    pub fn users(&self) -> Vec<User> {
        self.users
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

pub async fn serve<R, W>(uplink: R, downlink: W, ctx: &Context, peer: SocketAddr) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_stream(
        DirectIoWrapper {
            inner: CombinedStream {
                r: uplink,
                w: downlink,
            },
        },
        ctx,
        peer,
        &Default::default(),
    )
    .await
}

pub async fn serve_stream<S>(
    stream: S,
    ctx: &Context,
    peer: SocketAddr,
    tls: &crate::fallback::TlsInfo,
) -> io::Result<()>
where
    S: VisionStreamIo + Send + 'static,
{
    let mut stream = if let Some(enc) = &ctx.vless_encryption {
        let timeout_dur = crate::policy::get().handshake;
        match timeout(timeout_dur, enc.handshake(stream)).await {
            Ok(Ok(encrypted)) => MaybeEncrypted::Encrypted(Box::new(encrypted)),
            Ok(Err(e)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ML-KEM-768 handshake failed: {e}"),
                ));
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ML-KEM-768 handshake timeout",
                ));
            }
        }
    } else {
        MaybeEncrypted::Plain(stream)
    };

    let mut buf = Vec::with_capacity(512);
    let handshake_res = timeout(crate::policy::get().handshake, async {
        let mut chunk = [0u8; 512];
        loop {
            // The user is copied out so a concurrent removal cannot shift the index.
            let parsed = {
                let users = ctx.users.read().unwrap_or_else(PoisonError::into_inner);
                parse_request(&buf, &users).map(|(request, len)| {
                    let user = users[request.user].clone();
                    (request, len, user)
                })
            };
            match parsed {
                Ok(parsed) => return Ok(parsed),
                Err(ParseError::Invalid(reason)) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
                }
                Err(ParseError::Incomplete) if buf.len() > MAX_HEADER => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "header too long",
                    ));
                }
                Err(ParseError::Incomplete) => {}
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await;

    let (mut request, header_len, user) = match handshake_res {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(_)) => {
            if let Some(fb) = crate::fallback::find_fallback(&ctx.fallbacks, tls, &buf) {
                let (r, w) = tokio::io::split(stream);
                return crate::fallback::serve(r, w, fb, buf, peer, ctx.port).await;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vless handshake failed",
            ));
        }
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "vless handshake timeout",
            ));
        }
    };
    let mut early = buf.split_off(header_len);

    let user_has_reverse = user.reverse.is_some();
    if user_has_reverse && request.command != Command::Reverse {
        let uid = uuid::Uuid::from_bytes(user.id);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("for safety reasons, user {uid} is not allowed to use forward proxy"),
        ));
    }
    if !user_has_reverse && request.command == Command::Reverse {
        let uid = uuid::Uuid::from_bytes(user.id);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("reverse: user {uid} is not allowed to create reverse proxy"),
        ));
    }
    if request.command == Command::Reverse {
        let reverse_tag = user.reverse.as_deref().unwrap_or_default();
        let portal = ctx.router.get_or_create_reverse_portal(reverse_tag);
        stream.write_all(&[request.version, 0]).await?;
        stream.flush().await?;
        portal.add_parent(stream).await;
        return Ok(());
    }

    // VLESS encryption carries Vision too, as Xray's CommonConn does.
    let vision_capable = tls.vision_capable || ctx.vless_encryption.is_some();
    let vision = check_flow(&request, &user, vision_capable, &early)?;
    if !vision {
        stream.release_record_alignment();
    }
    let user_policy = crate::policy::for_level(user.level);
    let _online = stats::get().connect(&user.email, user.level, peer.ip());
    if request.command == Command::Mux {
        let info = mux::Info {
            peer,
            tag: ctx.tag.clone(),
            port: ctx.port,
            email: user.email.clone(),
            level: user.level,
            router: ctx.router.clone(),
            sniffing: ctx.sniffing.clone(),
        };
        if vision {
            // Mux under Vision (XUDP from a Vision client) keeps the padding but
            // never switches to direct copy.
            write_vision_response(&mut stream, request.version).await?;
            let client =
                VisionStream::new(PrefixedStreamIo::new(stream, early), user.id, user.testseed);
            let (mut r, mut w) = tokio::io::split(client);
            return mux::serve(&mut r, &mut w, &info).await;
        }
        stream.write_all(&[request.version, 0]).await?;
        stream.flush().await?;
        let (mut r, mut w) = tokio::io::split(stream);
        let mut reader = PrefixedReader {
            early,
            pos: 0,
            inner: &mut r,
        };
        return mux::serve(&mut reader, &mut w, &info).await;
    }
    let network = if request.command == Command::Tcp {
        Network::Tcp
    } else {
        Network::Udp
    };
    if network == Network::Tcp
        && early.is_empty()
        && (ctx.router.needs_sniff() || ctx.sniffing.enabled())
    {
        read_first(&mut stream, &mut early).await;
    }
    // UDP early data is length-prefixed packets.
    let payload = if network == Network::Udp {
        early.get(2..).unwrap_or_default()
    } else {
        &early[..]
    };
    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email: &user.email,
        peer,
        network,
        host: &request.host,
        port: request.port,
        sniffing: &ctx.sniffing,
    };
    let Some(decision) = route.allow(&ctx.router, payload).await else {
        return Ok(());
    };
    ctx.sniffing.override_host(payload, &mut request.host);
    if let Action::Block(BlockAction::Http403) = decision.action {
        if request.command == Command::Tcp {
            stream.write_all(&[request.version, 0]).await?;
            stream
                .write_all(crate::routing::BLACKHOLE_HTTP_RESPONSE)
                .await?;
            stream.flush().await?;
        }
        return Ok(());
    }
    let traffic = stats::get().traffic(&ctx.tag, &user.email, user.level, &decision.tag);

    match request.command {
        Command::Tcp => {
            if vision {
                write_vision_response(&mut stream, request.version).await?;

                let client_stream = PrefixedStreamIo::new(stream, early);
                let vision_client = VisionStream::new(client_stream, user.id, user.testseed);
                let (mut client_r, mut client_w) = tokio::io::split(vision_client);

                let target =
                    outbound::connect(&ctx.router, &decision, &request.host, request.port).await?;
                let (mut target_r, mut target_w) = tokio::io::split(target);

                let activity = Activity::new();
                relay_policy(
                    copy_buf(
                        &mut client_r,
                        &mut target_w,
                        &activity,
                        |n| traffic.up(n),
                        user_policy.buffer_size,
                    ),
                    copy_buf(
                        &mut target_r,
                        &mut client_w,
                        &activity,
                        |n| traffic.down(n),
                        user_policy.buffer_size,
                    ),
                    &activity,
                    user_policy,
                )
                .await
            } else {
                let target =
                    outbound::connect(&ctx.router, &decision, &request.host, request.port).await?;
                let (mut target_r, mut target_w) = tokio::io::split(target);
                target_w.write_all(&early).await?;
                traffic.up(early.len());
                stream.write_all(&[request.version, 0]).await?;
                stream.flush().await?;

                let (mut uplink, mut downlink) = tokio::io::split(stream);
                let activity = Activity::new();
                relay_policy(
                    copy_buf(
                        &mut uplink,
                        &mut target_w,
                        &activity,
                        |n| traffic.up(n),
                        user_policy.buffer_size,
                    ),
                    copy_buf(
                        &mut target_r,
                        &mut downlink,
                        &activity,
                        |n| traffic.down(n),
                        user_policy.buffer_size,
                    ),
                    &activity,
                    user_policy,
                )
                .await
            }
        }
        Command::Mux => unreachable!("handled above"),
        Command::Reverse => unreachable!("handled above"),
        Command::Udp => {
            let (mut uplink, mut downlink) = tokio::io::split(stream);
            let link = UdpLink::open(&ctx.router, &decision, &request.host, request.port).await?;
            downlink.write_all(&[request.version, 0]).await?;
            downlink.flush().await?;
            let activity = Activity::new();
            let reader = PrefixedReader {
                early,
                pos: 0,
                inner: &mut uplink,
            };
            relay_policy(
                udp_up(reader, &link, &activity, &traffic),
                udp_down(&link, &mut downlink, &activity, &traffic),
                &activity,
                user_policy,
            )
            .await
        }
    }
}

pub(crate) struct RouteRequest<'a> {
    pub ctx_tag: &'a str,
    pub inbound_port: u16,
    pub email: &'a str,
    pub peer: SocketAddr,
    pub network: Network,
    pub host: &'a Host,
    pub port: u16,
    pub sniffing: &'a Sniffing,
}

impl RouteRequest<'_> {
    /// Routes the request and writes the access log line. None means blocked.
    pub(crate) async fn allow(&self, router: &Router, first_payload: &[u8]) -> Option<Decision> {
        let sniffed = self.sniffing.sniff(first_payload, self.host);
        let sniffed_domain = sniffed.as_ref().map(|s| s.domain.as_str());
        let sniffed_protocol = sniffed.as_ref().map(|s| s.protocol);
        let is_fake_ip = sniffed.as_ref().is_some_and(|s| s.is_fake_ip);

        let (domain, ip) = if let Some(d) = sniffed_domain {
            // With routeOnly the original IP is still dialed, so IP rules must see it,
            // UNLESS it's a fake IP or fakedns/fakedns+others.
            let ip = match self.host {
                Host::Ip(ip) if self.sniffing.route_only && !is_fake_ip => Some(*ip),
                _ => None,
            };
            (Some(d), ip)
        } else {
            match self.host {
                Host::Domain(name) => (Some(name.as_str()), None),
                Host::Ip(ip) => (None, Some(*ip)),
            }
        };
        let protocol = if let Some(p) = sniffed_protocol {
            Some(p)
        } else if router.needs_sniff() {
            routing::sniff(first_payload, self.network)
        } else {
            None
        };
        let proc_cell = std::sync::OnceLock::new();
        let query = Query {
            inbound: self.ctx_tag,
            inbound_port: self.inbound_port,
            user: self.email,
            source: self.peer,
            network: self.network,
            domain,
            ip,
            port: self.port,
            protocol,
            attributes: None,
            local_ip: None,
            vless_route: None,
            process_info: Some(&proc_cell),
        };
        let decision = router.route(&query).await;
        let network = if self.network == Network::Tcp {
            "tcp"
        } else {
            "udp"
        };
        let label = if let Some(d) = sniffed_domain {
            d.to_owned()
        } else {
            host_label(self.host)
        };
        let to = format!("{network}:{}:{}", label, self.port);
        let accepted = !matches!(decision.action, Action::Block(_));
        log::access(
            self.peer,
            accepted,
            to,
            self.ctx_tag,
            &decision.tag,
            self.email,
        );
        match decision.action {
            Action::Block(BlockAction::Http403) => Some(decision),
            Action::Block(_) => None,
            _ => Some(decision),
        }
    }
}

pub(crate) fn host_label(host: &Host) -> String {
    match host {
        Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
        Host::Ip(ip) => ip.to_string(),
        Host::Domain(name) => name.clone(),
    }
}

/// Resolves a target, IPv4 first: many servers have no working IPv6 route.
pub(crate) async fn resolve_all(host: &Host, port: u16) -> io::Result<Vec<SocketAddr>> {
    let mut addrs = match host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Host::Domain(name) => {
            crate::log::dns(format!("resolving {name}:{port}"));
            let list: Vec<SocketAddr> = crate::dns::resolve_all(name, port).await?;
            crate::log::dns(format!("resolved {name}:{port} -> {list:?}"));
            list
        }
    };
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no address for host",
        ));
    }
    addrs.sort_by_key(SocketAddr::is_ipv6);
    Ok(addrs)
}

pub(crate) async fn resolve(host: &Host, port: u16) -> io::Result<SocketAddr> {
    Ok(resolve_all(host, port).await?[0])
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (a == 100 && (64..128).contains(&b))
                || a == 0
                || a >= 224
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || (first & 0xff00) == 0xff00
        }
    }
}

pub(crate) struct Activity {
    start: Instant,
    last: AtomicU64,
}

impl Activity {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    pub(crate) fn touch(&self) {
        self.last
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn idle(&self) -> Duration {
        self.start
            .elapsed()
            .saturating_sub(Duration::from_millis(self.last.load(Ordering::Relaxed)))
    }
}

/// Runs both directions until `CONN_IDLE` passes without traffic. Once one side
/// finishes, the other keeps going only while it stays active (Xray's
/// uplinkOnly/downlinkOnly semantics).
pub(crate) async fn relay(
    up: impl std::future::Future<Output = io::Result<()>>,
    down: impl std::future::Future<Output = io::Result<()>>,
    activity: &Activity,
) -> io::Result<()> {
    relay_policy(up, down, activity, crate::policy::get()).await
}

pub(crate) async fn relay_policy(
    up: impl std::future::Future<Output = io::Result<()>>,
    down: impl std::future::Future<Output = io::Result<()>>,
    activity: &Activity,
    policy: crate::policy::PolicySettings,
) -> io::Result<()> {
    tokio::pin!(up, down);
    tokio::select! {
        result = &mut up => {
            result?;
            activity.touch();
            tokio::select! { _ = &mut down => {}, _ = idle_for(activity, policy.downlink_only) => {} }
        }
        result = &mut down => {
            result?;
            activity.touch();
            tokio::select! { _ = &mut up => {}, _ = idle_for(activity, policy.uplink_only) => {} }
        }
        _ = idle_for(activity, policy.conn_idle) => {}
    }
    Ok(())
}

pub(crate) async fn idle_for(activity: &Activity, limit: Duration) {
    loop {
        let left = limit.saturating_sub(activity.idle());
        if left.is_zero() {
            return;
        }
        tokio::time::sleep(left).await;
    }
}

pub(crate) async fn copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    activity: &Activity,
    count: impl Fn(usize),
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy_buf(
        reader,
        writer,
        activity,
        count,
        crate::policy::get().buffer_size,
    )
    .await
}

pub(crate) async fn copy_buf<R, W>(
    reader: &mut R,
    writer: &mut W,
    activity: &Activity,
    count: impl Fn(usize),
    buf_size: usize,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buf_size.max(512)];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        count(n);
        activity.touch();
    }
}

pub(crate) struct PrefixedStreamIo<S> {
    pub(crate) inner: S,
    pub(crate) prefix: Vec<u8>,
    pub(crate) pos: usize,
}

impl<S> PrefixedStreamIo<S> {
    pub(crate) fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStreamIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.pos < this.prefix.len() {
            let to_copy = (this.prefix.len() - this.pos).min(output.remaining());
            output.put_slice(&this.prefix[this.pos..this.pos + to_copy]);
            this.pos += to_copy;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStreamIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: VisionStreamIo> VisionStreamIo for PrefixedStreamIo<S> {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

    fn poll_read_direct(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.pos < this.prefix.len() {
            let to_copy = (this.prefix.len() - this.pos).min(output.remaining());
            output.put_slice(&this.prefix[this.pos..this.pos + to_copy]);
            this.pos += to_copy;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read_direct(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_direct(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush_direct(cx)
    }

    fn poll_shutdown_direct(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown_direct(cx)
    }
}

pub(crate) struct PrefixedReader<'a, R> {
    pub(crate) early: Vec<u8>,
    pub(crate) pos: usize,
    pub(crate) inner: &'a mut R,
}

/// Replays bytes read past the VLESS header before reading the stream.
impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pos < this.early.len() {
            let n = (this.early.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.early[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

pub(crate) struct CombinedStream<R, W> {
    pub(crate) r: R,
    pub(crate) w: W,
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for CombinedStream<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().r).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for CombinedStream<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().w).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().w).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().w).poll_shutdown(cx)
    }
}

pub(crate) struct DirectIoWrapper<T> {
    pub(crate) inner: T,
}

impl<T: AsyncRead + Unpin> AsyncRead for DirectIoWrapper<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for DirectIoWrapper<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> VisionStreamIo for DirectIoWrapper<T> {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }
}

pub enum MaybeEncrypted<S> {
    Plain(S),
    Encrypted(Box<xray_vless_encryption::EncryptedStream<S>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeEncrypted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Encrypted(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeEncrypted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Encrypted(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Encrypted(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Encrypted(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl<S: VisionStreamIo> VisionStreamIo for MaybeEncrypted<S> {
    fn release_record_alignment(&mut self) {
        match self {
            Self::Plain(s) => s.release_record_alignment(),
            Self::Encrypted(s) => s.get_mut().release_record_alignment(),
        }
    }

    fn poll_read_direct(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read_direct(cx, output),
            Self::Encrypted(s) => s.poll_read_vision_direct(cx, output),
        }
    }

    fn poll_write_direct(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_direct(cx, input),
            Self::Encrypted(s) => s.poll_write_vision_direct(cx, input),
        }
    }

    fn poll_flush_direct(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush_direct(cx),
            Self::Encrypted(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown_direct(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown_direct(cx),
            Self::Encrypted(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

async fn udp_up<R: AsyncRead + Unpin>(
    mut reader: PrefixedReader<'_, R>,
    link: &UdpLink,
    activity: &Activity,
    traffic: &Traffic,
) -> io::Result<()> {
    let mut packet = vec![0u8; 65535];
    loop {
        let mut len = [0u8; 2];
        match reader.read_exact(&mut len).await {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            other => {
                other?;
            }
        }
        let len = u16::from_be_bytes(len) as usize;
        reader.read_exact(&mut packet[..len]).await?;
        link.send(&packet[..len]).await?;
        traffic.up(len);
        activity.touch();
    }
}

async fn udp_down<W: AsyncWrite + Unpin>(
    link: &UdpLink,
    writer: &mut W,
    activity: &Activity,
    traffic: &Traffic,
) -> io::Result<()> {
    let mut packet = vec![0u8; 2 + 65535];
    loop {
        let n = link.recv(&mut packet[2..]).await?;
        traffic.down(n);
        packet[..2].copy_from_slice(&(n as u16).to_be_bytes());
        writer.write_all(&packet[..2 + n]).await?;
        writer.flush().await?;
        activity.touch();
    }
}

async fn write_vision_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    version: u8,
) -> io::Result<()> {
    let addons = prost::Message::encode_to_vec(&Addons {
        flow: VISION_FLOW.to_owned(),
    });
    let mut header = vec![version, addons.len() as u8];
    header.extend_from_slice(&addons);
    stream.write_all(&header).await?;
    stream.flush().await
}

/// Xray's flow rules: Vision only for users configured with it, only over
/// TLS 1.3, REALITY or VLESS encryption, never for plain UDP; and a Vision user without the
/// flow may only send UDP, directly or as XUDP over Mux.
fn check_flow(
    request: &Request,
    user: &User,
    vision_capable: bool,
    first: &[u8],
) -> io::Result<bool> {
    let reject = |msg: String| Err(io::Error::new(io::ErrorKind::PermissionDenied, msg));
    let account = uuid::Uuid::from_bytes(user.id);
    match request.flow.as_deref().unwrap_or("") {
        VISION_FLOW if user.flow == VISION_FLOW => {
            if request.command == Command::Udp {
                return reject(format!("{VISION_FLOW} doesn't support UDP"));
            }
            if !vision_capable {
                return reject("XTLS only supports TLS and REALITY directly for now.".into());
            }
            Ok(true)
        }
        VISION_FLOW => reject(format!(
            "account {account} is not able to use the flow {VISION_FLOW}"
        )),
        "" => {
            // Xray's isMuxAndNotXUDP: the first Mux frame opens session 0 over UDP.
            let mux_not_xudp = request.command == Command::Mux
                && !(first.len() >= 7 && first[2] == 0 && first[3] == 0 && first[6] == 2);
            if user.flow == VISION_FLOW && (request.command == Command::Tcp || mux_not_xudp) {
                return reject(format!(
                    "account {account} is rejected since the client flow is empty. Note that the pure TLS proxy has certain TLS in TLS characters."
                ));
            }
            Ok(false)
        }
        other => reject(format!("unknown request flow {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn users() -> Vec<User> {
        vec![User {
            id: [7; 16],
            hash: [0; 56],
            email: "u".into(),
            level: 0,
            flow: String::new(),
            reverse: None,
            testseed: DEFAULT_VISION_SEED,
        }]
    }

    fn header(addr: &[u8]) -> Vec<u8> {
        let mut h = vec![0];
        h.extend_from_slice(&[7; 16]);
        h.extend_from_slice(&[0, 1, 0x01, 0xbb]);
        h.extend_from_slice(addr);
        h
    }

    #[test]
    fn parses_domain_request_with_early_data() {
        let mut buf = header(&[2, 11]);
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(b"GET");
        let (req, len) = parse_request(&buf, &users()).unwrap();
        assert_eq!(req.host, Host::Domain("example.com".into()));
        assert_eq!(req.port, 443);
        assert_eq!(&buf[len..], b"GET");
    }

    #[test]
    fn reports_incomplete_and_rejects_unknown_user() {
        let buf = header(&[1, 1, 2, 3]);
        assert_eq!(
            parse_request(&buf[..buf.len() - 1], &users()),
            Err(ParseError::Incomplete)
        );
        let mut bad = buf.clone();
        bad[1] = 0;
        assert_eq!(
            parse_request(&bad, &users()),
            Err(ParseError::Invalid("unknown user"))
        );
    }

    #[test]
    fn private_ranges() {
        assert!(is_private("127.0.0.1".parse().unwrap()));
        assert!(is_private("10.1.2.3".parse().unwrap()));
        assert!(is_private("::ffff:192.168.1.1".parse().unwrap()));
        assert!(!is_private("1.1.1.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn route_only_sniffing_keeps_ip_rules() {
        let config = serde_json::json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"}],
            "routing": {"rules": [{"type": "field", "outboundTag": "blocked", "ip": ["10.0.0.0/8"]}]}
        });
        let router = Router::build(&config, &[]).unwrap();
        let host = Host::Ip("10.0.0.1".parse().unwrap());
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let sniff_route_only = Sniffing {
            http: true,
            tls: false,
            route_only: true,
            ..Default::default()
        };
        let sniff_override = Sniffing {
            http: true,
            tls: false,
            route_only: false,
            ..Default::default()
        };
        let route = |sniffing| RouteRequest {
            ctx_tag: "in",
            inbound_port: 443,
            email: "u",
            peer: "203.0.113.5:40000".parse().unwrap(),
            network: Network::Tcp,
            host: &host,
            port: 80,
            sniffing,
        };
        // routeOnly still dials 10.0.0.1; without it the sniffed domain is dialed instead.
        assert!(route(&sniff_route_only)
            .allow(&router, payload)
            .await
            .is_none());
        let decision = route(&sniff_override)
            .allow(&router, payload)
            .await
            .unwrap();
        assert_eq!(decision.tag, "direct");
    }

    #[tokio::test]
    async fn sniffing_domains_excluded_and_metadata_only() {
        let sniffing = Sniffing {
            http: true,
            tls: true,
            quic: false,
            route_only: false,
            metadata_only: false,
            domains_excluded: std::sync::Arc::new(vec![
                "example.com".to_owned(),
                "test.org".to_owned(),
            ]),
            ..Default::default()
        };
        let http_excluded = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(sniffing.domain(http_excluded), None);

        let sub_excluded = b"GET / HTTP/1.1\r\nHost: sub.example.com\r\n\r\n";
        assert_eq!(sniffing.domain(sub_excluded), None);

        let http_allowed = b"GET / HTTP/1.1\r\nHost: allowed.com\r\n\r\n";
        assert_eq!(
            sniffing.domain(http_allowed),
            Some("allowed.com".to_string())
        );

        let metadata_sniffing = Sniffing {
            metadata_only: true,
            ..sniffing
        };
        assert_eq!(metadata_sniffing.domain(http_allowed), None);
    }

    #[tokio::test]
    async fn fakedns_sniffing_and_dest_override() {
        let pool = xray_transport::fake_dns::FakeDnsPoolConfig {
            ip_pool: "198.18.0.0/15".to_string(),
            pool_size: 1000,
        };
        let multi = xray_transport::fake_dns::FakeDnsMulti::from_configs(&[pool]).unwrap();
        crate::fakedns::init(multi);

        let fake_ips = crate::fakedns::get_fake_ip_for_domain("fakedomain.test", true, false);
        assert_eq!(fake_ips.len(), 1);
        let fake_ip = fake_ips[0];

        let sniff_fakedns = Sniffing {
            fakedns: true,
            route_only: true,
            ..Default::default()
        };

        let mut host = Host::Ip(fake_ip);
        let payload = b"";
        let sniffed = sniff_fakedns.sniff(payload, &host);
        assert!(sniffed.is_some());
        let res = sniffed.unwrap();
        assert_eq!(res.domain, "fakedomain.test");
        assert_eq!(res.protocol, "fakedns");
        assert!(res.is_fake_ip);

        // override_host turns host into Host::Domain("fakedomain.test") even with route_only: true
        sniff_fakedns.override_host(payload, &mut host);
        assert_eq!(host, Host::Domain("fakedomain.test".to_string()));

        // Test fakedns+others: unmapped IP in pool sniffs payload
        let unmapped_in_pool: std::net::IpAddr = "198.18.254.254".parse().unwrap();
        let sniff_fakedns_other = Sniffing {
            fakedns_other: true,
            ..Default::default()
        };
        let http_payload = b"GET / HTTP/1.1\r\nHost: unmapped.test\r\n\r\n";
        let sniffed = sniff_fakedns_other.sniff(http_payload, &Host::Ip(unmapped_in_pool));
        assert!(sniffed.is_some());
        let res = sniffed.unwrap();
        assert_eq!(res.domain, "unmapped.test");
        assert_eq!(res.protocol, "fakedns+others");
        assert!(res.is_fake_ip);

        // Test fakedns+others: IP outside pool is NOT sniffed
        let outside_pool: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let sniffed_outside = sniff_fakedns_other.sniff(http_payload, &Host::Ip(outside_pool));
        assert!(sniffed_outside.is_none());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn handshake_times_out_when_client_sends_no_data() {
        let (_client, server) = tokio::io::duplex(64);
        let ctx = Context {
            tag: "vless-in".into(),
            port: 443,
            users: RwLock::new(vec![]),
            hysteria_users: RwLock::new(vec![]),
            ss_users: RwLock::new(vec![]),
            ss_method: RwLock::new(None),
            ss_password: RwLock::new(None),
            router: Arc::new(Router::build(&serde_json::json!({}), &[]).unwrap()),
            sniffing: Sniffing::default(),
            fallbacks: vec![],
            vmess_filter: Arc::new(std::sync::Mutex::new(
                xray_proxy::vmess::server::AuthIdFilter::new(120, 65536),
            )),
            ss2022_salt_pool: Arc::new(std::sync::Mutex::new(
                xray_proxy::shadowsocks2022::SaltPool::new(60, 65536),
            )),
            vless_encryption: None,
        };

        let _lock = crate::policy::TEST_LOCK.lock().unwrap();
        crate::policy::init_single(crate::policy::PolicySettings {
            handshake: Duration::from_millis(50),
            ..Default::default()
        });

        let (r, w) = tokio::io::split(server);
        let err = serve(r, w, &ctx, "127.0.0.1:12345".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        crate::policy::init_single(crate::policy::PolicySettings::default());
    }
}
