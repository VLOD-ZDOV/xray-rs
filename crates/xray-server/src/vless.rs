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

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// Xray policy level 0 defaults.
pub(crate) const CONN_IDLE: Duration = Duration::from_secs(300);
const UPLINK_ONLY: Duration = Duration::from_secs(2);
const DOWNLINK_ONLY: Duration = Duration::from_secs(5);
// How long to wait for the first payload when a rule needs to sniff it.
const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_HEADER: usize = 1 + 16 + 1 + 255 + 1 + 2 + 1 + 1 + 255;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
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
    let addons = r.u8()? as usize;
    r.take(addons)?;
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sniffing {
    pub http: bool,
    pub tls: bool,
    pub route_only: bool,
}

impl Sniffing {
    pub fn enabled(self) -> bool {
        self.http || self.tls
    }

    pub fn domain(self, payload: &[u8]) -> Option<String> {
        let tls = self.tls.then(|| routing::sniff_tls_sni(payload)).flatten();
        tls.or_else(|| {
            self.http
                .then(|| routing::sniff_http_host(payload))
                .flatten()
        })
    }

    /// Like Xray, the sniffed domain replaces the destination unless `routeOnly` is set.
    pub fn override_host(self, payload: &[u8], host: &mut Host) {
        if !self.route_only {
            if let Some(domain) = self.domain(payload) {
                *host = Host::Domain(domain);
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

pub struct Context {
    pub tag: String,
    pub port: u16,
    pub users: RwLock<Vec<User>>,
    pub router: Arc<Router>,
    pub sniffing: Sniffing,
    pub fallbacks: Vec<crate::config::Fallback>,
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

    pub fn remove_user(&self, email: &str) -> Result<(), String> {
        if email.is_empty() {
            return Err("Email must not be empty.".into());
        }
        let mut users = self.users.write().unwrap_or_else(PoisonError::into_inner);
        let before = users.len();
        users.retain(|u| !u.email.eq_ignore_ascii_case(email));
        if users.len() == before {
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

pub async fn serve<R, W>(
    mut uplink: R,
    mut downlink: W,
    ctx: &Context,
    peer: SocketAddr,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(512);
    let handshake_res = timeout(HANDSHAKE_TIMEOUT, async {
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
            let n = uplink.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await;

    let (mut request, header_len, user) = match handshake_res {
        Ok(Ok(parsed)) => parsed,
        Err(_) | Ok(Err(_)) => {
            if let Some(fb) = crate::fallback::find_fallback(&ctx.fallbacks, &buf) {
                return crate::fallback::serve(uplink, downlink, fb, buf, peer, ctx.port).await;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vless handshake failed",
            ));
        }
    };
    let mut early = buf.split_off(header_len);

    let _online = stats::get().connect(&user.email, peer.ip());
    if request.command == Command::Mux {
        downlink.write_all(&[request.version, 0]).await?;
        downlink.flush().await?;
        let info = mux::Info {
            peer,
            tag: ctx.tag.clone(),
            port: ctx.port,
            email: user.email.clone(),
            router: ctx.router.clone(),
            sniffing: ctx.sniffing,
        };
        let mut reader = PrefixedReader {
            early,
            pos: 0,
            inner: &mut uplink,
        };
        return mux::serve(&mut reader, &mut downlink, &info).await;
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
        read_first(&mut uplink, &mut early).await;
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
        sniffing: ctx.sniffing,
    };
    let Some(decision) = route.allow(&ctx.router, payload).await else {
        return Ok(());
    };
    ctx.sniffing.override_host(payload, &mut request.host);
    if let Action::Block(BlockAction::Http403) = decision.action {
        if request.command == Command::Tcp {
            downlink.write_all(&[request.version, 0]).await?;
            downlink
                .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nCache-Control: max-age=600\r\nContent-Length: 0\r\n\r\n")
                .await?;
            downlink.flush().await?;
        }
        return Ok(());
    }
    let traffic = stats::get().traffic(&ctx.tag, &user.email, &decision.tag);

    match request.command {
        Command::Tcp => {
            let stream =
                outbound::connect(&ctx.router, &decision, &request.host, request.port).await?;
            let (mut target_r, mut target_w) = tokio::io::split(stream);
            target_w.write_all(&early).await?;
            traffic.up(early.len());
            downlink.write_all(&[request.version, 0]).await?;
            downlink.flush().await?;
            let activity = Activity::new();
            relay(
                copy(&mut uplink, &mut target_w, &activity, |n| traffic.up(n)),
                copy(&mut target_r, &mut downlink, &activity, |n| traffic.down(n)),
                &activity,
            )
            .await
        }
        Command::Mux => unreachable!("handled above"),
        Command::Udp => {
            let link = UdpLink::open(&ctx.router, &decision, &request.host, request.port).await?;
            downlink.write_all(&[request.version, 0]).await?;
            downlink.flush().await?;
            let activity = Activity::new();
            let reader = PrefixedReader {
                early,
                pos: 0,
                inner: &mut uplink,
            };
            relay(
                udp_up(reader, &link, &activity, &traffic),
                udp_down(&link, &mut downlink, &activity, &traffic),
                &activity,
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
    pub sniffing: Sniffing,
}

impl RouteRequest<'_> {
    /// Routes the request and writes the access log line. None means blocked.
    pub(crate) async fn allow(&self, router: &Router, first_payload: &[u8]) -> Option<Decision> {
        let sniffed_domain = self.sniffing.domain(first_payload);
        let (domain, ip) = if let Some(ref d) = sniffed_domain {
            (Some(d.as_str()), None)
        } else {
            match self.host {
                Host::Domain(name) => (Some(name.as_str()), None),
                Host::Ip(ip) => (None, Some(*ip)),
            }
        };
        let protocol = if router.needs_sniff() {
            routing::sniff(first_payload, self.network)
        } else {
            None
        };
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
        };
        let decision = router.route(&query).await;
        let network = if self.network == Network::Tcp {
            "tcp"
        } else {
            "udp"
        };
        let label = if let Some(ref d) = sniffed_domain {
            d.clone()
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
        Host::Domain(name) => tokio::net::lookup_host((name.as_str(), port))
            .await?
            .collect(),
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
    tokio::pin!(up, down);
    tokio::select! {
        result = &mut up => {
            result?;
            activity.touch();
            tokio::select! { _ = &mut down => {}, _ = idle_for(activity, DOWNLINK_ONLY) => {} }
        }
        result = &mut down => {
            result?;
            activity.touch();
            tokio::select! { _ = &mut up => {}, _ = idle_for(activity, UPLINK_ONLY) => {} }
        }
        _ = idle_for(activity, CONN_IDLE) => {}
    }
    Ok(())
}

async fn idle_for(activity: &Activity, limit: Duration) {
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
    let mut buf = vec![0u8; 32 * 1024];
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

#[cfg(test)]
mod tests {
    use super::*;

    fn users() -> Vec<User> {
        vec![User {
            id: [7; 16],
            hash: [0; 56],
            email: "u".into(),
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
}
