//! Xray gRPC API subset over cleartext HTTP/2: `StatsService`, which is how
//! 3x-ui reads traffic and online users, and the user operations of
//! `HandlerService`, which let it add and remove clients without a restart.
//! Everything else answers `Unimplemented`, and 3x-ui then restarts the core.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Request, Response};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use prost::Message;
use tokio::net::TcpListener;

use crate::config::{user_id, User as InboundUser};
use crate::routing::Router;
use crate::vless::Context;
use crate::{log, stats, xhttp::Body};

const STATS: &str = "/xray.app.stats.command.StatsService/";
const HANDLER: &str = "/xray.app.proxyman.command.HandlerService/";
const LOGGER: &str = "/xray.app.log.command.LoggerService/";
const ROUTER: &str = "/xray.app.router.command.RoutingService/";
const OBSERVATORY: &str = "/xray.core.app.observatory.command.ObservatoryService/";
const ADD_USER: &str = "xray.app.proxyman.command.AddUserOperation";
const REMOVE_USER: &str = "xray.app.proxyman.command.RemoveUserOperation";
const VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";
const TROJAN_ACCOUNT: &str = "xray.proxy.trojan.Account";
const VMESS_ACCOUNT: &str = "xray.proxy.vmess.Account";
const SHADOWSOCKS_ACCOUNT: &str = "xray.proxy.shadowsocks.Account";
const SHADOWSOCKS_2022_ACCOUNT: &str = "xray.proxy.shadowsocks_2022.Account";
const HYSTERIA_ACCOUNT: &str = "xray.proxy.hysteria.account.Account";
const HYSTERIA_ACCOUNT_ALT: &str = "xray.proxy.hysteria.Account";
const MAX_REQUEST: usize = 1 << 20;

// grpc-status codes.
const UNKNOWN: u8 = 2;
const NOT_FOUND: u8 = 5;
const INVALID_ARGUMENT: u8 = 3;
const UNIMPLEMENTED: u8 = 12;

#[derive(Clone, PartialEq, Message)]
pub struct GetStatsRequest {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct Stat {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(int64, tag = "2")]
    pub value: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetStatsResponse {
    #[prost(message, optional, tag = "1")]
    pub stat: Option<Stat>,
}

#[derive(Clone, PartialEq, Message)]
pub struct QueryStatsRequest {
    #[prost(string, tag = "1")]
    pub pattern: String,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct QueryStatsResponse {
    #[prost(message, repeated, tag = "1")]
    pub stat: Vec<Stat>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SysStatsResponse {
    #[prost(uint32, tag = "1")]
    pub num_goroutine: u32,
    #[prost(uint32, tag = "10")]
    pub uptime: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetStatsOnlineIpListResponse {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(map = "string, int64", tag = "2")]
    pub ips: std::collections::HashMap<String, i64>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetAllOnlineUsersResponse {
    #[prost(string, repeated, tag = "1")]
    pub users: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OnlineIpEntry {
    #[prost(string, tag = "1")]
    pub ip: String,
    #[prost(int64, tag = "2")]
    pub last_seen: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct TrafficUserStat {
    #[prost(int64, tag = "1")]
    pub uplink: i64,
    #[prost(int64, tag = "2")]
    pub downlink: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct UserStat {
    #[prost(string, tag = "1")]
    pub email: String,
    #[prost(message, repeated, tag = "2")]
    pub ips: Vec<OnlineIpEntry>,
    #[prost(message, optional, tag = "3")]
    pub traffic: Option<TrafficUserStat>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetUsersStatsRequest {
    #[prost(bool, tag = "1")]
    pub include_traffic: bool,
    #[prost(bool, tag = "2")]
    pub reset: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetUsersStatsResponse {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<UserStat>,
}

#[derive(Clone, PartialEq, Message)]
pub struct TypedMessage {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(bytes = "bytes", tag = "2")]
    pub value: Bytes,
}

#[derive(Clone, PartialEq, Message)]
pub struct AlterInboundRequest {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(message, optional, tag = "2")]
    pub operation: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AddUserOperation {
    #[prost(message, optional, tag = "1")]
    pub user: Option<ProtocolUser>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveUserOperation {
    #[prost(string, tag = "1")]
    pub email: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtocolUser {
    #[prost(uint32, tag = "1")]
    pub level: u32,
    #[prost(string, tag = "2")]
    pub email: String,
    #[prost(message, optional, tag = "3")]
    pub account: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, Message)]
pub struct VlessAccount {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub flow: String,
    #[prost(string, tag = "3")]
    pub encryption: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct TrojanAccount {
    #[prost(string, tag = "1")]
    pub password: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct VmessAccount {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(uint32, tag = "2")]
    pub alter_id: u32,
    #[prost(string, tag = "4")]
    pub tests_enabled: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ShadowsocksAccount {
    #[prost(string, tag = "1")]
    pub password: String,
    #[prost(enumeration = "CipherType", tag = "2")]
    pub cipher_type: i32,
    #[prost(bool, tag = "3")]
    pub iv_check: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct HysteriaAccount {
    #[prost(string, tag = "1")]
    pub auth: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
pub enum CipherType {
    Unknown = 0,
    Aes128Gcm = 5,
    Aes256Gcm = 6,
    Chacha20Poly1305 = 7,
    Xchacha20Poly1305 = 8,
}

#[derive(Clone, PartialEq, Message)]
pub struct Shadowsocks2022Account {
    #[prost(string, tag = "1")]
    pub key: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetInboundUserRequest {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(string, tag = "2")]
    pub email: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetInboundUserResponse {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<ProtocolUser>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetInboundUsersCountResponse {
    #[prost(int64, tag = "1")]
    pub count: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct AddInboundRequest {
    #[prost(message, optional, tag = "1")]
    pub inbound: Option<InboundHandlerConfig>,
}

#[derive(Clone, PartialEq, Message)]
pub struct InboundHandlerConfig {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(message, optional, tag = "2")]
    pub receiver_settings: Option<TypedMessage>,
    #[prost(message, optional, tag = "3")]
    pub proxy_settings: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AddInboundResponse {}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveInboundRequest {
    #[prost(string, tag = "1")]
    pub tag: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveInboundResponse {}

#[derive(Clone, PartialEq, Message)]
pub struct AddOutboundRequest {
    #[prost(message, optional, tag = "1")]
    pub outbound: Option<OutboundHandlerConfig>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OutboundHandlerConfig {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(message, optional, tag = "2")]
    pub sender_settings: Option<TypedMessage>,
    #[prost(message, optional, tag = "3")]
    pub proxy_settings: Option<TypedMessage>,
    #[prost(int64, tag = "4")]
    pub expire: i64,
    #[prost(string, tag = "5")]
    pub comment: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct AddOutboundResponse {}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveOutboundRequest {
    #[prost(string, tag = "1")]
    pub tag: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveOutboundResponse {}

#[derive(Clone, PartialEq, Message)]
pub struct AddRuleRequest {
    #[prost(message, optional, tag = "1")]
    pub config: Option<TypedMessage>,
    #[prost(bool, tag = "2")]
    pub should_append: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct AddRuleResponse {}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveRuleRequest {
    #[prost(string, tag = "1")]
    pub rule_tag: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RemoveRuleResponse {}

#[derive(Clone, PartialEq, Message)]
pub struct ListRuleRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct ListRuleItem {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(string, tag = "2")]
    pub rule_tag: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ListRuleResponse {
    #[prost(message, repeated, tag = "1")]
    pub rules: Vec<ListRuleItem>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RouterConfigProto {
    #[prost(message, repeated, tag = "2")]
    pub rule: Vec<RoutingRuleProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RoutingRuleProto {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(string, tag = "19")]
    pub rule_tag: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<DomainRuleProto>,
    #[prost(message, repeated, tag = "10")]
    pub ip: Vec<IpRuleProto>,
    #[prost(message, optional, tag = "14")]
    pub port_list: Option<PortListProto>,
    #[prost(int32, repeated, tag = "13")]
    pub networks: Vec<i32>,
    #[prost(message, repeated, tag = "11")]
    pub source_ip: Vec<IpRuleProto>,
    #[prost(message, optional, tag = "16")]
    pub source_port_list: Option<PortListProto>,
    #[prost(string, repeated, tag = "7")]
    pub user_email: Vec<String>,
    #[prost(string, repeated, tag = "8")]
    pub inbound_tag: Vec<String>,
    #[prost(string, repeated, tag = "9")]
    pub protocol: Vec<String>,
    #[prost(map = "string, string", tag = "15")]
    pub attributes: HashMap<String, String>,
    #[prost(message, repeated, tag = "17")]
    pub local_ip: Vec<IpRuleProto>,
    #[prost(message, optional, tag = "18")]
    pub local_port_list: Option<PortListProto>,
    #[prost(message, optional, tag = "20")]
    pub vless_route_list: Option<PortListProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DomainRuleProto {
    #[prost(message, optional, tag = "1")]
    pub geosite: Option<GeoSiteRuleProto>,
    #[prost(message, optional, tag = "2")]
    pub custom: Option<DomainProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DomainProto {
    #[prost(int32, tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoSiteRuleProto {
    #[prost(string, tag = "1")]
    pub file: String,
    #[prost(string, tag = "2")]
    pub code: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct IpRuleProto {
    #[prost(message, optional, tag = "1")]
    pub geoip: Option<GeoIpRuleProto>,
    #[prost(message, optional, tag = "2")]
    pub custom: Option<CidrProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoIpRuleProto {
    #[prost(string, tag = "1")]
    pub file: String,
    #[prost(string, tag = "2")]
    pub code: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct CidrProto {
    #[prost(bytes = "bytes", tag = "1")]
    pub ip: Bytes,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct PortRangeProto {
    #[prost(uint32, tag = "1")]
    pub from: u32,
    #[prost(uint32, tag = "2")]
    pub to: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct PortListProto {
    #[prost(message, repeated, tag = "1")]
    pub range: Vec<PortRangeProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ReceiverConfig {
    #[prost(message, optional, tag = "1")]
    pub port_list: Option<PortListProto>,
    #[prost(message, optional, tag = "2")]
    pub listen: Option<IpOrDomainProto>,
    #[prost(message, optional, tag = "3")]
    pub stream_settings: Option<StreamConfigProto>,
    #[prost(bool, tag = "4")]
    pub receive_original_destination: bool,
    #[prost(message, optional, tag = "6")]
    pub sniffing_settings: Option<SniffingConfigProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct IpOrDomainProto {
    #[prost(bytes = "bytes", optional, tag = "1")]
    pub ip: Option<Bytes>,
    #[prost(string, optional, tag = "2")]
    pub domain: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct StreamConfigProto {
    #[prost(string, tag = "5")]
    pub protocol_name: String,
    #[prost(string, tag = "3")]
    pub security_type: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct SniffingConfigProto {
    #[prost(bool, tag = "1")]
    pub enabled: bool,
    #[prost(string, repeated, tag = "2")]
    pub destination_override: Vec<String>,
    #[prost(bool, tag = "3")]
    pub metadata_only: bool,
    #[prost(bool, tag = "4")]
    pub route_only: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProxyUsersConfig {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<ProtocolUser>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RoutingContext {
    #[prost(string, tag = "1")]
    pub inbound_tag: String,
    #[prost(enumeration = "Network", tag = "2")]
    pub network: i32,
    #[prost(bytes = "bytes", repeated, tag = "3")]
    pub source_ips: Vec<Bytes>,
    #[prost(bytes = "bytes", repeated, tag = "4")]
    pub target_ips: Vec<Bytes>,
    #[prost(uint32, tag = "5")]
    pub source_port: u32,
    #[prost(uint32, tag = "6")]
    pub target_port: u32,
    #[prost(string, tag = "7")]
    pub target_domain: String,
    #[prost(string, tag = "8")]
    pub protocol: String,
    #[prost(string, tag = "9")]
    pub user: String,
    #[prost(map = "string, string", tag = "10")]
    pub attributes: HashMap<String, String>,
    #[prost(string, repeated, tag = "11")]
    pub outbound_group_tags: Vec<String>,
    #[prost(string, tag = "12")]
    pub outbound_tag: String,
    #[prost(bytes = "bytes", repeated, tag = "13")]
    pub local_ips: Vec<Bytes>,
    #[prost(uint32, tag = "14")]
    pub local_port: u32,
    #[prost(uint32, tag = "15")]
    pub vless_route: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
pub enum Network {
    Unknown = 0,
    Tcp = 2,
    Udp = 3,
    Unix = 4,
}

#[derive(Clone, PartialEq, Message)]
pub struct TestRouteRequest {
    #[prost(message, optional, tag = "1")]
    pub routing_context: Option<RoutingContext>,
    #[prost(string, repeated, tag = "2")]
    pub field_selectors: Vec<String>,
    #[prost(bool, tag = "3")]
    pub publish_result: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct RestartLoggerRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct RestartLoggerResponse {}

#[derive(Clone, PartialEq, Message)]
pub struct GetOutboundStatusRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct GetOutboundStatusResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<ObservationResultProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ObservationResultProto {
    #[prost(message, repeated, tag = "1")]
    pub status: Vec<OutboundStatusProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OutboundStatusProto {
    #[prost(bool, tag = "1")]
    pub alive: bool,
    #[prost(int64, tag = "2")]
    pub delay: i64,
    #[prost(string, tag = "3")]
    pub last_error_reason: String,
    #[prost(string, tag = "4")]
    pub outbound_tag: String,
    #[prost(int64, tag = "5")]
    pub last_seen_time: i64,
    #[prost(int64, tag = "6")]
    pub last_try_time: i64,
    #[prost(message, optional, tag = "7")]
    pub health_ping: Option<HealthPingMeasurementResultProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct HealthPingMeasurementResultProto {
    #[prost(int64, tag = "1")]
    pub all: i64,
    #[prost(int64, tag = "2")]
    pub fail: i64,
    #[prost(int64, tag = "3")]
    pub deviation: i64,
    #[prost(int64, tag = "4")]
    pub average: i64,
    #[prost(int64, tag = "5")]
    pub max: i64,
    #[prost(int64, tag = "6")]
    pub min: i64,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetBalancerInfoRequest {
    #[prost(string, tag = "1")]
    pub tag: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct GetBalancerInfoResponse {
    #[prost(message, optional, tag = "1")]
    pub balancer: Option<BalancerMsg>,
}

#[derive(Clone, PartialEq, Message)]
pub struct BalancerMsg {
    #[prost(message, optional, tag = "5")]
    pub override_info: Option<OverrideInfo>,
    #[prost(message, optional, tag = "6")]
    pub principle_target: Option<PrincipleTargetInfo>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PrincipleTargetInfo {
    #[prost(string, repeated, tag = "1")]
    pub tag: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct OverrideInfo {
    #[prost(string, tag = "2")]
    pub target: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct OverrideBalancerTargetRequest {
    #[prost(string, tag = "1")]
    pub balancer_tag: String,
    #[prost(string, tag = "2")]
    pub target: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct OverrideBalancerTargetResponse {}

enum ServiceType<'a> {
    Stats(&'a str),
    Handler(&'a str),
    Logger(&'a str),
    Router(&'a str),
    Observatory(&'a str),
}

#[derive(Clone, PartialEq, Message)]
pub struct Empty {}

pub struct InboundManager {
    inbounds: RwLock<HashMap<String, InboundEntry>>,
    router: Arc<Router>,
}

pub struct InboundEntry {
    pub ctx: Arc<Context>,
    pub tcp_abort: Option<tokio::task::AbortHandle>,
    pub udp_abort: Option<tokio::task::AbortHandle>,
}

impl InboundManager {
    pub fn new(router: Arc<Router>) -> Self {
        Self {
            inbounds: RwLock::new(HashMap::new()),
            router,
        }
    }

    pub fn insert_initial(
        &self,
        tag: String,
        ctx: Arc<Context>,
        tcp_abort: Option<tokio::task::AbortHandle>,
        udp_abort: Option<tokio::task::AbortHandle>,
    ) {
        let mut map = self
            .inbounds
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.insert(
            tag,
            InboundEntry {
                ctx,
                tcp_abort,
                udp_abort,
            },
        );
    }

    pub fn get_ctx(&self, tag: &str) -> Option<Arc<Context>> {
        let map = self
            .inbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(tag).map(|e| e.ctx.clone())
    }

    pub fn contains(&self, tag: &str) -> bool {
        let map = self
            .inbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.contains_key(tag)
    }

    pub fn remove(&self, tag: &str) -> bool {
        let mut map = self
            .inbounds
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = map.remove(tag) {
            if let Some(h) = entry.tcp_abort {
                h.abort();
            }
            if let Some(h) = entry.udp_abort {
                h.abort();
            }
            true
        } else {
            false
        }
    }

    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    pub fn add_entry(
        &self,
        tag: String,
        ctx: Arc<Context>,
        tcp_abort: Option<tokio::task::AbortHandle>,
        udp_abort: Option<tokio::task::AbortHandle>,
    ) -> Result<(), String> {
        let mut map = self
            .inbounds
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.contains_key(&tag) {
            return Err(format!("handler already exists: {tag}"));
        }
        map.insert(
            tag,
            InboundEntry {
                ctx,
                tcp_abort,
                udp_abort,
            },
        );
        Ok(())
    }
}

pub async fn serve(
    addr: SocketAddr,
    inbound_manager: Arc<InboundManager>,
    router: Arc<Router>,
    observatory: Option<Arc<crate::observatory::Observatory>>,
) -> Result<(), String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to listen on api {addr}: {e}"))?;
    log::info(format!("api listening on {addr}"));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let inbound_manager = inbound_manager.clone();
            let router = router.clone();
            let observatory = observatory.clone();
            tokio::spawn(async move {
                let service = service_fn(|req| {
                    let inbound_manager = inbound_manager.clone();
                    let router = router.clone();
                    let observatory = observatory.clone();
                    async move {
                        Ok::<_, Infallible>(
                            handle(req, &inbound_manager, &router, &observatory).await,
                        )
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok(())
}

async fn handle(
    req: Request<Incoming>,
    inbound_manager: &Arc<InboundManager>,
    router: &Arc<Router>,
    observatory: &Option<Arc<crate::observatory::Observatory>>,
) -> Response<Body> {
    let path = req.uri().path().to_owned();
    let svc = if let Some(m) = path.strip_prefix(STATS) {
        ServiceType::Stats(m)
    } else if let Some(m) = path.strip_prefix(HANDLER) {
        ServiceType::Handler(m)
    } else if let Some(m) = path.strip_prefix(LOGGER) {
        ServiceType::Logger(m)
    } else if let Some(m) = path.strip_prefix(ROUTER) {
        ServiceType::Router(m)
    } else if let Some(m) = path.strip_prefix(OBSERVATORY) {
        ServiceType::Observatory(m)
    } else {
        return status(UNIMPLEMENTED, "unknown service");
    };
    let body = match http_body_util::Limited::new(req.into_body(), MAX_REQUEST)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => return status(INVALID_ARGUMENT, "request too large"),
    };
    let Some(message) = unframe(body) else {
        return status(INVALID_ARGUMENT, "bad grpc frame");
    };
    match svc {
        ServiceType::Handler(method) => handle_handler(method, message, inbound_manager).await,
        ServiceType::Logger("RestartLogger") => {
            let Ok(_) = RestartLoggerRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            match log::restart() {
                Ok(()) => reply(&RestartLoggerResponse {}),
                Err(e) => status(UNKNOWN, &e),
            }
        }
        ServiceType::Logger(_) => status(UNIMPLEMENTED, "unknown method"),
        ServiceType::Router(method) => handle_router(method, message, router).await,
        ServiceType::Observatory(method) => handle_observatory(method, message, observatory).await,
        ServiceType::Stats(method) => handle_stats(method, message),
    }
}

async fn handle_router(method: &str, message: Bytes, router: &Arc<Router>) -> Response<Body> {
    match method {
        "AddRule" => match AddRuleRequest::decode(message) {
            Ok(req) => {
                let config = req.config.unwrap_or_default();
                if config.r#type.contains("xray.app.router.Config") {
                    if let Ok(cfg) = RouterConfigProto::decode(config.value) {
                        for r in cfg.rule {
                            let mut rule_obj = serde_json::Map::new();
                            rule_obj.insert("type".into(), serde_json::json!("field"));
                            if !r.tag.is_empty() {
                                rule_obj.insert("outboundTag".into(), serde_json::json!(r.tag));
                            }
                            if !r.rule_tag.is_empty() {
                                rule_obj.insert("ruleTag".into(), serde_json::json!(r.rule_tag));
                            }
                            let mut domains = Vec::new();
                            for d in r.domain {
                                if let Some(c) = d.custom {
                                    match c.r#type {
                                        0 => domains.push(c.value),
                                        1 => domains.push(format!("regexp:{}", c.value)),
                                        2 => domains.push(format!("domain:{}", c.value)),
                                        3 => domains.push(format!("full:{}", c.value)),
                                        _ => domains.push(c.value),
                                    }
                                } else if let Some(g) = d.geosite {
                                    domains.push(format!("geosite:{}", g.code));
                                }
                            }
                            if !domains.is_empty() {
                                rule_obj.insert("domain".into(), serde_json::json!(domains));
                            }
                            let mut ips = Vec::new();
                            for ip in r.ip {
                                if let Some(c) = ip.custom {
                                    if !c.ip.is_empty() {
                                        let ip_str = if c.ip.len() == 4 {
                                            format!(
                                                "{}.{}.{}.{}/{}",
                                                c.ip[0], c.ip[1], c.ip[2], c.ip[3], c.prefix
                                            )
                                        } else {
                                            format!("{:?}/{}", c.ip, c.prefix)
                                        };
                                        ips.push(ip_str);
                                    }
                                } else if let Some(g) = ip.geoip {
                                    ips.push(format!("geoip:{}", g.code));
                                }
                            }
                            if !ips.is_empty() {
                                rule_obj.insert("ip".into(), serde_json::json!(ips));
                            }
                            if !r.networks.is_empty() {
                                let nets: Vec<&str> = r
                                    .networks
                                    .iter()
                                    .filter_map(|n| match n {
                                        2 => Some("tcp"),
                                        3 => Some("udp"),
                                        _ => None,
                                    })
                                    .collect();
                                if !nets.is_empty() {
                                    rule_obj.insert(
                                        "network".into(),
                                        serde_json::json!(nets.join(",")),
                                    );
                                }
                            }
                            if !r.user_email.is_empty() {
                                rule_obj.insert("user".into(), serde_json::json!(r.user_email));
                            }
                            if !r.inbound_tag.is_empty() {
                                rule_obj
                                    .insert("inboundTag".into(), serde_json::json!(r.inbound_tag));
                            }
                            if !r.protocol.is_empty() {
                                rule_obj.insert("protocol".into(), serde_json::json!(r.protocol));
                            }
                            if !r.attributes.is_empty() {
                                rule_obj.insert("attrs".into(), serde_json::json!(r.attributes));
                            }
                            if let Some(pl) = r.port_list {
                                let ports: Vec<String> = pl
                                    .range
                                    .iter()
                                    .map(|p| {
                                        if p.from == p.to {
                                            format!("{}", p.from)
                                        } else {
                                            format!("{}-{}", p.from, p.to)
                                        }
                                    })
                                    .collect();
                                if !ports.is_empty() {
                                    rule_obj
                                        .insert("port".into(), serde_json::json!(ports.join(",")));
                                }
                            }
                            match router.parse_rule(&serde_json::Value::Object(rule_obj)) {
                                Ok(parsed_rule) => {
                                    router.add_rule(parsed_rule, req.should_append);
                                }
                                Err(e) => return status(UNKNOWN, &e),
                            }
                        }
                    }
                }
                reply(&AddRuleResponse {})
            }
            Err(e) => status(INVALID_ARGUMENT, &e.to_string()),
        },
        "RemoveRule" => match RemoveRuleRequest::decode(message) {
            Ok(req) => {
                let _count = router.remove_rule(&req.rule_tag);
                reply(&RemoveRuleResponse {})
            }
            Err(e) => status(INVALID_ARGUMENT, &e.to_string()),
        },
        "ListRule" => match ListRuleRequest::decode(message) {
            Ok(_) => {
                let rules: Vec<_> = router
                    .list_rules()
                    .into_iter()
                    .map(|(tag, rule_tag)| ListRuleItem { tag, rule_tag })
                    .collect();
                reply(&ListRuleResponse { rules })
            }
            Err(e) => status(INVALID_ARGUMENT, &e.to_string()),
        },
        "TestRoute" => match TestRouteRequest::decode(message) {
            Ok(req) => {
                let mut rc = req.routing_context.unwrap_or_else(|| RoutingContext {
                    inbound_tag: String::new(),
                    network: 0,
                    source_ips: Vec::new(),
                    target_ips: Vec::new(),
                    source_port: 0,
                    target_port: 0,
                    target_domain: String::new(),
                    protocol: String::new(),
                    user: String::new(),
                    attributes: HashMap::new(),
                    outbound_group_tags: Vec::new(),
                    outbound_tag: String::new(),
                    local_ips: Vec::new(),
                    local_port: 0,
                    vless_route: 0,
                });
                let source_ip: IpAddr = rc
                    .source_ips
                    .first()
                    .and_then(|b| {
                        if b.len() == 4 {
                            Some(IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])))
                        } else {
                            None
                        }
                    })
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
                let source = SocketAddr::new(source_ip, rc.source_port as u16);
                let network = match rc.network {
                    3 => xray_config::Network::Udp,
                    _ => xray_config::Network::Tcp,
                };
                let target_ip: Option<IpAddr> = rc.target_ips.first().and_then(|b| {
                    if b.len() == 4 {
                        Some(IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])))
                    } else {
                        None
                    }
                });
                let local_ip: Option<IpAddr> = rc.local_ips.first().and_then(|b| {
                    if b.len() == 4 {
                        Some(IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])))
                    } else {
                        None
                    }
                });
                let domain = if rc.target_domain.is_empty() {
                    None
                } else {
                    Some(rc.target_domain.as_str())
                };
                let protocol = if rc.protocol.is_empty() {
                    None
                } else {
                    match rc.protocol.as_str() {
                        "http" => Some("http"),
                        "tls" => Some("tls"),
                        "bittorrent" => Some("bittorrent"),
                        _ => None,
                    }
                };
                let vless_route = if rc.vless_route > 0 {
                    Some(rc.vless_route)
                } else {
                    None
                };
                let query = crate::routing::Query {
                    inbound: &rc.inbound_tag,
                    inbound_port: rc.local_port as u16,
                    user: &rc.user,
                    source,
                    network,
                    domain,
                    ip: target_ip,
                    port: rc.target_port as u16,
                    protocol,
                    attributes: Some(&rc.attributes),
                    local_ip,
                    vless_route,
                };
                let decision = router.route(&query).await;
                rc.outbound_tag = decision.tag;
                reply(&rc)
            }
            Err(e) => status(INVALID_ARGUMENT, &e.to_string()),
        },
        "GetBalancerInfo" => match GetBalancerInfoRequest::decode(message) {
            Ok(req) => {
                if let Some(b) = router.balancers.get(&req.tag) {
                    let override_target = b
                        .override_target
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    let override_info = override_target.map(|t| OverrideInfo { target: t });
                    let outbounds = router
                        .outbounds
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let obs = router
                        .observatory
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let principle_target = b.get_principle_target(&outbounds, obs.as_deref());
                    let resp = GetBalancerInfoResponse {
                        balancer: Some(BalancerMsg {
                            override_info,
                            principle_target: Some(PrincipleTargetInfo {
                                tag: principle_target,
                            }),
                        }),
                    };
                    reply(&resp)
                } else {
                    status(NOT_FOUND, "cannot find tag")
                }
            }
            Err(e) => status(INVALID_ARGUMENT, &e.to_string()),
        },
        "OverrideBalancerTarget" => match OverrideBalancerTargetRequest::decode(message) {
            Ok(req) => {
                if let Some(b) = router.balancers.get(&req.balancer_tag) {
                    let mut lock = b
                        .override_target
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if req.target.is_empty() {
                        *lock = None;
                    } else {
                        *lock = Some(req.target);
                    }
                    reply(&OverrideBalancerTargetResponse {})
                } else {
                    status(NOT_FOUND, "cannot find tag")
                }
            }
            Err(e) => status(INVALID_ARGUMENT, &e.to_string()),
        },
        _ => status(UNIMPLEMENTED, "unknown method"),
    }
}

async fn handle_observatory(
    method: &str,
    message: Bytes,
    observatory: &Option<Arc<crate::observatory::Observatory>>,
) -> Response<Body> {
    match method {
        "GetOutboundStatus" => match GetOutboundStatusRequest::decode(message) {
            Ok(_) => {
                let status_list = if let Some(obs) = observatory {
                    obs.get_observation()
                        .into_iter()
                        .map(|s| OutboundStatusProto {
                            alive: s.alive,
                            delay: s.delay,
                            last_error_reason: s.last_error_reason,
                            outbound_tag: s.outbound_tag,
                            last_seen_time: s.last_seen_time,
                            last_try_time: s.last_try_time,
                            health_ping: s.health_ping.map(|h| HealthPingMeasurementResultProto {
                                all: h.all,
                                fail: h.fail,
                                deviation: h.deviation,
                                average: h.average,
                                max: h.max,
                                min: h.min,
                            }),
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let resp = GetOutboundStatusResponse {
                    status: Some(ObservationResultProto {
                        status: status_list,
                    }),
                };
                reply(&resp)
            }
            Err(e) => status(INVALID_ARGUMENT, &e.to_string()),
        },
        _ => status(UNIMPLEMENTED, "unknown method"),
    }
}

fn handle_stats(method: &str, message: Bytes) -> Response<Body> {
    let stats = stats::get();
    match method {
        "QueryStats" => {
            let Ok(r) = QueryStatsRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let stat = stats
                .query(&r.pattern, r.reset)
                .into_iter()
                .map(|(name, value)| Stat { name, value })
                .collect();
            reply(&QueryStatsResponse { stat })
        }
        "GetStats" => {
            let Ok(r) = GetStatsRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            match stats.get_counter(&r.name, r.reset) {
                Some(value) => reply(&GetStatsResponse {
                    stat: Some(Stat {
                        name: r.name,
                        value,
                    }),
                }),
                None => status(NOT_FOUND, &format!("{} not found.", r.name)),
            }
        }
        "GetSysStats" => reply(&SysStatsResponse {
            num_goroutine: 0,
            uptime: stats.uptime_secs(),
        }),
        "GetUsersStats" => {
            let Ok(r) = GetUsersStatsRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let users = stats
                .online_users()
                .into_iter()
                .map(|(email, ips)| {
                    let traffic = r.include_traffic.then(|| TrafficUserStat {
                        uplink: stats
                            .get_counter(&format!("user>>>{email}>>>traffic>>>uplink"), r.reset)
                            .unwrap_or(0),
                        downlink: stats
                            .get_counter(&format!("user>>>{email}>>>traffic>>>downlink"), r.reset)
                            .unwrap_or(0),
                    });
                    UserStat {
                        email,
                        ips: ips
                            .into_iter()
                            .map(|(ip, last_seen)| OnlineIpEntry { ip, last_seen })
                            .collect(),
                        traffic,
                    }
                })
                .collect();
            reply(&GetUsersStatsResponse { users })
        }
        "GetStatsOnline" | "GetStatsOnlineIpList" => {
            let Ok(r) = GetStatsRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            // Xray names these "user>>>EMAIL>>>online".
            let email = r
                .name
                .strip_prefix("user>>>")
                .and_then(|n| n.strip_suffix(">>>online"))
                .unwrap_or(&r.name);
            let Some((_, ips)) = stats.online_users().into_iter().find(|(e, _)| e == email) else {
                return status(NOT_FOUND, &format!("{} not found.", r.name));
            };
            if method == "GetStatsOnline" {
                reply(&GetStatsResponse {
                    stat: Some(Stat {
                        name: r.name,
                        value: ips.len() as i64,
                    }),
                })
            } else {
                reply(&GetStatsOnlineIpListResponse {
                    name: r.name,
                    ips: ips.into_iter().collect(),
                })
            }
        }
        "GetAllOnlineUsers" => {
            let users = stats
                .online_users()
                .into_iter()
                .map(|(email, _)| format!("user>>>{email}>>>online"))
                .collect();
            reply(&GetAllOnlineUsersResponse { users })
        }
        _ => status(UNIMPLEMENTED, "unknown method"),
    }
}

async fn handle_handler(
    method: &str,
    message: Bytes,
    inbound_manager: &Arc<InboundManager>,
) -> Response<Body> {
    match method {
        "AlterInbound" => {
            let Ok(r) = AlterInboundRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let Some(ctx) = inbound_manager.get_ctx(&r.tag) else {
                return missing_handler(&r.tag);
            };
            let operation = r.operation.unwrap_or_default();
            let result = match operation.r#type.as_str() {
                ADD_USER => AddUserOperation::decode(operation.value)
                    .map_err(|e| e.to_string())
                    .and_then(|op| add_user_to_inbound(op.user.unwrap_or_default(), &ctx)),
                REMOVE_USER => RemoveUserOperation::decode(operation.value)
                    .map_err(|e| e.to_string())
                    .and_then(|op| ctx.remove_user(&op.email)),
                other => Err(format!("unknown operation {other:?}")),
            };
            match result {
                Ok(()) => {
                    log::info(format!(
                        "api: {} on inbound {:?}",
                        operation.r#type.rsplit('.').next().unwrap_or_default(),
                        r.tag
                    ));
                    reply(&Empty {})
                }
                Err(e) => status(UNKNOWN, &e),
            }
        }
        "GetInboundUsers" | "GetInboundUsersCount" => {
            let Ok(r) = GetInboundUserRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let Some(ctx) = inbound_manager.get_ctx(&r.tag) else {
                return missing_handler(&r.tag);
            };
            let users: Vec<_> = ctx
                .users()
                .into_iter()
                .filter(|u| r.email.is_empty() || u.email.eq_ignore_ascii_case(&r.email))
                .collect();
            if method == "GetInboundUsersCount" {
                return reply(&GetInboundUsersCountResponse {
                    count: users.len() as i64,
                });
            }
            let users = users.into_iter().map(protocol_user).collect();
            reply(&GetInboundUserResponse { users })
        }
        "AddInbound" => {
            let Ok(r) = AddInboundRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let Some(inbound_cfg) = r.inbound else {
                return status(INVALID_ARGUMENT, "missing inbound");
            };
            let tag = inbound_cfg.tag;
            if inbound_manager.contains(&tag) {
                return status(UNKNOWN, &format!("handler already exists: {tag}"));
            }
            let (port, listen, sniffing, transport) =
                if let Some(rec) = inbound_cfg.receiver_settings {
                    let rec = ReceiverConfig::decode(rec.value).unwrap_or(ReceiverConfig {
                        port_list: None,
                        listen: None,
                        stream_settings: None,
                        receive_original_destination: false,
                        sniffing_settings: None,
                    });
                    let port = rec
                        .port_list
                        .and_then(|p| p.range.first().map(|r| r.from as u16))
                        .unwrap_or(0);
                    let listen = if let Some(l) = rec.listen {
                        if let Some(d) = l.domain {
                            d
                        } else if let Some(ip) = l.ip {
                            if ip.len() == 4 {
                                format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                            } else {
                                "127.0.0.1".into()
                            }
                        } else {
                            "127.0.0.1".into()
                        }
                    } else {
                        "127.0.0.1".into()
                    };
                    let sniffing = if let Some(s) = rec.sniffing_settings {
                        let http = s
                            .destination_override
                            .iter()
                            .any(|d| d.eq_ignore_ascii_case("http"));
                        let tls = s
                            .destination_override
                            .iter()
                            .any(|d| d.eq_ignore_ascii_case("tls"));
                        let fakedns = s
                            .destination_override
                            .iter()
                            .any(|d| d.eq_ignore_ascii_case("fakedns"));
                        let fakedns_other = s
                            .destination_override
                            .iter()
                            .any(|d| d.eq_ignore_ascii_case("fakedns+others"));
                        crate::vless::Sniffing {
                            http: s.enabled && (http || s.destination_override.is_empty()),
                            tls: s.enabled && (tls || s.destination_override.is_empty()),
                            route_only: s.route_only,
                            quic: false,
                            fakedns: s.enabled && fakedns,
                            fakedns_other: s.enabled && fakedns_other,
                            domains_excluded: std::sync::Arc::new(Vec::new()),
                            metadata_only: false,
                        }
                    } else {
                        crate::vless::Sniffing::default()
                    };
                    let transport = match rec
                        .stream_settings
                        .as_ref()
                        .map(|s| s.protocol_name.as_str())
                    {
                        Some("ws") => {
                            crate::config::InboundTransport::Websocket(crate::ws::WsSettings {
                                path: "/".into(),
                                host: None,
                            })
                        }
                        Some("grpc") => {
                            crate::config::InboundTransport::Grpc(crate::grpc::GrpcSettings {
                                service_name: String::new(),
                                multi_mode: false,
                                authority: None,
                            })
                        }
                        Some("httpupgrade") => crate::config::InboundTransport::HttpUpgrade(
                            crate::httpupgrade::HttpUpgradeSettings {
                                path: "/".into(),
                                host: None,
                            },
                        ),
                        _ => crate::config::InboundTransport::Tcp,
                    };
                    (port, listen, sniffing, transport)
                } else {
                    (
                        0,
                        "127.0.0.1".into(),
                        crate::vless::Sniffing::default(),
                        crate::config::InboundTransport::Tcp,
                    )
                };
            let proxy_type = inbound_cfg
                .proxy_settings
                .as_ref()
                .map(|p| p.r#type.as_str())
                .unwrap_or_default();
            let protocol = if proxy_type.contains("trojan") {
                crate::config::InboundProtocol::Trojan
            } else if proxy_type.contains("vmess") {
                crate::config::InboundProtocol::Vmess
            } else if proxy_type.contains("shadowsocks") {
                crate::config::InboundProtocol::Shadowsocks
            } else if proxy_type.contains("dokodemo") {
                crate::config::InboundProtocol::Dokodemo
            } else if proxy_type.contains("socks") {
                crate::config::InboundProtocol::Socks
            } else if proxy_type.contains("http") {
                crate::config::InboundProtocol::Http
            } else if proxy_type.contains("hysteria") {
                crate::config::InboundProtocol::Hysteria
            } else {
                crate::config::InboundProtocol::Vless
            };
            let mut parsed_users = Vec::new();
            let mut parsed_ss_users = Vec::new();
            let mut parsed_hysteria_users = Vec::new();
            let mut ss_method = None;
            let mut ss_pass = None;
            if let Some(ref ps) = inbound_cfg.proxy_settings {
                if let Ok(u_cfg) = ProxyUsersConfig::decode(ps.value.clone()) {
                    for u in u_cfg.users {
                        let email = u.email.clone();
                        let account = u.account.unwrap_or_default();
                        match account.r#type.as_str() {
                            VLESS_ACCOUNT | VMESS_ACCOUNT => {
                                if let Ok(acc) = VlessAccount::decode(account.value) {
                                    parsed_users.push(InboundUser {
                                        id: user_id(&acc.id),
                                        hash: crate::trojan::trojan_password_hash(&acc.id),
                                        email,
                                        level: u.level,
                                        flow: acc.flow,
                                        reverse: None,
                                    });
                                }
                            }
                            TROJAN_ACCOUNT => {
                                if let Ok(acc) = TrojanAccount::decode(account.value) {
                                    parsed_users.push(InboundUser {
                                        id: user_id(&acc.password),
                                        hash: crate::trojan::trojan_password_hash(&acc.password),
                                        email,
                                        level: u.level,
                                        flow: String::new(),
                                        reverse: None,
                                    });
                                }
                            }
                            SHADOWSOCKS_ACCOUNT => {
                                if let Ok(acc) = ShadowsocksAccount::decode(account.value) {
                                    let m_name = match CipherType::try_from(acc.cipher_type) {
                                        Ok(CipherType::Aes128Gcm) => "aes-128-gcm",
                                        Ok(CipherType::Aes256Gcm) => "aes-256-gcm",
                                        Ok(CipherType::Chacha20Poly1305) => {
                                            "chacha20-ietf-poly1305"
                                        }
                                        Ok(CipherType::Xchacha20Poly1305) => {
                                            "xchacha20-ietf-poly1305"
                                        }
                                        _ => "aes-256-gcm",
                                    };
                                    if let Ok(m) = xray_proxy::shadowsocks::aead2017::Method::new(
                                        m_name,
                                        &acc.password,
                                    ) {
                                        parsed_ss_users.push(crate::config::ShadowsocksUser {
                                            email,
                                            method: crate::config::ShadowsocksMethod::Aead2017(
                                                Arc::new(m),
                                            ),
                                            level: u.level,
                                        });
                                        ss_method = Some(m_name.to_owned());
                                        ss_pass = Some(acc.password);
                                    }
                                }
                            }
                            HYSTERIA_ACCOUNT | HYSTERIA_ACCOUNT_ALT => {
                                if let Ok(acc) = HysteriaAccount::decode(account.value) {
                                    parsed_hysteria_users.push(crate::vless::HysteriaUser {
                                        auth: acc.auth,
                                        email,
                                        level: u.level,
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            let inbound = crate::config::Inbound {
                tag: tag.clone(),
                listen,
                port,
                protocol,
                users: parsed_users,
                shadowsocks_users: parsed_ss_users,
                shadowsocks_top_method: ss_method,
                shadowsocks_top_password: ss_pass,
                fallbacks: Vec::new(),
                socks_auth: xray_proxy::inbound::SocksInboundAuth::NoAuth,
                udp: true,
                sniffing,
                dokodemo: None,
                http_obfs: None,
                tls: None,
                reality: None,
                transport,
                accept_proxy_protocol: crate::proxy_proto::ProxyProtocolAccept::None,
                hysteria_users: parsed_hysteria_users,
                hysteria_salamander: None,
                hysteria_gecko: None,
                hysteria_udp_idle_timeout: None,
                has_udphop: false,
                vless_encryption: None,
                sockopt: None,
                quic_params: None,
            };
            match crate::start_inbound(&inbound, None, inbound_manager.router().clone()).await {
                Ok((ctx, tcp_abort, udp_abort)) => {
                    let _ = inbound_manager.add_entry(tag, ctx, tcp_abort, udp_abort);
                    reply(&AddInboundResponse {})
                }
                Err(e) => status(UNKNOWN, &e),
            }
        }
        "RemoveInbound" => {
            let Ok(r) = RemoveInboundRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            if !inbound_manager.remove(&r.tag) {
                return missing_handler(&r.tag);
            }
            reply(&RemoveInboundResponse {})
        }
        "AddOutbound" => {
            let Ok(r) = AddOutboundRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let Some(outbound) = r.outbound else {
                return status(INVALID_ARGUMENT, "missing outbound");
            };
            let tag = outbound.tag;
            let proxy_type = outbound
                .proxy_settings
                .as_ref()
                .map(|p| p.r#type.as_str())
                .unwrap_or_default();
            let action = if proxy_type.contains("freedom") {
                crate::routing::Action::Direct(crate::routing::FreedomStrategy::AsIs.into())
            } else if proxy_type.contains("blackhole") {
                crate::routing::Action::Block(crate::routing::BlockAction::Drop)
            } else {
                crate::routing::Action::Direct(crate::routing::FreedomStrategy::AsIs.into())
            };
            inbound_manager.router().add_outbound(tag, action);
            reply(&AddOutboundResponse {})
        }
        "RemoveOutbound" => {
            let Ok(r) = RemoveOutboundRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            if !inbound_manager.router().remove_outbound(&r.tag) {
                return missing_handler(&r.tag);
            }
            reply(&RemoveOutboundResponse {})
        }
        _ => status(UNIMPLEMENTED, "unknown method"),
    }
}

// 3x-ui treats "not found" as an already absent handler.
fn missing_handler(tag: &str) -> Response<Body> {
    status(
        UNKNOWN,
        &format!("failed to get handler: {tag} > handler not found: {tag}"),
    )
}

fn add_user_to_inbound(user: ProtocolUser, ctx: &Context) -> Result<(), String> {
    let account = user.account.unwrap_or_default();
    match account.r#type.as_str() {
        VLESS_ACCOUNT => {
            let account = VlessAccount::decode(account.value).map_err(|e| e.to_string())?;
            if !account.encryption.is_empty() && account.encryption != "none" {
                return Err("VLESS encryption is not supported".into());
            }
            if !matches!(account.flow.as_str(), "" | crate::config::VISION_FLOW) {
                return Err(format!(
                    r#"VLESS users: "flow" doesn't support "{}" in this version"#,
                    account.flow
                ));
            }
            ctx.add_user(InboundUser {
                id: user_id(&account.id),
                hash: crate::trojan::trojan_password_hash(&account.id),
                email: user.email,
                level: user.level,
                flow: account.flow,
                reverse: None,
            })
        }
        TROJAN_ACCOUNT => {
            let account = TrojanAccount::decode(account.value).map_err(|e| e.to_string())?;
            ctx.add_user(InboundUser {
                id: user_id(&account.password),
                hash: crate::trojan::trojan_password_hash(&account.password),
                email: user.email,
                level: user.level,
                flow: String::new(),
                reverse: None,
            })
        }
        VMESS_ACCOUNT => {
            let account = VmessAccount::decode(account.value).map_err(|e| e.to_string())?;
            ctx.add_user(InboundUser {
                id: user_id(&account.id),
                hash: crate::trojan::trojan_password_hash(&account.id),
                email: user.email,
                level: user.level,
                flow: String::new(),
                reverse: None,
            })
        }
        SHADOWSOCKS_ACCOUNT => {
            let account = ShadowsocksAccount::decode(account.value).map_err(|e| e.to_string())?;
            let top = ctx
                .ss_method
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let method_name = match CipherType::try_from(account.cipher_type) {
                Ok(CipherType::Aes128Gcm) => "aes-128-gcm",
                Ok(CipherType::Aes256Gcm) => "aes-256-gcm",
                Ok(CipherType::Chacha20Poly1305) => "chacha20-ietf-poly1305",
                Ok(CipherType::Xchacha20Poly1305) => "xchacha20-ietf-poly1305",
                _ => match &top {
                    Some(m) => m.as_str(),
                    None => return Err(format!("unknown cipher_type {}", account.cipher_type)),
                },
            };
            let m = xray_proxy::shadowsocks::aead2017::Method::new(method_name, &account.password)
                .map_err(|e| format!("shadowsocks auth: {e}"))?;
            ctx.add_ss_user(
                user.email.clone(),
                crate::config::ShadowsocksUser {
                    method: crate::config::ShadowsocksMethod::Aead2017(Arc::new(m)),
                    email: user.email,
                    level: user.level,
                },
            )
        }
        SHADOWSOCKS_2022_ACCOUNT => {
            let account =
                Shadowsocks2022Account::decode(account.value).map_err(|e| e.to_string())?;
            let top_method = ctx
                .ss_method
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .unwrap_or_else(|| "2022-blake3-aes-128-gcm".to_string());
            let top_pass = ctx
                .ss_password
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .unwrap_or_default();
            let full_key = if top_pass.is_empty() {
                account.key
            } else {
                format!("{top_pass}:{}", account.key)
            };
            let m = xray_proxy::shadowsocks2022::Method::new(&top_method, &full_key)
                .map_err(|e| format!("shadowsocks 2022 auth: {e}"))?;
            ctx.add_ss_user(
                user.email.clone(),
                crate::config::ShadowsocksUser {
                    method: crate::config::ShadowsocksMethod::Ss2022(Arc::new(m)),
                    email: user.email,
                    level: user.level,
                },
            )
        }
        HYSTERIA_ACCOUNT | HYSTERIA_ACCOUNT_ALT => {
            let account = HysteriaAccount::decode(account.value).map_err(|e| e.to_string())?;
            ctx.add_hysteria_user(crate::vless::HysteriaUser {
                auth: account.auth,
                email: user.email,
                level: user.level,
            })
        }
        other => Err(format!("account type {other:?} is not supported")),
    }
}

fn protocol_user(user: InboundUser) -> ProtocolUser {
    let account = VlessAccount {
        id: uuid::Uuid::from_bytes(user.id).to_string(),
        encryption: "none".into(),
        ..Default::default()
    };
    ProtocolUser {
        level: user.level,
        email: user.email,
        account: Some(TypedMessage {
            r#type: VLESS_ACCOUNT.into(),
            value: account.encode_to_vec().into(),
        }),
    }
}

/// Strips the 5-byte gRPC length prefix; compressed messages are rejected.
fn unframe(mut body: Bytes) -> Option<Bytes> {
    if body.len() < 5 || body[0] != 0 {
        return None;
    }
    body.advance(1);
    let len = body.get_u32() as usize;
    (body.len() == len).then_some(body)
}

fn reply(message: &impl Message) -> Response<Body> {
    let mut data = BytesMut::with_capacity(5 + message.encoded_len());
    data.put_u8(0);
    data.put_u32(message.encoded_len() as u32);
    message
        .encode(&mut data)
        .unwrap_or_else(|_| unreachable!("buffer reserved"));
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    let frames = [
        Ok(Frame::data(data.freeze())),
        Ok(Frame::trailers(trailers)),
    ];
    let body = StreamBody::new(futures_util::stream::iter(frames));
    grpc_response(BodyExt::boxed(body), None)
}

/// A trailers-only error response.
fn status(code: u8, message: &str) -> Response<Body> {
    grpc_response(
        Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed(),
        Some((code, message)),
    )
}

fn grpc_response(body: Body, error: Option<(u8, &str)>) -> Response<Body> {
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert("content-type", HeaderValue::from_static("application/grpc"));
    if let Some((code, message)) = error {
        headers.insert("grpc-status", HeaderValue::from(u16::from(code)));
        if let Ok(value) = HeaderValue::from_str(
            &message.replace(|c: char| !c.is_ascii_graphic() && c != ' ', "?"),
        ) {
            headers.insert("grpc-message", value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let message = QueryStatsRequest {
            pattern: "user>>>".into(),
            reset: true,
        };
        let mut framed = BytesMut::new();
        framed.put_u8(0);
        framed.put_u32(message.encoded_len() as u32);
        message.encode(&mut framed).unwrap();
        let inner = unframe(framed.freeze()).unwrap();
        assert_eq!(QueryStatsRequest::decode(inner).unwrap(), message);
        assert!(unframe(Bytes::from_static(&[1, 0, 0, 0, 0])).is_none());
    }

    #[test]
    fn restart_logger_request_decodes() {
        let req = RestartLoggerRequest {};
        let mut framed = BytesMut::new();
        framed.put_u8(0);
        framed.put_u32(req.encoded_len() as u32);
        req.encode(&mut framed).unwrap();
        let inner = unframe(framed.freeze()).unwrap();
        assert_eq!(RestartLoggerRequest::decode(inner).unwrap(), req);
        assert!(log::restart().is_ok());
    }

    #[test]
    fn alter_inbound_vmess_and_shadowsocks() {
        let router = Arc::new(
            crate::routing::Router::build(
                &serde_json::json!({
                    "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                    "routing": {"rules": []}
                }),
                &[],
            )
            .unwrap(),
        );
        let ctx = Context {
            tag: "test_in".into(),
            port: 1234,
            users: std::sync::RwLock::new(Vec::new()),
            hysteria_users: std::sync::RwLock::new(Vec::new()),
            ss_users: std::sync::RwLock::new(Vec::new()),
            ss_method: std::sync::RwLock::new(Some("aes-128-gcm".into())),
            ss_password: std::sync::RwLock::new(None),
            router,
            sniffing: Default::default(),
            fallbacks: Vec::new(),
            vmess_filter: Arc::new(std::sync::Mutex::new(
                xray_proxy::vmess::server::AuthIdFilter::default_vmess(),
            )),
            ss2022_salt_pool: Arc::new(std::sync::Mutex::new(
                xray_proxy::shadowsocks2022::SaltPool::default_ss2022(),
            )),
            vless_encryption: None,
        };

        // Add VMess user
        let vmess_acc = VmessAccount {
            id: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            alter_id: 0,
            tests_enabled: String::new(),
        };
        let p_user = ProtocolUser {
            level: 0,
            email: "vmess_user@test".into(),
            account: Some(TypedMessage {
                r#type: VMESS_ACCOUNT.into(),
                value: vmess_acc.encode_to_vec().into(),
            }),
        };
        assert!(add_user_to_inbound(p_user.clone(), &ctx).is_ok());
        // Duplicate VMess user
        let err = add_user_to_inbound(p_user, &ctx).unwrap_err();
        assert!(err.contains("already exists"), "got: {err}");

        // Add Shadowsocks user
        let ss_acc = ShadowsocksAccount {
            password: "password123".into(),
            cipher_type: CipherType::Aes128Gcm as i32,
            iv_check: false,
        };
        let p_user_ss = ProtocolUser {
            level: 0,
            email: "ss_user@test".into(),
            account: Some(TypedMessage {
                r#type: SHADOWSOCKS_ACCOUNT.into(),
                value: ss_acc.encode_to_vec().into(),
            }),
        };
        assert!(add_user_to_inbound(p_user_ss.clone(), &ctx).is_ok());
        // Duplicate SS user
        let err = add_user_to_inbound(p_user_ss, &ctx).unwrap_err();
        assert!(err.contains("already exists"), "got: {err}");

        // Remove users
        assert!(ctx.remove_user("vmess_user@test").is_ok());
        assert!(ctx.remove_user("ss_user@test").is_ok());
        // Remove non-existent user
        let err = ctx.remove_user("nonexistent").unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[tokio::test]
    async fn routing_service_add_remove_list_test_route() {
        let router = Arc::new(crate::routing::Router::build(&serde_json::json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "proxy", "protocol": "freedom"}],
            "routing": {"rules": []}
        }), &[]).unwrap());

        // 1. ListRule should be empty initially
        let req = ListRuleRequest {};
        let resp = handle_router("ListRule", req.encode_to_vec().into(), &router).await;
        assert_eq!(resp.status(), 200);
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let list_resp = ListRuleResponse::decode(unframe(collected).unwrap()).unwrap();
        assert_eq!(list_resp.rules.len(), 0);

        // 2. AddRule with domain rule
        let rule_proto = RoutingRuleProto {
            tag: "proxy".into(),
            rule_tag: "r-google".into(),
            domain: vec![DomainRuleProto {
                custom: Some(DomainProto {
                    r#type: 0,
                    value: "google.com".into(),
                }),
                geosite: None,
            }],
            ..Default::default()
        };
        let cfg_proto = RouterConfigProto {
            rule: vec![rule_proto],
        };
        let add_req = AddRuleRequest {
            config: Some(TypedMessage {
                r#type: "xray.app.router.Config".into(),
                value: cfg_proto.encode_to_vec().into(),
            }),
            should_append: false,
        };
        let resp = handle_router("AddRule", add_req.encode_to_vec().into(), &router).await;
        assert_eq!(resp.status(), 200);

        // 3. ListRule should now have 1 rule
        let resp = handle_router(
            "ListRule",
            ListRuleRequest {}.encode_to_vec().into(),
            &router,
        )
        .await;
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let list_resp = ListRuleResponse::decode(unframe(collected).unwrap()).unwrap();
        assert_eq!(list_resp.rules.len(), 1);
        assert_eq!(list_resp.rules[0].tag, "proxy");
        assert_eq!(list_resp.rules[0].rule_tag, "r-google");

        // 4. TestRoute for google.com should route to "proxy"
        let test_req = TestRouteRequest {
            routing_context: Some(RoutingContext {
                target_domain: "google.com".into(),
                target_port: 80,
                ..Default::default()
            }),
            field_selectors: Vec::new(),
            publish_result: false,
        };
        let resp = handle_router("TestRoute", test_req.encode_to_vec().into(), &router).await;
        assert_eq!(resp.status(), 200);
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let route_ctx = RoutingContext::decode(unframe(collected).unwrap()).unwrap();
        assert_eq!(route_ctx.outbound_tag, "proxy");

        // TestRoute for example.com should fall back to "direct"
        let test_req2 = TestRouteRequest {
            routing_context: Some(RoutingContext {
                target_domain: "example.com".into(),
                target_port: 80,
                ..Default::default()
            }),
            field_selectors: Vec::new(),
            publish_result: false,
        };
        let resp = handle_router("TestRoute", test_req2.encode_to_vec().into(), &router).await;
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let route_ctx2 = RoutingContext::decode(unframe(collected).unwrap()).unwrap();
        assert_eq!(route_ctx2.outbound_tag, "direct");

        // 5. RemoveRule
        let rm_req = RemoveRuleRequest {
            rule_tag: "r-google".into(),
        };
        let resp = handle_router("RemoveRule", rm_req.encode_to_vec().into(), &router).await;
        assert_eq!(resp.status(), 200);

        // Verify rule is gone and route goes to "direct"
        let resp = handle_router("TestRoute", test_req.encode_to_vec().into(), &router).await;
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let route_ctx3 = RoutingContext::decode(unframe(collected).unwrap()).unwrap();
        assert_eq!(route_ctx3.outbound_tag, "direct");
    }

    #[tokio::test]
    async fn handler_service_inbound_outbound_management() {
        let router = Arc::new(
            crate::routing::Router::build(
                &serde_json::json!({
                    "outbounds": [{"tag": "direct", "protocol": "freedom"}],
                    "routing": {"rules": []}
                }),
                &[],
            )
            .unwrap(),
        );
        let inbound_manager = Arc::new(InboundManager::new(router.clone()));

        // Outbound: AddOutbound
        let add_out_req = AddOutboundRequest {
            outbound: Some(OutboundHandlerConfig {
                tag: "dyn_out".into(),
                sender_settings: None,
                proxy_settings: Some(TypedMessage {
                    r#type: "xray.app.proxyman.outbound.FreedomConfig".into(),
                    value: Bytes::new(),
                }),
                expire: 0,
                comment: String::new(),
            }),
        };
        let resp = handle_handler(
            "AddOutbound",
            add_out_req.encode_to_vec().into(),
            &inbound_manager,
        )
        .await;
        assert_eq!(resp.status(), 200);

        // Outbound: RemoveOutbound
        let rm_out_req = RemoveOutboundRequest {
            tag: "dyn_out".into(),
        };
        let resp = handle_handler(
            "RemoveOutbound",
            rm_out_req.encode_to_vec().into(),
            &inbound_manager,
        )
        .await;
        assert_eq!(resp.status(), 200);

        // Outbound: Remove non-existent outbound returns error
        let resp = handle_handler(
            "RemoveOutbound",
            rm_out_req.encode_to_vec().into(),
            &inbound_manager,
        )
        .await;
        assert_eq!(resp.headers().get("grpc-status").unwrap(), "2");

        // Inbound: AddInbound (bind port 0)
        let receiver = ReceiverConfig {
            port_list: Some(PortListProto {
                range: vec![PortRangeProto { from: 0, to: 0 }],
            }),
            listen: Some(IpOrDomainProto {
                ip: Some(Bytes::from_static(&[127, 0, 0, 1])),
                domain: None,
            }),
            stream_settings: None,
            receive_original_destination: false,
            sniffing_settings: None,
        };
        let add_in_req = AddInboundRequest {
            inbound: Some(InboundHandlerConfig {
                tag: "dyn_in".into(),
                receiver_settings: Some(TypedMessage {
                    r#type: "xray.app.proxyman.ReceiverConfig".into(),
                    value: receiver.encode_to_vec().into(),
                }),
                proxy_settings: Some(TypedMessage {
                    r#type: "xray.proxy.vless.inbound.Config".into(),
                    value: Bytes::new(),
                }),
            }),
        };
        let resp = handle_handler(
            "AddInbound",
            add_in_req.encode_to_vec().into(),
            &inbound_manager,
        )
        .await;
        assert_eq!(resp.status(), 200);
        assert!(inbound_manager.contains("dyn_in"));

        // Inbound: Add duplicate inbound returns error
        let resp = handle_handler(
            "AddInbound",
            add_in_req.encode_to_vec().into(),
            &inbound_manager,
        )
        .await;
        assert_eq!(resp.headers().get("grpc-status").unwrap(), "2");

        // Inbound: RemoveInbound
        let rm_in_req = RemoveInboundRequest {
            tag: "dyn_in".into(),
        };
        let resp = handle_handler(
            "RemoveInbound",
            rm_in_req.encode_to_vec().into(),
            &inbound_manager,
        )
        .await;
        assert_eq!(resp.status(), 200);
        assert!(!inbound_manager.contains("dyn_in"));

        // Inbound: Remove non-existent inbound returns error
        let resp = handle_handler(
            "RemoveInbound",
            rm_in_req.encode_to_vec().into(),
            &inbound_manager,
        )
        .await;
        assert_eq!(resp.headers().get("grpc-status").unwrap(), "2");
    }
}
