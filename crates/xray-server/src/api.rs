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
use prost::{Message, Oneof};
use tokio::net::TcpListener;

use crate::config::{user_id, Inbound, InboundProtocol, InboundTransport, User as InboundUser};
use crate::routing::Router;
use crate::vless::Context;
use crate::{log, stats, xhttp::Body};

const STATS: &str = "/xray.app.stats.command.StatsService/";
const HANDLER: &str = "/xray.app.proxyman.command.HandlerService/";
const LOGGER: &str = "/xray.app.log.command.LoggerService/";
const ROUTER: &str = "/xray.app.router.command.RoutingService/";
const OBSERVATORY: &str = "/xray.core.app.observatory.command.ObservatoryService/";
const REFLECTION_V1ALPHA: &str = "/grpc.reflection.v1alpha.ServerReflection/";
const REFLECTION_V1: &str = "/grpc.reflection.v1.ServerReflection/";
const MAX_REFLECTION_MESSAGE: usize = 4 << 20;
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
    #[prost(uint64, tag = "3")]
    pub alloc: u64,
    #[prost(uint64, tag = "5")]
    pub sys: u64,
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
    #[prost(uint32, repeated, tag = "9")]
    pub testseed: Vec<u32>,
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
pub struct ListInboundsRequest {
    #[prost(bool, tag = "1")]
    pub is_only_tags: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct ListInboundsResponse {
    #[prost(message, repeated, tag = "1")]
    pub inbounds: Vec<InboundHandlerConfig>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ListOutboundsRequest {}

#[derive(Clone, PartialEq, Message)]
pub struct ListOutboundsResponse {
    #[prost(message, repeated, tag = "1")]
    pub outbounds: Vec<OutboundHandlerConfig>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AlterOutboundRequest {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(message, optional, tag = "2")]
    pub operation: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, Message)]
#[allow(dead_code)] // Xray has no outbound operation, so this is never sent.
pub struct AlterOutboundResponse {}

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
    #[prost(int32, tag = "1")]
    pub domain_strategy: i32,
    #[prost(message, repeated, tag = "2")]
    pub rule: Vec<RoutingRuleProto>,
    #[prost(message, repeated, tag = "3")]
    pub balancing_rule: Vec<BalancingRuleProto>,
    #[prost(string, tag = "4")]
    pub script: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct BalancingRuleProto {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(string, repeated, tag = "2")]
    pub outbound_selector: Vec<String>,
    #[prost(string, tag = "3")]
    pub strategy: String,
    #[prost(message, optional, tag = "4")]
    pub strategy_settings: Option<TypedMessage>,
    #[prost(string, tag = "5")]
    pub fallback_tag: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RoutingRuleProto {
    #[prost(string, tag = "1")]
    pub tag: String,
    #[prost(string, tag = "12")]
    pub balancing_tag: String,
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
    #[prost(message, repeated, tag = "2")]
    pub transport_settings: Vec<TypedMessage>,
    #[prost(message, repeated, tag = "4")]
    pub security_settings: Vec<TypedMessage>,
    #[prost(bytes = "bytes", optional, tag = "6")]
    pub socket_settings: Option<Bytes>,
    #[prost(message, optional, tag = "8")]
    pub address: Option<IpOrDomainProto>,
    #[prost(uint32, tag = "9")]
    pub port: u32,
    #[prost(message, repeated, tag = "10")]
    pub udp_masks: Vec<TypedMessage>,
    #[prost(message, repeated, tag = "11")]
    pub tcp_masks: Vec<TypedMessage>,
    #[prost(bytes = "bytes", optional, tag = "12")]
    pub quic_params: Option<Bytes>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SniffingConfigProto {
    #[prost(bool, tag = "1")]
    pub enabled: bool,
    #[prost(string, repeated, tag = "2")]
    pub destination_override: Vec<String>,
    #[prost(bytes = "bytes", repeated, tag = "3")]
    pub domains_excluded: Vec<Bytes>,
    #[prost(bool, tag = "4")]
    pub metadata_only: bool,
    #[prost(bool, tag = "5")]
    pub route_only: bool,
    #[prost(bytes = "bytes", repeated, tag = "6")]
    pub ips_excluded: Vec<Bytes>,
}

#[derive(Clone, PartialEq, Message)]
pub struct FallbackProto {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub alpn: String,
    #[prost(string, tag = "3")]
    pub path: String,
    #[prost(string, tag = "4")]
    pub r#type: String,
    #[prost(string, tag = "5")]
    pub dest: String,
    #[prost(uint64, tag = "6")]
    pub xver: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct VlessInboundConfigProto {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<ProtocolUser>,
    #[prost(message, repeated, tag = "2")]
    pub fallbacks: Vec<FallbackProto>,
    #[prost(string, tag = "3")]
    pub decryption: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct TrojanServerConfigProto {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<ProtocolUser>,
    #[prost(message, repeated, tag = "2")]
    pub fallbacks: Vec<FallbackProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct VmessDefaultConfigProto {
    #[prost(uint32, tag = "2")]
    pub level: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct VmessInboundConfigProto {
    #[prost(message, repeated, tag = "1")]
    pub user: Vec<ProtocolUser>,
    #[prost(message, optional, tag = "2")]
    pub default: Option<VmessDefaultConfigProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ShadowsocksServerConfigProto {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<ProtocolUser>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DokodemoConfigProto {
    #[prost(uint32, tag = "2")]
    pub rewrite_port: u32,
    #[prost(map = "string, string", tag = "3")]
    pub port_map: HashMap<String, String>,
    #[prost(bool, tag = "5")]
    pub follow_redirect: bool,
    #[prost(uint32, tag = "6")]
    pub user_level: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct HysteriaServerConfigProto {
    #[prost(message, repeated, tag = "1")]
    pub users: Vec<ProtocolUser>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SocksServerConfigProto {
    #[prost(uint32, tag = "6")]
    pub user_level: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct HttpServerConfigProto {
    #[prost(uint32, tag = "4")]
    pub user_level: u32,
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
pub struct SubscribeRoutingStatsRequest {
    #[prost(string, repeated, tag = "1")]
    pub field_selectors: Vec<String>,
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

impl ServiceType<'_> {
    /// The lowercased `api.services` entry that enables this service.
    fn config_name(&self) -> &'static str {
        match self {
            Self::Stats(_) => "statsservice",
            Self::Handler(_) => "handlerservice",
            Self::Logger(_) => "loggerservice",
            Self::Router(_) => "routingservice",
            Self::Observatory(_) => "observatoryservice",
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Empty {}

// gRPC server reflection (`google.golang.org/grpc/reflection`), which Xray
// registers for `api.services: ["reflectionService"]`. The v1 and v1alpha
// packages have identical wire formats.
#[derive(Clone, PartialEq, Message)]
pub struct ServerReflectionRequest {
    #[prost(string, tag = "1")]
    pub host: String,
    #[prost(
        oneof = "server_reflection_request::MessageRequest",
        tags = "3,4,5,6,7"
    )]
    pub message_request: Option<server_reflection_request::MessageRequest>,
}

pub mod server_reflection_request {
    use super::*;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum MessageRequest {
        #[prost(string, tag = "3")]
        FileByFilename(String),
        #[prost(string, tag = "4")]
        FileContainingSymbol(String),
        #[prost(message, tag = "5")]
        FileContainingExtension(ExtensionRequest),
        #[prost(string, tag = "6")]
        AllExtensionNumbersOfType(String),
        #[prost(string, tag = "7")]
        ListServices(String),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct ExtensionRequest {
    #[prost(string, tag = "1")]
    pub containing_type: String,
    #[prost(int32, tag = "2")]
    pub extension_number: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct ServerReflectionResponse {
    #[prost(string, tag = "1")]
    pub valid_host: String,
    #[prost(message, optional, tag = "2")]
    pub original_request: Option<ServerReflectionRequest>,
    #[prost(
        oneof = "server_reflection_response::MessageResponse",
        tags = "4,5,6,7"
    )]
    pub message_response: Option<server_reflection_response::MessageResponse>,
}

pub mod server_reflection_response {
    use super::*;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum MessageResponse {
        #[prost(message, tag = "4")]
        Files(FileDescriptorResponse),
        #[prost(message, tag = "5")]
        Extensions(ExtensionNumberResponse),
        #[prost(message, tag = "6")]
        Services(ListServiceResponse),
        #[prost(message, tag = "7")]
        Error(ErrorResponse),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct FileDescriptorResponse {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub file_descriptor_proto: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ExtensionNumberResponse {
    #[prost(string, tag = "1")]
    pub base_type_name: String,
    #[prost(int32, repeated, tag = "2")]
    pub extension_number: Vec<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ListServiceResponse {
    #[prost(message, repeated, tag = "1")]
    pub service: Vec<ServiceResponse>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ServiceResponse {
    #[prost(string, tag = "1")]
    pub name: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ErrorResponse {
    #[prost(int32, tag = "1")]
    pub error_code: i32,
    #[prost(string, tag = "2")]
    pub error_message: String,
}

/// Xray's registered services, as reflection lists them.
const REGISTERED_SERVICES: &[(&str, &str)] = &[
    ("statsservice", "xray.app.stats.command.StatsService"),
    ("handlerservice", "xray.app.proxyman.command.HandlerService"),
    ("loggerservice", "xray.app.log.command.LoggerService"),
    ("routingservice", "xray.app.router.command.RoutingService"),
    (
        "observatoryservice",
        "xray.core.app.observatory.command.ObservatoryService",
    ),
];

static DESCRIPTOR_FILES: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();

fn descriptor_files() -> &'static [Vec<u8>] {
    DESCRIPTOR_FILES.get_or_init(|| {
        #[derive(Clone, PartialEq, Message)]
        struct FileDescriptorSet {
            #[prost(bytes = "vec", repeated, tag = "1")]
            file: Vec<Vec<u8>>,
        }
        FileDescriptorSet::decode(include_bytes!("api_descriptor.bin").as_slice())
            .map(|set| set.file)
            .unwrap_or_default()
    })
}

pub struct InboundManager {
    inbounds: RwLock<HashMap<String, InboundEntry>>,
    router: Arc<Router>,
}

pub struct InboundEntry {
    pub ctx: Arc<Context>,
    pub tcp_abort: Option<tokio::task::AbortHandle>,
    pub udp_abort: Option<tokio::task::AbortHandle>,
    pub inbound: Inbound,
}

/// The protobuf name Xray registers for an inbound protocol's server config.
fn inbound_proxy_type_name(protocol: InboundProtocol) -> &'static str {
    match protocol {
        InboundProtocol::Vless => "xray.proxy.vless.inbound.Config",
        InboundProtocol::Trojan => "xray.proxy.trojan.ServerConfig",
        InboundProtocol::Vmess => "xray.proxy.vmess.inbound.Config",
        InboundProtocol::Socks => "xray.proxy.socks.ServerConfig",
        InboundProtocol::Http => "xray.proxy.http.ServerConfig",
        InboundProtocol::Shadowsocks => "xray.proxy.shadowsocks.ServerConfig",
        InboundProtocol::Dokodemo => "xray.proxy.dokodemo.Config",
        InboundProtocol::Hysteria => "xray.proxy.hysteria.ServerConfig",
        InboundProtocol::Wireguard => "xray.proxy.wireguard.DeviceConfig",
        InboundProtocol::Masque => "xray.proxy.masque.ServerConfig",
    }
}

fn protocol_user_from_config(user: &crate::config::User) -> ProtocolUser {
    let account = VlessAccount {
        id: uuid::Uuid::from_bytes(user.id).to_string(),
        flow: user.flow.clone(),
        encryption: "none".into(),
        testseed: user.testseed.to_vec(),
    };
    ProtocolUser {
        level: user.level,
        email: user.email.clone(),
        account: Some(TypedMessage {
            r#type: VLESS_ACCOUNT.into(),
            value: account.encode_to_vec().into(),
        }),
    }
}

fn fallback_to_proto(f: &crate::config::Fallback) -> FallbackProto {
    FallbackProto {
        name: f.name.clone(),
        alpn: f.alpn.clone(),
        path: f.path.clone(),
        r#type: String::new(),
        dest: format!("{}", f.dest),
        xver: u64::from(f.xver),
    }
}

fn serialize_proxy_settings(inbound: &Inbound) -> (String, Vec<u8>) {
    let type_name = inbound_proxy_type_name(inbound.protocol).to_string();
    let mut buf = Vec::new();
    match inbound.protocol {
        InboundProtocol::Vless => {
            let users = inbound
                .users
                .iter()
                .map(protocol_user_from_config)
                .collect();
            let fallbacks = inbound.fallbacks.iter().map(fallback_to_proto).collect();
            let cfg = VlessInboundConfigProto {
                users,
                fallbacks,
                decryption: "none".into(),
            };
            let _ = cfg.encode(&mut buf);
        }
        InboundProtocol::Trojan => {
            let users = inbound
                .users
                .iter()
                .map(|u| {
                    let password = uuid::Uuid::from_bytes(u.id).to_string();
                    let account = TrojanAccount { password };
                    ProtocolUser {
                        level: u.level,
                        email: u.email.clone(),
                        account: Some(TypedMessage {
                            r#type: TROJAN_ACCOUNT.into(),
                            value: account.encode_to_vec().into(),
                        }),
                    }
                })
                .collect();
            let fallbacks = inbound.fallbacks.iter().map(fallback_to_proto).collect();
            let cfg = TrojanServerConfigProto { users, fallbacks };
            let _ = cfg.encode(&mut buf);
        }
        InboundProtocol::Vmess => {
            let user = inbound
                .users
                .iter()
                .map(|u| {
                    let id = uuid::Uuid::from_bytes(u.id).to_string();
                    let account = VmessAccount {
                        id,
                        alter_id: 0,
                        tests_enabled: String::new(),
                    };
                    ProtocolUser {
                        level: u.level,
                        email: u.email.clone(),
                        account: Some(TypedMessage {
                            r#type: VMESS_ACCOUNT.into(),
                            value: account.encode_to_vec().into(),
                        }),
                    }
                })
                .collect();
            let cfg = VmessInboundConfigProto {
                user,
                default: None,
            };
            let _ = cfg.encode(&mut buf);
        }
        InboundProtocol::Shadowsocks => {
            let users = inbound
                .shadowsocks_users
                .iter()
                .map(|u| {
                    let cipher_type = match &u.method {
                        crate::config::ShadowsocksMethod::Aead2017(_) => {
                            CipherType::Aes256Gcm as i32
                        }
                        crate::config::ShadowsocksMethod::Ss2022(_) => CipherType::Aes256Gcm as i32,
                    };
                    let account = ShadowsocksAccount {
                        password: String::new(),
                        cipher_type,
                        iv_check: false,
                    };
                    ProtocolUser {
                        level: u.level,
                        email: u.email.clone(),
                        account: Some(TypedMessage {
                            r#type: SHADOWSOCKS_ACCOUNT.into(),
                            value: account.encode_to_vec().into(),
                        }),
                    }
                })
                .collect();
            let cfg = ShadowsocksServerConfigProto { users };
            let _ = cfg.encode(&mut buf);
        }
        InboundProtocol::Dokodemo => {
            let doko = inbound.dokodemo.as_ref();
            let cfg = DokodemoConfigProto {
                rewrite_port: doko.and_then(|d| d.port).map_or(0, u32::from),
                port_map: doko.map_or_else(HashMap::new, |d| {
                    d.port_map
                        .iter()
                        .map(|(k, (h, p))| {
                            let val = match (h, p) {
                                (Some(h), Some(p)) => format!("{h}:{p}"),
                                (Some(h), None) => format!("{h}:"),
                                (None, Some(p)) => format!(":{p}"),
                                (None, None) => ":".to_string(),
                            };
                            (k.to_string(), val)
                        })
                        .collect()
                }),
                follow_redirect: false,
                user_level: inbound.user_level,
            };
            let _ = cfg.encode(&mut buf);
        }
        InboundProtocol::Hysteria => {
            let users = inbound
                .hysteria_users
                .iter()
                .map(|u| {
                    let account = HysteriaAccount {
                        auth: u.auth.clone(),
                    };
                    ProtocolUser {
                        level: u.level,
                        email: u.email.clone(),
                        account: Some(TypedMessage {
                            r#type: HYSTERIA_ACCOUNT.into(),
                            value: account.encode_to_vec().into(),
                        }),
                    }
                })
                .collect();
            let cfg = HysteriaServerConfigProto { users };
            let _ = cfg.encode(&mut buf);
        }
        InboundProtocol::Socks => {
            let cfg = SocksServerConfigProto {
                user_level: inbound.user_level,
            };
            let _ = cfg.encode(&mut buf);
        }
        InboundProtocol::Http => {
            let cfg = HttpServerConfigProto {
                user_level: inbound.user_level,
            };
            let _ = cfg.encode(&mut buf);
        }
        _ => {}
    }
    (type_name, buf)
}

pub fn inbound_handler_config(inbound: &Inbound) -> InboundHandlerConfig {
    let protocol_name = match &inbound.transport {
        InboundTransport::Tcp => "tcp",
        InboundTransport::Websocket(_) => "websocket",
        InboundTransport::HttpUpgrade(_) => "httpupgrade",
        InboundTransport::Grpc(_) => "grpc",
        InboundTransport::Xhttp(_) => "splithttp",
        InboundTransport::Hysteria => "hysteria",
        InboundTransport::Kcp(_) => "mkcp",
        InboundTransport::Xdrive(_) => "xdrive",
    };
    let security_type = if inbound.tls.is_some() {
        "tls"
    } else if inbound.reality.is_some() {
        "reality"
    } else {
        "none"
    };
    let stream_settings = Some(StreamConfigProto {
        protocol_name: protocol_name.into(),
        security_type: security_type.into(),
        ..Default::default()
    });

    let sniffing_settings = if inbound.sniffing.http
        || inbound.sniffing.tls
        || inbound.sniffing.quic
        || inbound.sniffing.fakedns
        || inbound.sniffing.fakedns_other
    {
        let mut dests = Vec::new();
        if inbound.sniffing.http {
            dests.push("http".into());
        }
        if inbound.sniffing.tls {
            dests.push("tls".into());
        }
        if inbound.sniffing.quic {
            dests.push("quic".into());
        }
        if inbound.sniffing.fakedns || inbound.sniffing.fakedns_other {
            dests.push("fakedns".into());
        }
        Some(SniffingConfigProto {
            enabled: true,
            destination_override: dests,
            metadata_only: inbound.sniffing.metadata_only,
            route_only: inbound.sniffing.route_only,
            ..Default::default()
        })
    } else {
        None
    };

    let receiver = ReceiverConfig {
        port_list: Some(PortListProto {
            range: vec![PortRangeProto {
                from: u32::from(inbound.port),
                to: u32::from(inbound.port),
            }],
        }),
        listen: (!inbound.listen.is_empty()).then(|| IpOrDomainProto {
            ip: None,
            domain: Some(inbound.listen.clone()),
        }),
        stream_settings,
        receive_original_destination: false,
        sniffing_settings,
    };
    let mut value = Vec::new();
    if receiver.encode(&mut value).is_err() {
        value.clear();
    }
    let (proxy_type, proxy_val) = serialize_proxy_settings(inbound);
    InboundHandlerConfig {
        tag: inbound.tag.clone(),
        receiver_settings: Some(TypedMessage {
            r#type: "xray.app.proxyman.ReceiverConfig".into(),
            value: Bytes::from(value),
        }),
        proxy_settings: Some(TypedMessage {
            r#type: proxy_type,
            value: Bytes::from(proxy_val),
        }),
    }
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
        inbound: Inbound,
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
                inbound,
            },
        );
    }

    pub fn configs(&self) -> Vec<InboundHandlerConfig> {
        let map = self
            .inbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut configs: Vec<_> = map
            .values()
            .map(|entry| {
                let mut inbound = entry.inbound.clone();
                inbound.users = entry
                    .ctx
                    .users
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                inbound.shadowsocks_users = entry
                    .ctx
                    .ss_users
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                inbound.hysteria_users = entry
                    .ctx
                    .hysteria_users
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                inbound_handler_config(&inbound)
            })
            .collect();
        configs.sort_by(|a, b| a.tag.cmp(&b.tag));
        configs
    }

    pub fn get_ctx(&self, tag: &str) -> Option<Arc<Context>> {
        let map = self
            .inbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(tag).map(|e| e.ctx.clone())
    }

    pub fn protocol(&self, tag: &str) -> Option<crate::config::InboundProtocol> {
        let map = self
            .inbounds
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(tag).map(|entry| entry.inbound.protocol)
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
        inbound: Inbound,
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
                inbound,
            },
        );
        Ok(())
    }
}

pub async fn serve(
    addr: SocketAddr,
    services: Vec<String>,
    inbound_manager: Arc<InboundManager>,
    router: Arc<Router>,
    observatory: Option<Arc<crate::observatory::Observatory>>,
) -> Result<(), String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to listen on api {addr}: {e}"))?;
    crate::log::info!("api listening on {addr}");
    let services: Arc<[String]> = services.into();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            };
            let inbound_manager = inbound_manager.clone();
            let router = router.clone();
            let observatory = observatory.clone();
            let services = services.clone();
            tokio::spawn(async move {
                let service = service_fn(|req| {
                    let inbound_manager = inbound_manager.clone();
                    let router = router.clone();
                    let observatory = observatory.clone();
                    let services = services.clone();
                    async move {
                        Ok::<_, Infallible>(
                            handle(req, &services, &inbound_manager, &router, &observatory).await,
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
    services: &[String],
    inbound_manager: &Arc<InboundManager>,
    router: &Arc<Router>,
    observatory: &Option<Arc<crate::observatory::Observatory>>,
) -> Response<Body> {
    let path = req.uri().path().to_owned();
    if let Some(method) = path
        .strip_prefix(REFLECTION_V1ALPHA)
        .or_else(|| path.strip_prefix(REFLECTION_V1))
    {
        if !services
            .iter()
            .any(|service| service == "reflectionservice")
        {
            return status(UNIMPLEMENTED, "unknown service");
        }
        if method != "ServerReflectionInfo" {
            return status(UNIMPLEMENTED, "unknown method");
        }
        return handle_reflection(req, services).await;
    }
    if let Some(method) = path.strip_prefix(ROUTER) {
        if method == "SubscribeRoutingStats" {
            if !services.iter().any(|service| service == "routingservice") {
                return status(UNIMPLEMENTED, "unknown service");
            }
            return handle_subscribe_routing_stats(req, router).await;
        }
    }
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
    if !services.iter().any(|s| s == svc.config_name()) {
        return status(UNIMPLEMENTED, "unknown service");
    }
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

fn framed_bytes(message: &impl Message) -> Bytes {
    let mut data = BytesMut::with_capacity(5 + message.encoded_len());
    data.put_u8(0);
    data.put_u32(message.encoded_len() as u32);
    message
        .encode(&mut data)
        .unwrap_or_else(|_| unreachable!("buffer reserved"));
    data.freeze()
}

/// The reflection stream: one request message in, one response message out,
/// for as long as the client keeps the stream open.
async fn handle_reflection(req: Request<Incoming>, services: &[String]) -> Response<Body> {
    let services = services.to_vec();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(8);
    let mut body = req.into_body();
    tokio::spawn(async move {
        let mut buffer = BytesMut::new();
        let mut status = 0u8;
        'read: loop {
            let frame = match body.frame().await {
                None => break,
                Some(Err(e)) => {
                    status = UNKNOWN;
                    let _ = e;
                    break;
                }
                Some(Ok(frame)) => frame,
            };
            if let Some(data) = frame.data_ref() {
                if buffer.len() + data.len() > MAX_REFLECTION_MESSAGE {
                    status = 8; // RESOURCE_EXHAUSTED
                    break;
                }
                buffer.extend_from_slice(data);
            }
            let trailers = frame.is_trailers();
            while buffer.len() >= 5 {
                let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
                if len > MAX_REFLECTION_MESSAGE {
                    status = 8;
                    break 'read;
                }
                if buffer.len() < 5 + len {
                    break;
                }
                let message = buffer.split_to(5 + len);
                if message[0] != 0 {
                    status = INVALID_ARGUMENT;
                    break 'read;
                }
                let reply = reflection_reply(&message[5..], &services);
                if tx
                    .send(Ok(Frame::data(framed_bytes(&reply))))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            if trailers {
                break;
            }
        }
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from(u16::from(status)));
        let _ = tx.send(Ok(Frame::trailers(trailers))).await;
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|frame| (frame, rx))
    });
    let mut response = Response::new(StreamBody::new(stream).boxed());
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/grpc"));
    response
}

fn reflection_reply(data: &[u8], services: &[String]) -> ServerReflectionResponse {
    use server_reflection_request::MessageRequest;
    use server_reflection_response::MessageResponse;

    let Ok(request) = ServerReflectionRequest::decode(data) else {
        return ServerReflectionResponse {
            valid_host: String::new(),
            original_request: None,
            message_response: Some(MessageResponse::Error(ErrorResponse {
                error_code: i32::from(INVALID_ARGUMENT),
                error_message: "bad reflection request".to_owned(),
            })),
        };
    };
    let response = match &request.message_request {
        Some(MessageRequest::ListServices(_)) => {
            let mut names: Vec<String> = REGISTERED_SERVICES
                .iter()
                .filter(|(config_name, _)| services.iter().any(|s| s == config_name))
                .map(|(_, full_name)| (*full_name).to_owned())
                .collect();
            names.push("grpc.reflection.v1alpha.ServerReflection".to_owned());
            names.push("grpc.reflection.v1.ServerReflection".to_owned());
            MessageResponse::Services(ListServiceResponse {
                service: names
                    .into_iter()
                    .map(|name| ServiceResponse { name })
                    .collect(),
            })
        }
        Some(MessageRequest::FileByFilename(_)) | Some(MessageRequest::FileContainingSymbol(_)) => {
            MessageResponse::Files(FileDescriptorResponse {
                file_descriptor_proto: descriptor_files().to_vec(),
            })
        }
        Some(MessageRequest::AllExtensionNumbersOfType(name)) => {
            MessageResponse::Extensions(ExtensionNumberResponse {
                base_type_name: name.clone(),
                extension_number: Vec::new(),
            })
        }
        Some(MessageRequest::FileContainingExtension(_)) => MessageResponse::Error(ErrorResponse {
            error_code: i32::from(NOT_FOUND),
            error_message: "extensions are not supported".to_owned(),
        }),
        None => MessageResponse::Error(ErrorResponse {
            error_code: i32::from(INVALID_ARGUMENT),
            error_message: "empty reflection request".to_owned(),
        }),
    };
    ServerReflectionResponse {
        valid_host: request.host.clone(),
        original_request: Some(request),
        message_response: Some(response),
    }
}

async fn handle_subscribe_routing_stats(
    req: Request<Incoming>,
    router: &Arc<Router>,
) -> Response<Body> {
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
    let Ok(request) = SubscribeRoutingStatsRequest::decode(message) else {
        return status(INVALID_ARGUMENT, "bad request");
    };
    let selectors = request.field_selectors;
    let receiver = router.subscribe_routing_stats();
    let stream = futures_util::stream::unfold(receiver, move |mut receiver| {
        let selectors = selectors.clone();
        async move {
            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        let context = routing_context_for_event(event, &selectors);
                        return Some((Ok(Frame::data(framed_bytes(&context))), receiver));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        }
    });
    let mut response = Response::new(StreamBody::new(stream).boxed());
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/grpc"));
    response
}

fn routing_context_for_event(
    event: crate::routing::RoutingEvent,
    selectors: &[String],
) -> RoutingContext {
    let wants = |field: &str| {
        selectors.is_empty()
            || selectors
                .iter()
                .any(|selector| field.starts_with(selector.as_str()))
    };
    let mut context = RoutingContext::default();
    if wants("inbound") {
        context.inbound_tag = event.inbound;
    }
    if wants("network") {
        context.network = if event.udp {
            Network::Udp as i32
        } else {
            Network::Tcp as i32
        };
    }
    if wants("ip_source") {
        context.source_ips = vec![Bytes::copy_from_slice(&ip_octets(event.source.ip()))];
    }
    if wants("ip_target") {
        if let Some(ip) = event.ip {
            context.target_ips = vec![Bytes::copy_from_slice(&ip_octets(ip))];
        }
    }
    if wants("ip_local") {
        if let Some(ip) = event.local_ip {
            context.local_ips = vec![Bytes::copy_from_slice(&ip_octets(ip))];
        }
    }
    if wants("port_source") {
        context.source_port = u32::from(event.source.port());
    }
    if wants("port_target") {
        context.target_port = u32::from(event.port);
    }
    if wants("port_local") {
        context.local_port = u32::from(event.inbound_port);
    }
    if wants("domain") {
        if let Some(domain) = event.domain {
            context.target_domain = domain;
        }
    }
    if wants("protocol") {
        if let Some(protocol) = event.protocol {
            context.protocol = protocol.to_owned();
        }
    }
    if wants("user") {
        context.user = event.user;
    }
    if wants("attributes") {
        context.attributes = event.attributes.unwrap_or_default();
    }
    if wants("outbound") {
        context.outbound_tag = event.outbound;
    }
    context
}

fn ip_octets(ip: std::net::IpAddr) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

async fn handle_router(method: &str, message: Bytes, router: &Arc<Router>) -> Response<Body> {
    match method {
        "AddRule" => match AddRuleRequest::decode(message) {
            Ok(req) => {
                let config = req.config.unwrap_or_default();
                if config.r#type.contains("xray.app.router.Config") {
                    if let Ok(cfg) = RouterConfigProto::decode(config.value) {
                        if !cfg.balancing_rule.is_empty() {
                            // `Router.balancers` is immutable after build; a
                            // clear error makes 3x-ui restart with the config.
                            return status(
                                UNKNOWN,
                                "routing balancers cannot be changed at runtime; restart the core",
                            );
                        }
                        let strategy = match cfg.domain_strategy {
                            2 => xray_config::RoutingDomainStrategy::IpIfNonMatch,
                            3 => xray_config::RoutingDomainStrategy::IpOnDemand,
                            _ => xray_config::RoutingDomainStrategy::AsIs,
                        };
                        if strategy != router.strategy {
                            return status(
                                UNKNOWN,
                                "routing domainStrategy change requires a restart",
                            );
                        }
                        let mut parsed_rules = Vec::new();
                        for r in cfg.rule {
                            let mut rule_obj = serde_json::Map::new();
                            rule_obj.insert("type".into(), serde_json::json!("field"));
                            if !r.balancing_tag.is_empty() {
                                rule_obj.insert(
                                    "balancerTag".into(),
                                    serde_json::json!(r.balancing_tag),
                                );
                            } else if !r.tag.is_empty() {
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
                                        let ip = match c.ip.len() {
                                            4 => <[u8; 4]>::try_from(&c.ip[..])
                                                .map(std::net::IpAddr::from),
                                            16 => <[u8; 16]>::try_from(&c.ip[..])
                                                .map(std::net::IpAddr::from),
                                            _ => {
                                                return status(
                                                    INVALID_ARGUMENT,
                                                    "invalid IP length",
                                                )
                                            }
                                        };
                                        let Ok(ip) = ip else {
                                            return status(INVALID_ARGUMENT, "invalid IP length");
                                        };
                                        ips.push(format!("{ip}/{}", c.prefix));
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
                                Ok(parsed_rule) => parsed_rules.push(parsed_rule),
                                Err(e) => return status(UNKNOWN, &e),
                            }
                        }
                        if req.should_append {
                            for rule in parsed_rules {
                                router.add_rule(rule, true);
                            }
                        } else {
                            router.set_rules(parsed_rules);
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
                    process_info: None,
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
    handle_stats_inner(stats::get(), method, message)
}

fn handle_stats_inner(stats: &crate::stats::Stats, method: &str, message: Bytes) -> Response<Body> {
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
        // No Go runtime here: tasks stand in for goroutines and the process's
        // anonymous and resident memory for the heap; GC counters stay zero.
        "GetSysStats" => reply(&SysStatsResponse {
            num_goroutine: u32::try_from(
                tokio::runtime::Handle::current()
                    .metrics()
                    .num_alive_tasks(),
            )
            .unwrap_or(u32::MAX),
            alloc: proc_status_kib("RssAnon:") * 1024,
            sys: proc_status_kib("VmRSS:") * 1024,
            uptime: stats.uptime_secs(),
        }),
        "GetUsersStats" => {
            let Ok(r) = GetUsersStatsRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let online = stats.online_users();
            let all_users = stats.all_users();
            let users = all_users
                .into_iter()
                .filter_map(|email| {
                    let ips = online
                        .iter()
                        .find(|(e, _)| e == &email)
                        .map(|(_, ips)| ips.clone())
                        .unwrap_or_default();
                    if !r.include_traffic && ips.is_empty() {
                        return None;
                    }
                    let traffic = r.include_traffic.then(|| TrafficUserStat {
                        uplink: stats
                            .get_counter(&format!("user>>>{email}>>>traffic>>>uplink"), r.reset)
                            .unwrap_or(0),
                        downlink: stats
                            .get_counter(&format!("user>>>{email}>>>traffic>>>downlink"), r.reset)
                            .unwrap_or(0),
                    });
                    Some(UserStat {
                        email,
                        ips: ips
                            .into_iter()
                            .map(|(ip, last_seen)| OnlineIpEntry { ip, last_seen })
                            .collect(),
                        traffic,
                    })
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
            let ips = stats
                .online_users()
                .into_iter()
                .find(|(e, _)| e == email)
                .map(|(_, ips)| ips)
                .unwrap_or_default();
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

/// The runtime protobuf carries one port (3x-ui always sends a single value).
fn receiver_port(rec: &ReceiverConfig) -> Result<u16, String> {
    let ranges = rec
        .port_list
        .as_ref()
        .map(|list| list.range.as_slice())
        .unwrap_or_default();
    if ranges.len() != 1 || ranges[0].from != ranges[0].to {
        return Err("AddInbound needs exactly one port".into());
    }
    u16::try_from(ranges[0].from).map_err(|_| {
        format!(
            "AddInbound port {} is out of range (0-65535)",
            ranges[0].from
        )
    })
}

fn receiver_listen(rec: &ReceiverConfig) -> Result<String, String> {
    let Some(listen) = &rec.listen else {
        return Ok(String::new());
    };
    if let Some(domain) = &listen.domain {
        return Ok(domain.clone());
    }
    let Some(ip) = &listen.ip else {
        return Ok(String::new());
    };
    match ip.len() {
        4 => Ok(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(ip);
            Ok(std::net::Ipv6Addr::from(octets).to_string())
        }
        len => Err(format!(
            "AddInbound listen address has {len} bytes, expected 4 or 16"
        )),
    }
}

/// Rejects proxy settings whose fields this server would silently drop when
/// starting the inbound from the runtime protobuf.
fn check_inbound_proxy_settings(proxy_name: &str, value: &Bytes) -> Result<(), String> {
    match proxy_name {
        "vless" => {
            let config = VlessInboundConfigProto::decode(value.clone())
                .map_err(|e| format!("bad VLESS inbound settings: {e}"))?;
            if !config.decryption.is_empty() && !config.decryption.eq_ignore_ascii_case("none") {
                return Err(format!(
                    "AddInbound does not support VLESS decryption {:?} yet",
                    config.decryption
                ));
            }
            if !config.fallbacks.is_empty() {
                return Err("AddInbound does not support fallbacks yet".into());
            }
        }
        "trojan" => {
            let config = TrojanServerConfigProto::decode(value.clone())
                .map_err(|e| format!("bad Trojan inbound settings: {e}"))?;
            if !config.fallbacks.is_empty() {
                return Err("AddInbound does not support fallbacks yet".into());
            }
        }
        "vmess" => {
            let config = VmessInboundConfigProto::decode(value.clone())
                .map_err(|e| format!("bad VMess inbound settings: {e}"))?;
            if config.default.is_some_and(|default| default.level != 0) {
                return Err(
                    "AddInbound does not support a non-zero VMess default level yet".into(),
                );
            }
        }
        other => {
            return Err(format!(
                "AddInbound does not support proxy type {other:?} yet"
            ))
        }
    }
    Ok(())
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
                    crate::log::info!(
                        "api: {} on inbound {:?}",
                        operation.r#type.rsplit('.').next().unwrap_or_default(),
                        r.tag
                    );
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
            if inbound_manager.protocol(&r.tag) == Some(crate::config::InboundProtocol::Wireguard) {
                // 3x-ui then falls back to a full core restart, which applies
                // the peer removal from the JSON config.
                return status(
                    UNKNOWN,
                    "wireguard user management is not supported at runtime; restart the core",
                );
            }
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
        "ListInbounds" => {
            let Ok(request) = ListInboundsRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let mut inbounds = inbound_manager.configs();
            if request.is_only_tags {
                for config in &mut inbounds {
                    config.receiver_settings = None;
                    config.proxy_settings = None;
                }
            }
            reply(&ListInboundsResponse { inbounds })
        }
        "ListOutbounds" => {
            let Ok(_) = ListOutboundsRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let outbounds = inbound_manager
                .router
                .outbound_summaries()
                .into_iter()
                .map(|(tag, proxy_type)| OutboundHandlerConfig {
                    tag,
                    sender_settings: Some(TypedMessage {
                        r#type: "xray.app.proxyman.SenderConfig".into(),
                        value: Bytes::new(),
                    }),
                    proxy_settings: Some(TypedMessage {
                        r#type: proxy_type.into(),
                        value: Bytes::new(),
                    }),
                    expire: 0,
                    comment: String::new(),
                })
                .collect();
            reply(&ListOutboundsResponse { outbounds })
        }
        "AlterOutbound" => {
            let Ok(request) = AlterOutboundRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            let Some(operation) = request.operation else {
                // Official Xray dereferences the nil operation and panics; a
                // status is the safe equivalent.
                return status(UNKNOWN, "app/proxyman/command: unknown operation");
            };
            if operation.r#type == ADD_USER || operation.r#type == REMOVE_USER {
                // Xray's AddUser/RemoveUser implement only the inbound half of
                // the operation interface, so AlterOutbound rejects them.
                return status(UNKNOWN, "app/proxyman/command: not an outbound operation");
            }
            status(
                UNKNOWN,
                "app/proxyman/command: unknown operation > proto:\u{a0}not found",
            )
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
            let proxy_type = inbound_cfg
                .proxy_settings
                .as_ref()
                .map(|p| p.r#type.as_str())
                .unwrap_or_default();
            // AddInbound receives the runtime protobuf, not the JSON config.
            // TLS, REALITY, fallbacks and transport options live in nested
            // typed messages; rebuilding only part of them would start a
            // listener that differs from the panel. Rejecting makes 3x-ui
            // restart the core with the full JSON config instead.
            let known = ["vless", "vmess", "trojan"];
            let Some(proxy_name) = known.iter().find(|k| proxy_type.contains(*k)) else {
                return status(
                    UNKNOWN,
                    &format!("AddInbound does not support proxy type {proxy_type:?} yet"),
                );
            };
            let Some(receiver) = inbound_cfg.receiver_settings else {
                return status(INVALID_ARGUMENT, "missing receiver settings");
            };
            let rec = match ReceiverConfig::decode(receiver.value) {
                Ok(rec) => rec,
                Err(e) => return status(INVALID_ARGUMENT, &format!("bad receiver settings: {e}")),
            };
            if rec.receive_original_destination {
                return status(
                    UNKNOWN,
                    "AddInbound does not support receiveOriginalDestination yet",
                );
            }
            if let Some(stream) = &rec.stream_settings {
                // The API only rebuilds plain TCP inbounds. Everything else
                // lives in nested typed messages this server does not decode;
                // dropping it silently would start a listener that differs
                // from the panel. An error makes 3x-ui restart the core.
                if !stream.security_type.is_empty()
                    || !matches!(stream.protocol_name.as_str(), "" | "tcp" | "raw")
                {
                    return status(
                        UNKNOWN,
                        &format!(
                            "AddInbound does not support this stream setting yet: {} {}",
                            stream.protocol_name, stream.security_type
                        ),
                    );
                }
                if stream
                    .transport_settings
                    .iter()
                    .any(|settings| !settings.value.is_empty())
                {
                    return status(
                        UNKNOWN,
                        "AddInbound does not support transport settings yet",
                    );
                }
                if !stream.security_settings.is_empty() {
                    return status(UNKNOWN, "AddInbound does not support security settings yet");
                }
                if stream
                    .socket_settings
                    .as_ref()
                    .is_some_and(|settings| !settings.is_empty())
                {
                    return status(UNKNOWN, "AddInbound does not support sockopt yet");
                }
                if stream.address.is_some() || stream.port != 0 {
                    return status(
                        UNKNOWN,
                        "AddInbound does not support stream address or port",
                    );
                }
                if stream
                    .udp_masks
                    .iter()
                    .chain(stream.tcp_masks.iter())
                    .any(|mask| !mask.value.is_empty())
                {
                    return status(UNKNOWN, "AddInbound does not support finalmask yet");
                }
                if stream
                    .quic_params
                    .as_ref()
                    .is_some_and(|params| !params.is_empty())
                {
                    return status(UNKNOWN, "AddInbound does not support quicParams yet");
                }
            }
            let port = match receiver_port(&rec) {
                Ok(port) => port,
                Err(e) => return status(UNKNOWN, &e),
            };
            let listen = match receiver_listen(&rec) {
                Ok(listen) => listen,
                Err(e) => return status(UNKNOWN, &e),
            };
            let sniffing = if let Some(s) = rec.sniffing_settings {
                if !s.domains_excluded.is_empty() || !s.ips_excluded.is_empty() {
                    return status(
                        UNKNOWN,
                        "AddInbound does not support sniffing exclusion lists yet",
                    );
                }
                let http = s
                    .destination_override
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case("http"));
                let tls = s
                    .destination_override
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case("tls"));
                let quic = s
                    .destination_override
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case("quic"));
                let fakedns = s
                    .destination_override
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case("fakedns"));
                let fakedns_other = s
                    .destination_override
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case("fakedns+others"));
                let empty = s.destination_override.is_empty();
                crate::vless::Sniffing {
                    http: s.enabled && (http || empty),
                    tls: s.enabled && (tls || empty),
                    route_only: s.route_only,
                    quic: s.enabled && quic,
                    fakedns: s.enabled && fakedns,
                    fakedns_other: s.enabled && fakedns_other,
                    domains_excluded: std::sync::Arc::new(Vec::new()),
                    ips_excluded: std::sync::Arc::new(Vec::new()),
                    metadata_only: s.metadata_only,
                }
            } else {
                crate::vless::Sniffing::default()
            };
            if let Some(proxy_settings) = &inbound_cfg.proxy_settings {
                if let Err(e) = check_inbound_proxy_settings(proxy_name, &proxy_settings.value) {
                    return status(UNKNOWN, &e);
                }
            }
            let transport = crate::config::InboundTransport::Tcp;
            let protocol = match *proxy_name {
                "trojan" => crate::config::InboundProtocol::Trojan,
                "vmess" => crate::config::InboundProtocol::Vmess,
                _ => crate::config::InboundProtocol::Vless,
            };
            let mut parsed_users = Vec::new();
            if let Some(ref ps) = inbound_cfg.proxy_settings {
                let u_cfg = match ProxyUsersConfig::decode(ps.value.clone()) {
                    Ok(config) => config,
                    Err(e) => {
                        return status(INVALID_ARGUMENT, &format!("bad inbound users: {e}"));
                    }
                };
                for u in u_cfg.users {
                    let email = u.email.clone();
                    let account = u.account.unwrap_or_default();
                    match (protocol, account.r#type.as_str()) {
                        (crate::config::InboundProtocol::Vmess, VMESS_ACCOUNT) => {
                            let Ok(acc) = VmessAccount::decode(account.value) else {
                                return status(INVALID_ARGUMENT, "bad VMess account");
                            };
                            parsed_users.push(InboundUser {
                                id: user_id(&acc.id),
                                hash: crate::trojan::trojan_password_hash(&acc.id),
                                email,
                                level: u.level,
                                flow: String::new(),
                                reverse: None,
                                testseed: xray_proxy::vless::DEFAULT_VISION_SEED,
                            });
                        }
                        (crate::config::InboundProtocol::Vless, VLESS_ACCOUNT) => {
                            let Ok(acc) = VlessAccount::decode(account.value) else {
                                return status(INVALID_ARGUMENT, "bad VLESS account");
                            };
                            if !acc.encryption.is_empty()
                                && !acc.encryption.eq_ignore_ascii_case("none")
                            {
                                return status(
                                    UNKNOWN,
                                    "AddInbound does not support VLESS encryption yet",
                                );
                            }
                            let testseed = if acc.testseed.len() >= 4 {
                                [
                                    acc.testseed[0],
                                    acc.testseed[1],
                                    acc.testseed[2],
                                    acc.testseed[3],
                                ]
                            } else {
                                xray_proxy::vless::DEFAULT_VISION_SEED
                            };
                            parsed_users.push(InboundUser {
                                id: user_id(&acc.id),
                                hash: crate::trojan::trojan_password_hash(&acc.id),
                                email,
                                level: u.level,
                                flow: acc.flow,
                                reverse: None,
                                testseed,
                            });
                        }
                        (crate::config::InboundProtocol::Trojan, TROJAN_ACCOUNT) => {
                            let Ok(acc) = TrojanAccount::decode(account.value) else {
                                return status(INVALID_ARGUMENT, "bad Trojan account");
                            };
                            parsed_users.push(InboundUser {
                                id: user_id(&acc.password),
                                hash: crate::trojan::trojan_password_hash(&acc.password),
                                email,
                                level: u.level,
                                flow: String::new(),
                                reverse: None,
                                testseed: xray_proxy::vless::DEFAULT_VISION_SEED,
                            });
                        }
                        (_, other) => {
                            return status(
                                UNKNOWN,
                                &format!(
                                    "AddInbound does not support account type {other:?} for {:?}",
                                    protocol
                                ),
                            );
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
                shadowsocks_users: Vec::new(),
                shadowsocks_top_method: None,
                shadowsocks_top_password: None,
                fallbacks: Vec::new(),
                socks_auth: xray_proxy::inbound::SocksInboundAuth::NoAuth,
                user_level: 0,
                udp: true,
                sniffing,
                dokodemo: None,
                http_obfs: None,
                tls: None,
                reality: None,
                transport,
                accept_proxy_protocol: crate::proxy_proto::ProxyProtocolAccept::None,
                tcp_masks: None,
                hysteria_users: Vec::new(),
                hysteria_salamander: None,
                hysteria_gecko: None,
                hysteria_udp_idle_timeout: None,
                hysteria_masq: None,
                has_udphop: false,
                vless_encryption: None,
                sockopt: None,
                quic_params: None,
                wireguard: None,
                masque: None,
            };
            match crate::start_inbound(&inbound, None, inbound_manager.router().clone()).await {
                Ok((ctx, tcp_abort, udp_abort)) => {
                    inbound_manager
                        .router()
                        .set_inbound_protocol(&tag, Some(proxy_name));
                    if let Err(e) = inbound_manager.add_entry(
                        tag,
                        ctx,
                        tcp_abort.clone(),
                        udp_abort.clone(),
                        inbound,
                    ) {
                        for handle in [tcp_abort, udp_abort].into_iter().flatten() {
                            handle.abort();
                        }
                        return status(UNKNOWN, &e);
                    }
                    reply(&AddInboundResponse {})
                }
                Err(e) => status(UNKNOWN, &e),
            }
        }
        "RemoveInbound" => {
            let Ok(r) = RemoveInboundRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            // Xray's inbound manager answers an unknown tag with ErrNoClue.
            if r.tag.is_empty() || !inbound_manager.remove(&r.tag) {
                return status(UNKNOWN, NO_CLUE);
            }
            inbound_manager.router().set_inbound_protocol(&r.tag, None);
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
            if inbound_manager
                .router()
                .outbounds
                .read()
                .unwrap()
                .contains_key(&tag)
            {
                return status(UNKNOWN, &format!("existing tag found: {tag}"));
            }
            let action = if proxy_type.contains("freedom") {
                crate::routing::Action::Direct(crate::routing::FreedomStrategy::AsIs.into())
            } else if proxy_type.contains("blackhole") {
                crate::routing::Action::Block(crate::routing::BlockAction::Drop)
            } else {
                // Anything else would silently send traffic direct.
                return status(
                    UNKNOWN,
                    &format!("AddOutbound does not support proxy type {proxy_type:?} yet"),
                );
            };
            if !inbound_manager.router().add_outbound(tag.clone(), action) {
                return status(UNKNOWN, &format!("existing tag found: {tag}"));
            }
            reply(&AddOutboundResponse {})
        }
        "RemoveOutbound" => {
            let Ok(r) = RemoveOutboundRequest::decode(message) else {
                return status(INVALID_ARGUMENT, "bad request");
            };
            // Xray's outbound manager removes an unknown tag as a no-op.
            if r.tag.is_empty() {
                return status(UNKNOWN, NO_CLUE);
            }
            inbound_manager.router().remove_outbound(&r.tag);
            reply(&RemoveOutboundResponse {})
        }
        _ => status(UNIMPLEMENTED, "unknown method"),
    }
}

// 3x-ui treats "not found" as an already absent handler.
fn proc_status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        })
        .unwrap_or(0)
}

const NO_CLUE: &str = "common: not enough information for making a decision";

fn missing_handler(tag: &str) -> Response<Body> {
    status(
        UNKNOWN,
        &format!("failed to get handler: {tag} > handler not found: {tag}"),
    )
}

fn add_user_to_inbound(user: ProtocolUser, ctx: &Context) -> Result<(), String> {
    let email = user.email.clone();
    let level = user.level;
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
            let testseed = if account.testseed.len() >= 4 {
                [
                    account.testseed[0],
                    account.testseed[1],
                    account.testseed[2],
                    account.testseed[3],
                ]
            } else {
                xray_proxy::vless::DEFAULT_VISION_SEED
            };
            ctx.add_user(InboundUser {
                id: user_id(&account.id),
                hash: crate::trojan::trojan_password_hash(&account.id),
                email: user.email,
                level: user.level,
                flow: account.flow,
                reverse: None,
                testseed,
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
                testseed: xray_proxy::vless::DEFAULT_VISION_SEED,
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
                testseed: xray_proxy::vless::DEFAULT_VISION_SEED,
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
    }?;
    crate::stats::get().register_user(&email, level);
    Ok(())
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

    fn receiver_with_port(from: u32, to: u32) -> ReceiverConfig {
        ReceiverConfig {
            port_list: Some(PortListProto {
                range: vec![PortRangeProto { from, to }],
            }),
            listen: None,
            stream_settings: None,
            receive_original_destination: false,
            sniffing_settings: None,
        }
    }

    #[test]
    fn add_inbound_receiver_ports_and_listen() {
        assert_eq!(receiver_port(&receiver_with_port(0, 0)), Ok(0));
        assert_eq!(receiver_port(&receiver_with_port(8443, 8443)), Ok(8443));
        assert!(receiver_port(&receiver_with_port(1, 2)).is_err());
        assert!(receiver_port(&receiver_with_port(70000, 70000)).is_err());

        let mut receiver = receiver_with_port(443, 443);
        receiver.listen = Some(IpOrDomainProto {
            ip: Some(Bytes::from_static(&[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            domain: None,
        });
        assert_eq!(receiver_listen(&receiver).as_deref(), Ok("2001:db8::1"));

        receiver.listen = Some(IpOrDomainProto {
            ip: Some(Bytes::from_static(&[127, 0, 0, 1])),
            domain: None,
        });
        assert_eq!(receiver_listen(&receiver).as_deref(), Ok("127.0.0.1"));

        receiver.listen = Some(IpOrDomainProto {
            ip: Some(Bytes::from_static(&[1, 2, 3])),
            domain: None,
        });
        assert!(receiver_listen(&receiver).is_err());

        receiver.listen = None;
        assert_eq!(receiver_listen(&receiver).as_deref(), Ok(""));
    }

    #[test]
    fn add_inbound_rejects_proxy_settings_it_would_drop() {
        let empty = Bytes::new();
        assert!(check_inbound_proxy_settings("vless", &empty).is_ok());
        assert!(check_inbound_proxy_settings("vmess", &empty).is_ok());
        assert!(check_inbound_proxy_settings("trojan", &empty).is_ok());

        let vless_fallback = VlessInboundConfigProto {
            users: Vec::new(),
            fallbacks: vec![FallbackProto {
                name: String::new(),
                alpn: String::new(),
                path: "/".into(),
                r#type: String::new(),
                dest: 8080u16.to_string(),
                xver: 0,
            }],
            decryption: "none".into(),
        }
        .encode_to_vec();
        assert!(check_inbound_proxy_settings("vless", &vless_fallback.into()).is_err());

        let vmess_default = VmessInboundConfigProto {
            user: Vec::new(),
            default: Some(VmessDefaultConfigProto { level: 1 }),
        }
        .encode_to_vec();
        assert!(check_inbound_proxy_settings("vmess", &vmess_default.into()).is_err());

        let trojan_fallback = TrojanServerConfigProto {
            users: Vec::new(),
            fallbacks: vec![FallbackProto {
                name: String::new(),
                alpn: String::new(),
                path: String::new(),
                r#type: String::new(),
                dest: 8080u16.to_string(),
                xver: 0,
            }],
        }
        .encode_to_vec();
        // Xray's `xray.proxy.trojan.ServerConfig.fallbacks` is field 2.
        assert_eq!(trojan_fallback[0], 0x12);
        assert!(check_inbound_proxy_settings("trojan", &trojan_fallback.into()).is_err());

        assert!(check_inbound_proxy_settings("socks", &empty).is_err());
    }

    #[test]
    fn routing_stats_events_apply_field_selectors() {
        let event = crate::routing::RoutingEvent {
            inbound: "socks-in".into(),
            udp: false,
            source: "203.0.113.5:40000".parse().unwrap(),
            ip: Some("198.51.100.7".parse().unwrap()),
            domain: Some("example.com".into()),
            port: 443,
            protocol: Some("tls"),
            user: "u@example.com".into(),
            attributes: None,
            local_ip: Some("127.0.0.1".parse().unwrap()),
            inbound_port: 1080,
            vless_route: Some(7),
            outbound: "direct".into(),
        };
        let all = routing_context_for_event(event.clone(), &[]);
        assert_eq!(all.inbound_tag, "socks-in");
        assert_eq!(all.network, Network::Tcp as i32);
        assert_eq!(all.source_port, 40000);
        assert_eq!(all.target_port, 443);
        assert_eq!(all.target_domain, "example.com");
        assert_eq!(all.outbound_tag, "direct");

        let only_inbound = routing_context_for_event(event.clone(), &["inbound".into()]);
        assert_eq!(only_inbound.inbound_tag, "socks-in");
        assert!(only_inbound.target_ips.is_empty());
        assert_eq!(only_inbound.target_port, 0);
        assert!(only_inbound.outbound_tag.is_empty());

        let only_ip = routing_context_for_event(event.clone(), &["ip".into()]);
        assert_eq!(only_ip.source_ips.len(), 1);
        assert_eq!(only_ip.target_ips.len(), 1);
        assert_eq!(only_ip.local_ips.len(), 1);
        assert!(only_ip.inbound_tag.is_empty());

        let only_outbound = routing_context_for_event(event, &["outbound".into()]);
        assert_eq!(only_outbound.outbound_tag, "direct");
        assert!(only_outbound.inbound_tag.is_empty());
    }

    #[test]
    fn reflection_lists_only_enabled_services() {
        use server_reflection_request::MessageRequest;
        use server_reflection_response::MessageResponse;

        let request = ServerReflectionRequest {
            host: "api".into(),
            message_request: Some(MessageRequest::ListServices(String::new())),
        };
        let reply = reflection_reply(
            &request.encode_to_vec(),
            &["statsservice".to_owned(), "reflectionservice".to_owned()],
        );
        let Some(MessageResponse::Services(list)) = reply.message_response else {
            panic!("expected a service list");
        };
        let names: Vec<&str> = list.service.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"xray.app.stats.command.StatsService"));
        assert!(names.contains(&"grpc.reflection.v1.ServerReflection"));
        assert!(names.contains(&"grpc.reflection.v1alpha.ServerReflection"));
        assert!(!names.contains(&"xray.app.proxyman.command.HandlerService"));
    }

    #[test]
    fn reflection_returns_the_registered_descriptor_set() {
        use server_reflection_request::MessageRequest;
        use server_reflection_response::MessageResponse;

        let request = ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::FileContainingSymbol(
                "xray.app.stats.command.StatsService".into(),
            )),
        };
        let reply = reflection_reply(&request.encode_to_vec(), &["statsservice".to_owned()]);
        let Some(MessageResponse::Files(files)) = reply.message_response else {
            panic!("expected file descriptors");
        };
        assert!(!files.file_descriptor_proto.is_empty());

        #[derive(Clone, PartialEq, Message)]
        struct FileDescriptorProto {
            #[prost(string, optional, tag = "1")]
            name: Option<String>,
        }
        let names: Vec<String> = files
            .file_descriptor_proto
            .iter()
            .filter_map(|file| FileDescriptorProto::decode(file.as_slice()).ok())
            .filter_map(|file| file.name)
            .collect();
        assert!(names
            .iter()
            .any(|name| name == "app/stats/command/command.proto"));
        assert!(names
            .iter()
            .any(|name| name == "grpc/reflection/v1/reflection.proto"));
    }

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
            vmess_keys: Default::default(),
            ss_users_version: std::sync::atomic::AtomicU64::new(0),
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
        let vmess_count = || crate::vmess::Keys::get(&ctx).users.len();
        let before = vmess_count();
        assert!(add_user_to_inbound(p_user.clone(), &ctx).is_ok());
        assert_eq!(
            vmess_count(),
            before + 1,
            "VMess key cache must see new users"
        );
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
        assert_eq!(
            vmess_count(),
            before,
            "VMess key cache must drop removed users"
        );
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
            ..Default::default()
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

        // Outbound: removing it again is a no-op, as in Xray
        let resp = handle_handler(
            "RemoveOutbound",
            rm_out_req.encode_to_vec().into(),
            &inbound_manager,
        )
        .await;
        assert!(resp.headers().get("grpc-status").is_none_or(|s| s == "0"));

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

    #[tokio::test]
    async fn stats_service_reports_offline_and_online_clients() {
        {
            let _lock = crate::policy::TEST_LOCK.lock().unwrap();
            let cfg = serde_json::json!({
                "stats": {},
                "policy": {
                    "levels": {
                        "0": {
                            "statsUserUplink": true,
                            "statsUserDownlink": true,
                            "statsUserOnline": true
                        }
                    }
                }
            });
            crate::policy::init(crate::policy::PolicyManager::from_config(&cfg));
        }
        let stats: &'static crate::stats::Stats =
            Box::leak(Box::new(crate::stats::Stats::new(crate::stats::Policy {
                enabled: true,
                user_uplink: true,
                user_downlink: true,
                user_online: true,
                ..Default::default()
            })));

        // Register an offline user
        stats.register_user("offline_user@test", 0);

        // 1. GetStatsOnline for offline user returns 0, NOT an error
        let req = GetStatsRequest {
            name: "user>>>offline_user@test>>>online".into(),
            reset: false,
        };
        let resp = handle_stats_inner(stats, "GetStatsOnline", req.encode_to_vec().into());
        assert_eq!(resp.status(), 200);
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let stat_resp = GetStatsResponse::decode(unframe(collected).unwrap()).unwrap();
        assert_eq!(stat_resp.stat.unwrap().value, 0);

        // 2. GetStatsOnlineIpList for offline user returns empty map, NOT an error
        let resp = handle_stats_inner(stats, "GetStatsOnlineIpList", req.encode_to_vec().into());
        assert_eq!(resp.status(), 200);
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let iplist_resp =
            GetStatsOnlineIpListResponse::decode(unframe(collected).unwrap()).unwrap();
        assert!(iplist_resp.ips.is_empty());

        // 3. GetUsersStats with include_traffic: true reports offline users with their counters
        let req = GetUsersStatsRequest {
            reset: false,
            include_traffic: true,
        };
        let resp = handle_stats_inner(stats, "GetUsersStats", req.encode_to_vec().into());
        assert_eq!(resp.status(), 200);
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let users_resp = GetUsersStatsResponse::decode(unframe(collected).unwrap()).unwrap();
        let found = users_resp
            .users
            .iter()
            .find(|u| u.email == "offline_user@test")
            .expect("offline user must be present in GetUsersStats when include_traffic is true");
        assert!(found.ips.is_empty());
        let traffic = found.traffic.as_ref().expect("traffic must be included");
        assert_eq!(traffic.uplink, 0);
        assert_eq!(traffic.downlink, 0);

        // 4. GetUsersStats with include_traffic: false excludes offline users
        let req = GetUsersStatsRequest {
            reset: false,
            include_traffic: false,
        };
        let resp = handle_stats_inner(stats, "GetUsersStats", req.encode_to_vec().into());
        assert_eq!(resp.status(), 200);
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let users_resp = GetUsersStatsResponse::decode(unframe(collected).unwrap()).unwrap();
        assert!(
            users_resp
                .users
                .iter()
                .all(|u| u.email != "offline_user@test"),
            "offline users without active IPs must be excluded when include_traffic is false"
        );

        // 5. When a client connects, online stats and IPs are reported
        stats.register_user("online_user@test", 0);
        let guard = stats.connect("online_user@test", 0, "198.51.100.42".parse().unwrap());
        assert!(guard.is_some());

        let req = GetStatsRequest {
            name: "user>>>online_user@test>>>online".into(),
            reset: false,
        };
        let resp = handle_stats_inner(stats, "GetStatsOnline", req.encode_to_vec().into());
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let stat_resp = GetStatsResponse::decode(unframe(collected).unwrap()).unwrap();
        assert_eq!(stat_resp.stat.unwrap().value, 1);

        drop(guard);
    }

    #[tokio::test]
    async fn list_inbounds_full_payloads_and_tags_only() {
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
        let ctx = Arc::new(Context {
            tag: "vless-in".into(),
            port: 443,
            users: std::sync::RwLock::new(vec![crate::config::User {
                id: [1u8; 16],
                hash: [0u8; 56],
                email: "user1@example.com".into(),
                level: 1,
                flow: crate::config::VISION_FLOW.into(),
                reverse: None,
                testseed: xray_proxy::vless::DEFAULT_VISION_SEED,
            }]),
            hysteria_users: std::sync::RwLock::new(Vec::new()),
            ss_users: std::sync::RwLock::new(Vec::new()),
            ss_method: std::sync::RwLock::new(None),
            ss_password: std::sync::RwLock::new(None),
            router,
            sniffing: crate::vless::Sniffing {
                http: true,
                tls: true,
                quic: false,
                fakedns: false,
                fakedns_other: false,
                route_only: true,
                metadata_only: false,
                domains_excluded: Arc::new(Vec::new()),
                ips_excluded: Arc::new(Vec::new()),
            },
            fallbacks: vec![crate::config::Fallback {
                name: "fb1".into(),
                alpn: "h2".into(),
                path: "/fallback".into(),
                dest: crate::config::FallbackDest::Tcp(
                    crate::vless::Host::Domain("127.0.0.1".into()),
                    8080,
                ),
                xver: 1,
            }],
            vmess_filter: Arc::new(std::sync::Mutex::new(
                xray_proxy::vmess::server::AuthIdFilter::default_vmess(),
            )),
            ss2022_salt_pool: Arc::new(std::sync::Mutex::new(
                xray_proxy::shadowsocks2022::SaltPool::default_ss2022(),
            )),
            vless_encryption: None,
            vmess_keys: Default::default(),
            ss_users_version: std::sync::atomic::AtomicU64::new(0),
        });

        let inbound = crate::config::Inbound {
            tag: "vless-in".into(),
            listen: "0.0.0.0".into(),
            port: 443,
            protocol: InboundProtocol::Vless,
            users: vec![crate::config::User {
                id: [1u8; 16],
                hash: [0u8; 56],
                email: "user1@example.com".into(),
                level: 1,
                flow: crate::config::VISION_FLOW.into(),
                reverse: None,
                testseed: xray_proxy::vless::DEFAULT_VISION_SEED,
            }],
            shadowsocks_users: Vec::new(),
            shadowsocks_top_method: None,
            shadowsocks_top_password: None,
            fallbacks: vec![crate::config::Fallback {
                name: "fb1".into(),
                alpn: "h2".into(),
                path: "/fallback".into(),
                dest: crate::config::FallbackDest::Tcp(
                    crate::vless::Host::Domain("127.0.0.1".into()),
                    8080,
                ),
                xver: 1,
            }],
            socks_auth: xray_proxy::inbound::SocksInboundAuth::NoAuth,
            user_level: 0,
            udp: true,
            sniffing: ctx.sniffing.clone(),
            dokodemo: None,
            http_obfs: None,
            tls: Some(crate::config::TlsSettings {
                cert_pem: Vec::new(),
                key_pem: Vec::new(),
                certificates: Vec::new(),
                alpn: vec!["h2".into()],
                reject_unknown_sni: false,
                server_names: vec!["example.com".into()],
                min_version: Some("1.2".into()),
                max_version: Some("1.3".into()),
                cipher_suites: Vec::new(),
                curve_preferences: Vec::new(),
                ech_server_keys: None,
                ech_config_list: None,
            }),
            reality: None,
            transport: InboundTransport::Tcp,
            accept_proxy_protocol: crate::proxy_proto::ProxyProtocolAccept::None,
            tcp_masks: None,
            hysteria_users: Vec::new(),
            hysteria_salamander: None,
            hysteria_gecko: None,
            hysteria_udp_idle_timeout: None,
            hysteria_masq: None,
            has_udphop: false,
            vless_encryption: None,
            sockopt: None,
            quic_params: None,
            wireguard: None,
            masque: None,
        };

        inbound_manager.insert_initial("vless-in".into(), ctx.clone(), None, None, inbound);

        // 1. ListInbounds with is_only_tags: false
        let req = ListInboundsRequest {
            is_only_tags: false,
        };
        let resp =
            handle_handler("ListInbounds", req.encode_to_vec().into(), &inbound_manager).await;
        assert_eq!(resp.status(), 200);
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let list_resp = ListInboundsResponse::decode(unframe(collected).unwrap()).unwrap();
        assert_eq!(list_resp.inbounds.len(), 1);
        let inb = &list_resp.inbounds[0];
        assert_eq!(inb.tag, "vless-in");

        let rec_msg = inb
            .receiver_settings
            .as_ref()
            .expect("receiver_settings must be present");
        assert_eq!(rec_msg.r#type, "xray.app.proxyman.ReceiverConfig");
        let rec = ReceiverConfig::decode(rec_msg.value.clone()).unwrap();
        let port_range = &rec.port_list.unwrap().range[0];
        assert_eq!(port_range.from, 443);
        assert_eq!(port_range.to, 443);
        let stream = rec.stream_settings.unwrap();
        assert_eq!(stream.protocol_name, "tcp");
        assert_eq!(stream.security_type, "tls");
        let sniff = rec.sniffing_settings.unwrap();
        assert!(sniff.enabled);
        assert_eq!(sniff.destination_override, vec!["http", "tls"]);
        assert!(sniff.route_only);

        let proxy_msg = inb
            .proxy_settings
            .as_ref()
            .expect("proxy_settings must be present");
        assert_eq!(proxy_msg.r#type, "xray.proxy.vless.inbound.Config");
        let vless_cfg = VlessInboundConfigProto::decode(proxy_msg.value.clone()).unwrap();
        assert_eq!(vless_cfg.decryption, "none");
        assert_eq!(vless_cfg.users.len(), 1);
        assert_eq!(vless_cfg.users[0].email, "user1@example.com");
        assert_eq!(vless_cfg.users[0].level, 1);
        assert_eq!(vless_cfg.fallbacks.len(), 1);
        assert_eq!(vless_cfg.fallbacks[0].name, "fb1");
        assert_eq!(vless_cfg.fallbacks[0].alpn, "h2");

        // 2. Dynamic user addition appears in ListInbounds
        let new_user = ProtocolUser {
            level: 2,
            email: "dynamic@example.com".into(),
            account: Some(TypedMessage {
                r#type: VLESS_ACCOUNT.into(),
                value: VlessAccount {
                    id: "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8".into(),
                    flow: String::new(),
                    encryption: "none".into(),
                    testseed: vec![1, 2, 3, 4],
                }
                .encode_to_vec()
                .into(),
            }),
        };
        assert!(add_user_to_inbound(new_user, &ctx).is_ok());

        let req = ListInboundsRequest {
            is_only_tags: false,
        };
        let resp =
            handle_handler("ListInbounds", req.encode_to_vec().into(), &inbound_manager).await;
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let list_resp = ListInboundsResponse::decode(unframe(collected).unwrap()).unwrap();
        let vless_cfg = VlessInboundConfigProto::decode(
            list_resp.inbounds[0]
                .proxy_settings
                .as_ref()
                .unwrap()
                .value
                .clone(),
        )
        .unwrap();
        assert_eq!(vless_cfg.users.len(), 2);
        assert!(vless_cfg
            .users
            .iter()
            .any(|u| u.email == "dynamic@example.com"));

        // 3. ListInbounds with is_only_tags: true
        let req = ListInboundsRequest { is_only_tags: true };
        let resp =
            handle_handler("ListInbounds", req.encode_to_vec().into(), &inbound_manager).await;
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let list_resp = ListInboundsResponse::decode(unframe(collected).unwrap()).unwrap();
        assert_eq!(list_resp.inbounds[0].tag, "vless-in");
        assert!(list_resp.inbounds[0].receiver_settings.is_none());
        assert!(list_resp.inbounds[0].proxy_settings.is_none());
    }
}
