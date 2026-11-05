//! Xray gRPC API subset over cleartext HTTP/2: `StatsService`, which is how
//! 3x-ui reads traffic and online users, and the user operations of
//! `HandlerService`, which let it add and remove clients without a restart.
//! Everything else answers `Unimplemented`, and 3x-ui then restarts the core.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

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
use crate::vless::Context;
use crate::{log, stats, xhttp::Body};

const STATS: &str = "/xray.app.stats.command.StatsService/";
const HANDLER: &str = "/xray.app.proxyman.command.HandlerService/";
const ADD_USER: &str = "xray.app.proxyman.command.AddUserOperation";
const REMOVE_USER: &str = "xray.app.proxyman.command.RemoveUserOperation";
const VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";
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
pub struct Empty {}

type Inbounds = Arc<HashMap<String, Arc<Context>>>;

pub async fn serve(addr: SocketAddr, inbounds: HashMap<String, Arc<Context>>) -> Result<(), String> {
    let inbounds: Inbounds = Arc::new(inbounds);
    let listener = TcpListener::bind(addr).await.map_err(|e| format!("failed to listen on api {addr}: {e}"))?;
    log::info(format!("api listening on {addr}"));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let inbounds = inbounds.clone();
            tokio::spawn(async move {
                let service = service_fn(|req| {
                    let inbounds = inbounds.clone();
                    async move { Ok::<_, Infallible>(handle(req, &inbounds).await) }
                });
                let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream), service).await;
            });
        }
    });
    Ok(())
}

async fn handle(req: Request<Incoming>, inbounds: &Inbounds) -> Response<Body> {
    let path = req.uri().path().to_owned();
    let (handler, method) = match (path.strip_prefix(STATS), path.strip_prefix(HANDLER)) {
        (Some(method), _) => (false, method),
        (_, Some(method)) => (true, method),
        _ => return status(UNIMPLEMENTED, "unknown service"),
    };
    let body = match http_body_util::Limited::new(req.into_body(), MAX_REQUEST).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => return status(INVALID_ARGUMENT, "request too large"),
    };
    let Some(message) = unframe(body) else {
        return status(INVALID_ARGUMENT, "bad grpc frame");
    };
    if handler {
        return handle_handler(method, message, inbounds);
    }
    let stats = stats::get();
    match method {
        "QueryStats" => {
            let Ok(r) = QueryStatsRequest::decode(message) else { return status(INVALID_ARGUMENT, "bad request") };
            let stat = stats.query(&r.pattern, r.reset).into_iter().map(|(name, value)| Stat { name, value }).collect();
            reply(&QueryStatsResponse { stat })
        }
        "GetStats" => {
            let Ok(r) = GetStatsRequest::decode(message) else { return status(INVALID_ARGUMENT, "bad request") };
            match stats.get_counter(&r.name, r.reset) {
                Some(value) => reply(&GetStatsResponse { stat: Some(Stat { name: r.name, value }) }),
                None => status(NOT_FOUND, &format!("{} not found.", r.name)),
            }
        }
        "GetSysStats" => reply(&SysStatsResponse { num_goroutine: 0, uptime: stats.uptime_secs() }),
        "GetUsersStats" => {
            let Ok(r) = GetUsersStatsRequest::decode(message) else { return status(INVALID_ARGUMENT, "bad request") };
            let users = stats
                .online_users()
                .into_iter()
                .map(|(email, ips)| {
                    let traffic = r.include_traffic.then(|| TrafficUserStat {
                        uplink: stats.get_counter(&format!("user>>>{email}>>>traffic>>>uplink"), r.reset).unwrap_or(0),
                        downlink: stats.get_counter(&format!("user>>>{email}>>>traffic>>>downlink"), r.reset).unwrap_or(0),
                    });
                    UserStat { email, ips: ips.into_iter().map(|(ip, last_seen)| OnlineIpEntry { ip, last_seen }).collect(), traffic }
                })
                .collect();
            reply(&GetUsersStatsResponse { users })
        }
        "GetStatsOnline" | "GetStatsOnlineIpList" => {
            let Ok(r) = GetStatsRequest::decode(message) else { return status(INVALID_ARGUMENT, "bad request") };
            // Xray names these "user>>>EMAIL>>>online".
            let email = r.name.strip_prefix("user>>>").and_then(|n| n.strip_suffix(">>>online")).unwrap_or(&r.name);
            let Some((_, ips)) = stats.online_users().into_iter().find(|(e, _)| e == email) else {
                return status(NOT_FOUND, &format!("{} not found.", r.name));
            };
            if method == "GetStatsOnline" {
                reply(&GetStatsResponse { stat: Some(Stat { name: r.name, value: ips.len() as i64 }) })
            } else {
                reply(&GetStatsOnlineIpListResponse { name: r.name, ips: ips.into_iter().collect() })
            }
        }
        "GetAllOnlineUsers" => {
            let users = stats.online_users().into_iter().map(|(email, _)| format!("user>>>{email}>>>online")).collect();
            reply(&GetAllOnlineUsersResponse { users })
        }
        _ => status(UNIMPLEMENTED, "unknown method"),
    }
}

fn handle_handler(method: &str, message: Bytes, inbounds: &Inbounds) -> Response<Body> {
    match method {
        "AlterInbound" => {
            let Ok(r) = AlterInboundRequest::decode(message) else { return status(INVALID_ARGUMENT, "bad request") };
            let Some(ctx) = inbounds.get(&r.tag) else { return missing_handler(&r.tag) };
            let operation = r.operation.unwrap_or_default();
            let result = match operation.r#type.as_str() {
                ADD_USER => AddUserOperation::decode(operation.value)
                    .map_err(|e| e.to_string())
                    .and_then(|op| inbound_user(op.user.unwrap_or_default()))
                    .and_then(|user| ctx.add_user(user)),
                REMOVE_USER => RemoveUserOperation::decode(operation.value).map_err(|e| e.to_string()).and_then(|op| ctx.remove_user(&op.email)),
                other => Err(format!("unknown operation {other:?}")),
            };
            match result {
                Ok(()) => {
                    log::info(format!("api: {} on inbound {:?}", operation.r#type.rsplit('.').next().unwrap_or_default(), r.tag));
                    reply(&Empty {})
                }
                Err(e) => status(UNKNOWN, &e),
            }
        }
        "GetInboundUsers" | "GetInboundUsersCount" => {
            let Ok(r) = GetInboundUserRequest::decode(message) else { return status(INVALID_ARGUMENT, "bad request") };
            let Some(ctx) = inbounds.get(&r.tag) else { return missing_handler(&r.tag) };
            let users: Vec<_> = ctx.users().into_iter().filter(|u| r.email.is_empty() || u.email.eq_ignore_ascii_case(&r.email)).collect();
            if method == "GetInboundUsersCount" {
                return reply(&GetInboundUsersCountResponse { count: users.len() as i64 });
            }
            let users = users.into_iter().map(protocol_user).collect();
            reply(&GetInboundUserResponse { users })
        }
        _ => status(UNIMPLEMENTED, "unknown method"),
    }
}

// 3x-ui treats "not found" as an already absent handler.
fn missing_handler(tag: &str) -> Response<Body> {
    status(UNKNOWN, &format!("failed to get handler: {tag} > handler not found: {tag}"))
}

fn inbound_user(user: ProtocolUser) -> Result<InboundUser, String> {
    let account = user.account.unwrap_or_default();
    if account.r#type != VLESS_ACCOUNT {
        return Err(format!("account type {:?} is not supported, only VLESS", account.r#type));
    }
    let account = VlessAccount::decode(account.value).map_err(|e| e.to_string())?;
    if !account.encryption.is_empty() && account.encryption != "none" {
        return Err("VLESS encryption is not supported".into());
    }
    Ok(InboundUser { id: user_id(&account.id), email: user.email })
}

fn protocol_user(user: InboundUser) -> ProtocolUser {
    let account = VlessAccount { id: uuid::Uuid::from_bytes(user.id).to_string(), encryption: "none".into(), ..Default::default() };
    ProtocolUser {
        level: 0,
        email: user.email,
        account: Some(TypedMessage { r#type: VLESS_ACCOUNT.into(), value: account.encode_to_vec().into() }),
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
    message.encode(&mut data).unwrap_or_else(|_| unreachable!("buffer reserved"));
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    let frames = [Ok(Frame::data(data.freeze())), Ok(Frame::trailers(trailers))];
    let body = StreamBody::new(futures_util::stream::iter(frames));
    grpc_response(BodyExt::boxed(body), None)
}

/// A trailers-only error response.
fn status(code: u8, message: &str) -> Response<Body> {
    grpc_response(Full::new(Bytes::new()).map_err(|never| match never {}).boxed(), Some((code, message)))
}

fn grpc_response(body: Body, error: Option<(u8, &str)>) -> Response<Body> {
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert("content-type", HeaderValue::from_static("application/grpc"));
    if let Some((code, message)) = error {
        headers.insert("grpc-status", HeaderValue::from(u16::from(code)));
        if let Ok(value) = HeaderValue::from_str(&message.replace(|c: char| !c.is_ascii_graphic() && c != ' ', "?")) {
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
        let message = QueryStatsRequest { pattern: "user>>>".into(), reset: true };
        let mut framed = BytesMut::new();
        framed.put_u8(0);
        framed.put_u32(message.encoded_len() as u32);
        message.encode(&mut framed).unwrap();
        let inner = unframe(framed.freeze()).unwrap();
        assert_eq!(QueryStatsRequest::decode(inner).unwrap(), message);
        assert!(unframe(Bytes::from_static(&[1, 0, 0, 0, 0])).is_none());
    }
}
