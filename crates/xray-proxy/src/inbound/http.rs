use std::net::IpAddr;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use xray_routing::{Network, Target, TargetAddr};
use zeroize::Zeroizing;

const MAX_REQUEST_LINE_LEN: usize = 8192;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("request is not http connect")]
    NotConnect,
    #[error("request line is too long")]
    LineTooLong,
    #[error("target is missing port")]
    MissingPort,
    #[error("invalid authority")]
    InvalidAuthority,
    #[error("invalid port")]
    InvalidPort,
    #[error("io error")]
    Io,
}

/// An HTTP `CONNECT` request and the credentials it offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectRequest {
    pub target: Target,
    /// The last `Proxy-Authorization` value, trimmed of whitespace.
    pub proxy_authorization: Option<Zeroizing<Vec<u8>>>,
}

/// An incoming HTTP request on an HTTP inbound proxy, either CONNECT tunneling or plain request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpInboundRequest {
    Connect(HttpConnectRequest),
    Plain {
        target: Target,
        proxy_authorization: Option<Zeroizing<Vec<u8>>>,
        forwarded_request: Vec<u8>,
    },
}

impl HttpInboundRequest {
    pub fn target(&self) -> &Target {
        match self {
            Self::Connect(req) => &req.target,
            Self::Plain { target, .. } => target,
        }
    }

    pub fn proxy_authorization(&self) -> Option<&[u8]> {
        match self {
            Self::Connect(req) => req.proxy_authorization.as_deref().map(|v| v.as_slice()),
            Self::Plain {
                proxy_authorization,
                ..
            } => proxy_authorization.as_deref().map(|v| v.as_slice()),
        }
    }
}

pub async fn parse_http_connect<R: AsyncRead + Unpin>(reader: R) -> Result<Target, HttpParseError> {
    Ok(parse_http_connect_request(reader).await?.target)
}

pub async fn parse_http_connect_request<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<HttpConnectRequest, HttpParseError> {
    let request_line = read_line_limited(&mut reader).await?;
    let request_line =
        std::str::from_utf8(&request_line).map_err(|_| HttpParseError::NotConnect)?;
    let request_line = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpParseError::NotConnect)?;
    if method != "CONNECT" {
        return Err(HttpParseError::NotConnect);
    }

    let authority = parts.next().ok_or(HttpParseError::MissingPort)?;
    let (host, port) = parse_authority(authority)?;
    let port = parse_port(port)?;
    let addr = parse_host(host)?;
    let proxy_authorization = consume_headers(&mut reader).await?;

    Ok(HttpConnectRequest {
        target: Target::new(addr, port, Network::Tcp),
        proxy_authorization,
    })
}

pub async fn parse_http_inbound_request<R: AsyncRead + Unpin>(
    mut reader: R,
) -> Result<HttpInboundRequest, HttpParseError> {
    let request_line = read_line_limited(&mut reader).await?;
    let request_line =
        std::str::from_utf8(&request_line).map_err(|_| HttpParseError::NotConnect)?;
    let request_line = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpParseError::NotConnect)?;
    let uri = parts.next().ok_or(HttpParseError::MissingPort)?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method == "CONNECT" {
        let (host, port) = parse_authority(uri)?;
        let port = parse_port(port)?;
        let addr = parse_host(host)?;
        let proxy_authorization = consume_headers(&mut reader).await?;
        return Ok(HttpInboundRequest::Connect(HttpConnectRequest {
            target: Target::new(addr, port, Network::Tcp),
            proxy_authorization,
        }));
    }

    let (target_from_uri, path) = if let Some(rest) = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("HTTP://"))
    {
        let (host_port, path_part) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let (addr, port) = parse_host_and_port(host_port, 80)?;
        (Some(Target::new(addr, port, Network::Tcp)), path_part)
    } else {
        (None, uri)
    };

    let mut proxy_authorization = None;
    let mut target = target_from_uri;
    let mut headers_buf = Vec::new();

    loop {
        let line = Zeroizing::new(read_line_limited(&mut reader).await?);
        if *line == b"\r\n" || *line == b"\n" {
            break;
        }
        if let Some(colon) = line.iter().position(|&byte| byte == b':') {
            let name = &line[..colon];
            if name.eq_ignore_ascii_case(b"proxy-authorization") {
                proxy_authorization = Some(Zeroizing::new(line[colon + 1..].trim_ascii().to_vec()));
                continue;
            }
            if name.eq_ignore_ascii_case(b"proxy-connection") {
                continue;
            }
            if target.is_none() && name.eq_ignore_ascii_case(b"host") {
                let host_val = std::str::from_utf8(line[colon + 1..].trim_ascii())
                    .map_err(|_| HttpParseError::InvalidAuthority)?;
                let (addr, port) = parse_host_and_port(host_val, 80)?;
                target = Some(Target::new(addr, port, Network::Tcp));
            }
        }
        headers_buf.extend_from_slice(&line);
    }

    let target = target.ok_or(HttpParseError::InvalidAuthority)?;

    let mut forwarded = Vec::new();
    forwarded.extend_from_slice(method.as_bytes());
    forwarded.push(b' ');
    forwarded.extend_from_slice(path.as_bytes());
    forwarded.push(b' ');
    forwarded.extend_from_slice(version.as_bytes());
    forwarded.extend_from_slice(b"\r\n");
    forwarded.extend_from_slice(&headers_buf);
    forwarded.extend_from_slice(b"\r\n");

    Ok(HttpInboundRequest::Plain {
        target,
        proxy_authorization,
        forwarded_request: forwarded,
    })
}

async fn consume_headers<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Zeroizing<Vec<u8>>>, HttpParseError> {
    let mut proxy_authorization = None;
    loop {
        let line = Zeroizing::new(read_line_limited(reader).await?);
        if *line == b"\r\n" || *line == b"\n" {
            return Ok(proxy_authorization);
        }
        if let Some(colon) = line.iter().position(|&byte| byte == b':') {
            if line[..colon].eq_ignore_ascii_case(b"proxy-authorization") {
                proxy_authorization = Some(Zeroizing::new(line[colon + 1..].trim_ascii().to_vec()));
            }
        }
    }
}

/// A user name and password from `Proxy-Authorization`, wiped on drop.
pub type HttpBasicCredentials = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// Go's `parseBasicAuth` in Xray's HTTP server: a case-sensitive `Basic `
/// prefix, padded standard base64, and a split at the first colon.
pub fn decode_http_basic_credentials(value: &[u8]) -> Option<HttpBasicCredentials> {
    use base64::Engine as _;
    let encoded = value.strip_prefix(b"Basic ")?;
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?,
    );
    let colon = decoded.iter().position(|&byte| byte == b':')?;
    Some((
        Zeroizing::new(decoded[..colon].to_vec()),
        Zeroizing::new(decoded[colon + 1..].to_vec()),
    ))
}

async fn read_line_limited<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, HttpParseError> {
    let mut line = Vec::new();

    loop {
        if line.len() >= MAX_REQUEST_LINE_LEN {
            return Err(HttpParseError::LineTooLong);
        }

        let byte = reader.read_u8().await.map_err(|_| HttpParseError::Io)?;
        line.push(byte);
        if byte == b'\n' {
            return Ok(line);
        }
    }
}

fn parse_authority(authority: &str) -> Result<(&str, &str), HttpParseError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or(HttpParseError::MissingPort)?;
        return Ok((host, port));
    }

    authority
        .rsplit_once(':')
        .ok_or(HttpParseError::MissingPort)
}

fn parse_port(port: &str) -> Result<u16, HttpParseError> {
    let port = port.parse().map_err(|_| HttpParseError::InvalidPort)?;
    if port == 0 {
        return Err(HttpParseError::InvalidPort);
    }

    Ok(port)
}

fn parse_host(host: &str) -> Result<TargetAddr, HttpParseError> {
    if host.is_empty() {
        return Err(HttpParseError::InvalidAuthority);
    }

    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(TargetAddr::Ip(ip)),
        Err(_) => Ok(TargetAddr::Domain(host.to_owned())),
    }
}

fn parse_host_and_port(
    authority: &str,
    default_port: u16,
) -> Result<(TargetAddr, u16), HttpParseError> {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, port_str)) = rest.split_once("]:") {
            let port = parse_port(port_str)?;
            let addr = parse_host(host)?;
            return Ok((addr, port));
        } else if let Some(host) = rest.strip_suffix(']') {
            let addr = parse_host(host)?;
            return Ok((addr, default_port));
        }
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = parse_port(port_str)?;
        let addr = parse_host(host)?;
        Ok((addr, port))
    } else {
        let addr = parse_host(authority)?;
        Ok((addr, default_port))
    }
}
