#![forbid(unsafe_code)]

//! `finalmask.tcp` on inbounds: the masks wrap each accepted connection
//! before TLS or REALITY. Xray's `NewFinalMask` reverses the configured
//! list, so the last mask is the one next to the wire.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_transport::header_custom::{
    server_handshake, CustomArg, CustomExpr, CustomItem, HeaderCustomTcpConfig,
};
use xray_transport::sudoku::{SudokuConfig, SudokuStream};
use xray_transport::{BoxedTransportStream, TransportStream};

pub enum TcpMask {
    HeaderCustom {
        config: HeaderCustomTcpConfig,
        errors: Vec<Vec<CustomItem>>,
    },
    Sudoku(SudokuConfig),
}

// Only the kind: the settings carry a password.
impl std::fmt::Debug for TcpMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::HeaderCustom { .. } => "header-custom",
            Self::Sudoku(_) => "sudoku",
        })
    }
}

/// The masks the server runs, in order; `None` without any.
pub fn parse(stream: &Value) -> Result<Option<Arc<Vec<TcpMask>>>, String> {
    let Some(masks) = stream.pointer("/finalmask/tcp").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for mask in masks {
        let kind = mask
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if kind != "header-custom" && kind != "sudoku" {
            continue;
        }
        // The upstream parser reads one mask at a time into its model.
        let synth = json!({"outbounds": [{
            "protocol": "freedom",
            "streamSettings": {"network": "raw", "finalmask": {"tcp": [mask]}},
        }]});
        let parsed = xray_config::parse_xray_json(&synth.to_string()).map_err(|e| {
            let messages: Vec<String> = e.diagnostics.iter().map(|d| format!("{d:?}")).collect();
            format!("finalmask.tcp {kind}: {}", messages.join("; "))
        })?;
        let parsed = &parsed.config.outbounds[0].stream;
        if let Some(header) = &parsed.tcp_header_custom {
            out.push(TcpMask::HeaderCustom {
                config: HeaderCustomTcpConfig {
                    clients: header.clients.iter().map(|s| items(s)).collect(),
                    servers: header.servers.iter().map(|s| items(s)).collect(),
                },
                errors: header.errors.iter().map(|s| items(s)).collect(),
            });
        } else if let Some(mask) = &parsed.tcp_sudoku {
            let config = SudokuConfig {
                password: mask.password.to_string(),
                ascii: mask.ascii.clone(),
                custom_table: mask.custom_table.clone(),
                custom_tables: mask.custom_tables.clone(),
                padding_min: mask.padding_min,
                padding_max: mask.padding_max,
            };
            config
                .check()
                .map_err(|e| format!("finalmask.tcp sudoku: {e}"))?;
            out.push(TcpMask::Sudoku(config));
        }
    }
    Ok((!out.is_empty()).then(|| Arc::new(out)))
}

fn items(source: &[xray_config::HeaderCustomItem]) -> Vec<CustomItem> {
    fn expr(source: &xray_config::HeaderCustomExpr) -> CustomExpr {
        CustomExpr {
            op: source.op.clone(),
            args: source
                .args
                .iter()
                .map(|arg| match arg {
                    xray_config::HeaderCustomArg::Bytes(bytes) => CustomArg::Bytes(bytes.clone()),
                    xray_config::HeaderCustomArg::U64(value) => CustomArg::U64(*value),
                    xray_config::HeaderCustomArg::Reuse(name) => CustomArg::Reuse(name.clone()),
                    xray_config::HeaderCustomArg::Metadata(name) => {
                        CustomArg::Metadata(name.clone())
                    }
                    xray_config::HeaderCustomArg::Transform(inner) => {
                        CustomArg::Transform(expr(inner))
                    }
                })
                .collect(),
        }
    }
    source
        .iter()
        .map(|item| CustomItem {
            delay: item.delay,
            rand: item.rand,
            rand_range: (item.rand_range.0 as u8, item.rand_range.1 as u8),
            packet: item.packet.clone(),
            capture: item.capture.clone(),
            reuse: item.reuse.clone(),
            transform: item.transform.as_ref().map(expr),
        })
        .collect()
}

/// Runs each mask over `stream`: a `header-custom` handshake on what came
/// before it, a `sudoku` wrap around it.
pub async fn accept<S>(
    stream: S,
    masks: &[TcpMask],
    local: Option<SocketAddr>,
    peer: SocketAddr,
) -> io::Result<BoxedTransportStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut stream: BoxedTransportStream = Box::new(Carrier(stream));
    for mask in masks.iter().rev() {
        match mask {
            TcpMask::HeaderCustom { config, errors } => {
                server_handshake(&mut stream, config, errors, local, Some(peer)).await?;
            }
            TcpMask::Sudoku(config) => {
                stream = Box::new(SudokuStream::server(stream, config)?);
            }
        }
    }
    Ok(stream)
}

/// Any byte stream as a transport stream, with no direct mode of its own.
struct Carrier<S>(S);

impl<S: AsyncRead + Unpin> AsyncRead for Carrier<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Carrier<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> TransportStream for Carrier<S> {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}
