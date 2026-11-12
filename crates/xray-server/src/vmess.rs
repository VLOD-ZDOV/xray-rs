//! Inbound VMess protocol handler (AEAD).

use std::io;
use std::net::SocketAddr;
use std::sync::PoisonError;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use sha2::{Digest, Sha256};
use tokio::time::{timeout_at, Instant};
use xray_config::Network;
use xray_proxy::vmess::server::{self, ServerHandshake, ServerStream, ServerUser};
use xray_routing::TargetAddr;

use crate::outbound::{self, ConeUdp};
use crate::routing::{Action, BlockAction};
use crate::stats;
use crate::vless::{read_first, Activity, Context, Host, RouteRequest};

pub async fn serve<R, W>(
    mut uplink: R,
    downlink: W,
    ctx: &Context,
    peer: SocketAddr,
    drain: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut seed = Sha256::new();
    let (server_users, levels): (Vec<ServerUser>, Vec<u32>) = {
        let users = ctx.users.read().unwrap_or_else(PoisonError::into_inner);
        users
            .iter()
            .map(|u| {
                seed.update(u.id);
                (ServerUser::new(&u.id, u.email.clone()), u.level)
            })
            .unzip()
    };

    let deadline = Instant::now() + crate::policy::get().handshake;
    let mut counted = crate::drain::Counted::new(&mut uplink);
    let hs_res = timeout_at(
        deadline,
        server::handshake_with_filter(&mut counted, &server_users, Some(&ctx.vmess_filter)),
    )
    .await;
    let read = counted.read;
    let hs: ServerHandshake = match hs_res {
        Ok(Ok(hs)) => hs,
        Ok(Err(e)) => {
            if drain {
                let total = crate::drain::size(&seed.finalize());
                crate::drain::discard(&mut uplink, total, read, deadline).await;
            }
            return Err(e);
        }
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "vmess handshake timeout",
            ));
        }
    };

    let user_email = server_users[hs.user_index].email.clone();
    let user_level = levels.get(hs.user_index).copied().unwrap_or(0);
    let user_policy = crate::policy::for_level(user_level);
    let _online = stats::get().connect(&user_email, user_level, peer.ip());

    let host = match &hs.target.addr {
        TargetAddr::Ip(ip) => Host::Ip(*ip),
        TargetAddr::Domain(d) => match d.parse() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(d.clone()),
        },
    };
    let port = hs.target.port;

    let (mut server_r, mut server_w) =
        ServerStream::<()>::split_from_handshake(uplink, downlink, &hs);

    let network = match hs.network {
        xray_routing::Network::Tcp => Network::Tcp,
        xray_routing::Network::Udp => Network::Udp,
    };

    let mut early = Vec::new();
    if network == Network::Tcp && (ctx.router.needs_sniff() || ctx.sniffing.enabled()) {
        read_first(&mut server_r, &mut early).await;
    }

    let route = RouteRequest {
        ctx_tag: &ctx.tag,
        inbound_port: ctx.port,
        email: &user_email,
        peer,
        network,
        host: &host,
        port,
        sniffing: &ctx.sniffing,
    };

    // Xray writes the response header even when the request goes nowhere.
    let Some(decision) = route.allow(&ctx.router, &early).await else {
        let _ = server_w.flush().await;
        return Ok(());
    };

    let mut route_host = host.clone();
    ctx.sniffing.override_host(&early, &mut route_host);

    if let Action::Block(BlockAction::Http403) = decision.action {
        if network == Network::Tcp {
            server_w
                .write_all(crate::routing::BLACKHOLE_HTTP_RESPONSE)
                .await?;
            server_w.flush().await?;
        }
        return Ok(());
    }
    if let Action::Block(_) = decision.action {
        let _ = server_w.flush().await;
        return Ok(());
    }

    let traffic = stats::get().traffic(&ctx.tag, &user_email, user_level, &decision.tag);

    match network {
        Network::Tcp => {
            let target_stream =
                outbound::connect(&ctx.router, &decision, &route_host, port).await?;
            let (mut target_r, mut target_w) = tokio::io::split(target_stream);

            if !early.is_empty() {
                target_w.write_all(&early).await?;
                traffic.up(early.len());
            }

            let activity = Activity::new();
            crate::vless::relay_policy(
                crate::vless::copy_buf(
                    &mut server_r,
                    &mut target_w,
                    &activity,
                    |n| traffic.up(n),
                    user_policy.buffer_size,
                ),
                crate::vless::copy_buf(
                    &mut target_r,
                    &mut server_w,
                    &activity,
                    |n| traffic.down(n),
                    user_policy.buffer_size,
                ),
                &activity,
                user_policy,
            )
            .await
        }
        Network::Udp => {
            let cone = ConeUdp::open(ctx.router.clone(), &decision).await?;
            let activity = Activity::new();
            let target_addr = cone.target(&route_host, port).await?;

            let up = async {
                let mut packet = vec![0u8; 65535];
                loop {
                    let n = server_r.read(&mut packet).await?;
                    if n == 0 {
                        break;
                    }
                    activity.touch();
                    cone.send_to(&packet[..n], target_addr).await?;
                    traffic.up(n);
                }
                Ok::<(), io::Error>(())
            };

            let down = async {
                let mut buf = vec![0u8; 65535];
                loop {
                    let (n, _from) = cone.recv_from(&mut buf).await?;
                    activity.touch();
                    server_w.write_all(&buf[..n]).await?;
                    server_w.flush().await?;
                    traffic.down(n);
                }
            };

            crate::vless::relay_policy(up, down, &activity, user_policy).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use xray_proxy::vmess::server::{AuthIdFilter, ServerUser};
    use xray_proxy::vmess::{Account, Cipher, ClientStream, Options};
    use xray_routing::{Network, Target, TargetAddr};

    #[tokio::test]
    async fn test_vmess_replayed_first_packet_rejected() {
        let user_id = [0x42u8; 16];
        let users = vec![ServerUser::new(&user_id, "test@vmess".to_string())];
        let filter = Mutex::new(AuthIdFilter::default_vmess());

        let account = Account::new(&user_id, Cipher::Aes128Gcm, Options::default());
        let target = Target::new(
            TargetAddr::Domain("example.com".to_string()),
            80,
            Network::Tcp,
        );

        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut client = ClientStream::new(client_io, &account, &target).unwrap();

        let client_task = tokio::spawn(async move {
            client.write_all(b"test request").await.unwrap();
            client.flush().await.unwrap();
        });

        // Capture what the client sends in the initial handshake
        let mut client_bytes = vec![0u8; 4096];
        let n = server_io.read(&mut client_bytes).await.unwrap();
        client_bytes.truncate(n);
        drop(client_task);

        // First attempt with these bytes
        let mut first_attempt = std::io::Cursor::new(client_bytes.clone());
        let res1 = server::handshake_with_filter(&mut first_attempt, &users, Some(&filter)).await;
        assert!(res1.is_ok(), "First handshake must succeed");

        // Replayed attempt with the exact same bytes and same filter
        let mut second_attempt = std::io::Cursor::new(client_bytes);
        let res2 = server::handshake_with_filter(&mut second_attempt, &users, Some(&filter)).await;
        let err = match res2 {
            Err(e) => e,
            Ok(_) => panic!("Replayed handshake must be rejected"),
        };
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("replayed"),
            "Error message should mention replay: {err_msg}"
        );
    }
}
