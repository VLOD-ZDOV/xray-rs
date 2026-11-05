# xray-rust server

A Rust server core that can stand in for `xray-linux-amd64` in the 3x-ui panel.
Clients keep using the regular Xray core.

This is a fork of [aimalygin/xray-rust](https://github.com/aimalygin/xray-rust),
a Rust client core for Xray-style configs. The server lives in the new
`crates/xray-server` crate and reuses the upstream config parser, routing
matcher and WireGuard client. The rest of the upstream workspace is kept as is.

The server crate and every workspace crate it is built from (`xray-config`,
`xray-proxy`, `xray-transport`, `xray-routing`, `xray-utls`,
`xray-vless-encryption`, `xray-wireguard`) are `#![forbid(unsafe_code)]`.

## What works

| Area | Supported |
|---|---|
| Inbound | VLESS over XHTTP (packet-up, stream-up, stream-one), HTTP/1.1 and HTTP/2, TLS or plain (behind nginx) |
| VLESS | TCP, UDP, Mux.Cool and XUDP |
| Outbound | `freedom` (with `finalRules`, private addresses blocked by default), `blackhole`, `wireguard` (Cloudflare WARP, including `reserved`), `socks` (SOCKS5 with optional login, TCP and UDP) |
| Routing | `domain`, `geosite`, `ip`, `geoip`, `port`, `network`, `inboundTag`, `user`, `source`, `sourcePort`, `protocol`; `domainStrategy` AsIs, IPIfNonMatch, IPOnDemand |
| 3x-ui | `-c`, `run -test -c`, `-version`, gRPC `StatsService` (traffic, online users and IPs), `HandlerService` user operations (clients are added and removed without a restart), the `log` section (`loglevel`, `access`, `error`, `maskAddress`) |

Tested against the official Xray-core 26.10.31 as client, WireGuard peer and
`xray api` client.

## Not supported yet

- Outbounds other than the four above (`vless`, `vmess`, ...) and balancers.
  Traffic routed to them is blocked with a warning.
- Changing routing rules, inbounds or outbounds in the panel still restarts
  the core (no `RoutingService`, `AddInbound`, `AddOutbound`).
- Inbounds other than VLESS + XHTTP: REALITY, XHTTP over HTTP/3, socks,
  wireguard. They are skipped with a warning.
- DNS for WireGuard traffic goes through the system resolver, not the tunnel.
- Routing fields `attrs`, `vlessRoute`, `localPort`, `localIP`, `process`,
  `webhook` stop the core at startup with an error.

## Build

```bash
cargo build --release -p xray-server
```

The binary is `target/release/xray-server`. A glibc build needs glibc 2.38 or
newer (Ubuntu 24.04 works, Ubuntu 22.04 and Debian 12 do not).

## Install into 3x-ui

```bash
systemctl stop x-ui
cd /usr/local/x-ui/bin
cp xray-linux-amd64 xray-linux-amd64.orig
cp /path/to/xray-server xray-linux-amd64
./xray-linux-amd64 run -test -c config.json
systemctl start x-ui
```

Do not use the panel's "update Xray" button afterwards: it overwrites the core.
To roll back, copy `xray-linux-amd64.orig` back.

For a debug log, stop the panel and run
`XRAY_SERVER_DEBUG=1 ./xray-linux-amd64 -c config.json`.

## License

[MPL-2.0](LICENSE), same as upstream. Third-party data notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
