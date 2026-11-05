//! REALITY Inbound implementation matching Xray-core / xtls/reality semantics.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::config::{FallbackDest, RealityInboundSettings};
use crate::fallback::Stream;
use crate::httpupgrade::PrefixedStream;
use crate::log;

#[derive(Debug)]
struct RealitySigningKey {
    inner: Arc<dyn rustls::sign::SigningKey>,
}

impl rustls::sign::SigningKey for RealitySigningKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if let Some(signer) = self.inner.choose_scheme(offered) {
            return Some(signer);
        }
        self.inner.choose_scheme(&[rustls::SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.inner.algorithm()
    }
}

#[derive(Debug)]
struct RealityCertResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for RealityCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub struct RealityServer {
    settings: Arc<RealityInboundSettings>,
    ed25519_pub: [u8; 32],
    signing_key: Arc<dyn rustls::sign::SigningKey>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    alpn_protocols: Vec<Vec<u8>>,
    inbound_port: u16,
}

impl RealityServer {
    pub fn new(
        settings: RealityInboundSettings,
        inbound_port: u16,
        is_grpc: bool,
        _is_xhttp: bool,
    ) -> Result<Self, String> {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| format!("failed to generate reality ed25519 key: {e}"))?;
        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(key_pair.public_key_raw());

        let der = key_pair.serialize_der();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let private_key = PrivateKeyDer::Pkcs8(der.into());
        let signing_key = provider
            .key_provider
            .load_private_key(private_key)
            .map_err(|e| format!("failed to load reality signing key: {e}"))?;
        let signing_key: Arc<dyn rustls::sign::SigningKey> = Arc::new(RealitySigningKey { inner: signing_key });

        let alpn: Vec<Vec<u8>> = settings
            .alpn
            .iter()
            .filter(|p| *p != "h3")
            .map(|p| p.as_bytes().to_vec())
            .collect();
        let alpn_protocols = if !alpn.is_empty() {
            alpn
        } else if is_grpc {
            vec![b"h2".to_vec()]
        } else {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        };

        Ok(Self {
            settings: Arc::new(settings),
            ed25519_pub,
            signing_key,
            provider,
            alpn_protocols,
            inbound_port,
        })
    }

    pub async fn handle<S>(
        &self,
        mut stream: S,
        peer: SocketAddr,
    ) -> io::Result<Option<tokio_rustls::server::TlsStream<PrefixedStream<S>>>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // 1. Read 5-byte TLS record header
        let mut record_header = [0u8; 5];
        if stream.read_exact(&mut record_header).await.is_err() {
            self.fallback(stream, &[], peer).await?;
            return Ok(None);
        }

        // Validate TLS record header:
        // Content type 0x16 (Handshake)
        // Record length 1..=16384
        let content_type = record_header[0];
        let payload_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        if content_type != 0x16 || payload_len == 0 || payload_len > 16384 {
            self.fallback(stream, &record_header, peer).await?;
            return Ok(None);
        }

        // 2. Read full record payload
        let mut payload = vec![0u8; payload_len];
        if stream.read_exact(&mut payload).await.is_err() {
            let mut early = record_header.to_vec();
            early.extend_from_slice(&payload);
            self.fallback(stream, &early, peer).await?;
            return Ok(None);
        }

        let mut full_record = Vec::with_capacity(5 + payload_len);
        full_record.extend_from_slice(&record_header);
        full_record.extend_from_slice(&payload);

        // 3. Parse ClientHello
        let client_hello = match xray_transport::reality::parse_reality_client_hello(&payload) {
            Ok(hello) => hello,
            Err(_) => {
                self.fallback(stream, &full_record, peer).await?;
                return Ok(None);
            }
        };

        // 4. Validate SNI against server_names
        let is_sni_match = match &client_hello.server_name {
            Some(sni) => {
                let sni_lower = sni.to_ascii_lowercase();
                self.settings
                    .server_names
                    .iter()
                    .any(|pattern| crate::match_sni(pattern, &sni_lower))
            }
            None => false,
        };
        if !is_sni_match {
            if self.settings.show {
                log::info(format!(
                    "REALITY remoteAddr: {peer} forwarded SNI: {:?}",
                    client_hello.server_name
                ));
            }
            self.fallback(stream, &full_record, peer).await?;
            return Ok(None);
        }

        // 5. Must have an X25519-compatible key share
        let Some(key_share) = client_hello.key_share else {
            self.fallback(stream, &full_record, peer).await?;
            return Ok(None);
        };

        // 6. Decrypt REALITY session ID
        let decrypted = match xray_transport::reality::decrypt_reality_session_id(
            &self.settings.private_key,
            &key_share.public_key,
            &client_hello.random,
            &payload,
            client_hello.session_id_offset,
            &client_hello.session_id,
        ) {
            Ok(decrypted) => decrypted,
            Err(_) => {
                self.fallback(stream, &full_record, peer).await?;
                return Ok(None);
            }
        };

        // 7. Check minClientVer and maxClientVer
        if let Some(min_ver) = &self.settings.min_client_ver {
            if decrypted.version < *min_ver {
                self.fallback(stream, &full_record, peer).await?;
                return Ok(None);
            }
        }
        if let Some(max_ver) = &self.settings.max_client_ver {
            if decrypted.version > *max_ver {
                self.fallback(stream, &full_record, peer).await?;
                return Ok(None);
            }
        }

        // 8. Check maxTimeDiff
        if self.settings.max_time_diff > 0 {
            let now_secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let client_secs = decrypted.unix_time as u64;
            let diff_ms = now_secs.abs_diff(client_secs).saturating_mul(1000);
            if diff_ms > self.settings.max_time_diff {
                self.fallback(stream, &full_record, peer).await?;
                return Ok(None);
            }
        }

        // 9. Check shortIds
        if !self.settings.short_ids.is_empty()
            && !self.settings.short_ids.contains(&decrypted.short_id)
        {
            self.fallback(stream, &full_record, peer).await?;
            return Ok(None);
        }

        if self.settings.show {
            log::info(format!(
                "REALITY remoteAddr: {peer} valid REALITY client: ver={:?}, time={}, short_id={:02x?}",
                decrypted.version, decrypted.unix_time, decrypted.short_id
            ));
        }

        // 10. REALITY authenticated! Generate certificate DER and complete TLS handshake
        let cert_der = xray_transport::reality::generate_reality_certificate_der(
            &decrypted.auth_key,
            &self.ed25519_pub,
        );

        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(
            vec![CertificateDer::from(cert_der)],
            self.signing_key.clone(),
        ));
        let mut server_config = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| io::Error::other(e.to_string()))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(RealityCertResolver(certified_key)));
        server_config.alpn_protocols = self.alpn_protocols.clone();

        let prefixed_stream = PrefixedStream::new(stream, full_record);
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let tls_stream = acceptor.accept(prefixed_stream).await?;

        Ok(Some(tls_stream))
    }

    async fn fallback<S>(
        &self,
        client: S,
        early: &[u8],
        peer: SocketAddr,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut dest: Box<dyn Stream> = match &self.settings.dest {
            FallbackDest::Tcp(host, port) => {
                let stream = match host {
                    crate::vless::Host::Ip(ip) => TcpStream::connect((*ip, *port)).await?,
                    crate::vless::Host::Domain(name) => {
                        TcpStream::connect((name.as_str(), *port)).await?
                    }
                };
                let _ = stream.set_nodelay(true);
                Box::new(stream)
            }
            FallbackDest::Unix(path) => Box::new(crate::fallback::connect_unix(path).await?),
        };

        crate::fallback::write_proxy_header(
            &mut dest,
            self.settings.xver,
            peer,
            self.inbound_port,
        )
        .await?;

        if !early.is_empty() {
            dest.write_all(early).await?;
        }

        let (mut client_r, mut client_w) = tokio::io::split(client);
        let (mut dest_r, mut dest_w) = tokio::io::split(dest);
        let activity = crate::vless::Activity::new();
        let _ = crate::vless::relay(
            crate::vless::copy(&mut client_r, &mut dest_w, &activity, |_| ()),
            crate::vless::copy(&mut dest_r, &mut client_w, &activity, |_| ()),
            &activity,
        )
        .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_reality_server_init() {
        let settings = RealityInboundSettings {
            dest: FallbackDest::Tcp(crate::vless::Host::Domain("localhost".into()), 80),
            server_names: vec!["example.com".to_string()],
            private_key: [0x11; 32],
            short_ids: vec![[0u8; 8]],
            min_client_ver: None,
            max_client_ver: None,
            max_time_diff: 0,
            xver: 0,
            show: false,
            alpn: vec!["h2".to_string()],
        };
        let srv = RealityServer::new(settings, 443, false, false).unwrap();
        assert_eq!(srv.ed25519_pub.len(), 32);
        assert_eq!(srv.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[tokio::test]
    async fn test_reality_fallback_on_non_tls() {
        let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_port = dest_listener.local_addr().unwrap().port();

        // Mock dest server
        tokio::spawn(async move {
            let (mut socket, _) = dest_listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = socket.read(&mut buf).await.unwrap();
            assert!(std::str::from_utf8(&buf[..n]).unwrap().contains("GET /probe"));
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").await.unwrap();
        });

        let settings = RealityInboundSettings {
            dest: FallbackDest::Tcp(crate::vless::Host::Ip("127.0.0.1".parse().unwrap()), dest_port),
            server_names: vec!["example.com".to_string()],
            private_key: [0x11; 32],
            short_ids: vec![[0u8; 8]],
            min_client_ver: None,
            max_client_ver: None,
            max_time_diff: 0,
            xver: 0,
            show: false,
            alpn: vec![],
        };
        let srv = RealityServer::new(settings, 8443, false, false).unwrap();

        let srv_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv_listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(srv_addr).await.unwrap();
            client.write_all(b"GET /probe HTTP/1.1\r\n\r\n").await.unwrap();
            let mut buf = Vec::new();
            client.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let (inbound_stream, peer) = srv_listener.accept().await.unwrap();
        let res = srv.handle(inbound_stream, peer).await.unwrap();
        assert!(res.is_none()); // Was handled via fallback

        let resp_bytes = client_task.await.unwrap();
        assert!(std::str::from_utf8(&resp_bytes).unwrap().contains("HTTP/1.1 200 OK"));
    }
}
