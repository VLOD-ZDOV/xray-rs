//! REALITY Inbound implementation matching Xray-core / xtls/reality semantics.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, RwLock};
use std::task::{ready, Context, Poll};
use std::time::{Duration, SystemTime};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aws_lc_rs::signature::KeyPair;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::Mac;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::config::{FallbackDest, RealityInboundSettings};
use crate::fallback::Stream;
use crate::log;
use xray_proxy::vless::VisionStreamIo;

pub struct RealityServer {
    settings: Arc<RealityInboundSettings>,
    ed25519_key_pair: Arc<aws_lc_rs::signature::Ed25519KeyPair>,
    ed25519_pub: [u8; 32],
    alpn_protocols: Vec<Vec<u8>>,
    inbound_port: u16,
    mldsa65_key: Option<ml_dsa::SigningKey<ml_dsa::MlDsa65>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherType {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x1301 => Some(Self::Aes128Gcm),
            0x1302 => Some(Self::Aes256Gcm),
            0x1303 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub fn hash_len(&self) -> usize {
        match self {
            Self::Aes128Gcm | Self::ChaCha20Poly1305 => 32,
            Self::Aes256Gcm => 48,
        }
    }
}

fn aead_encrypt(
    cipher: CipherType,
    key: &[u8],
    nonce: &[u8; 12],
    ad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    match cipher {
        CipherType::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key).expect("Aes128Gcm key");
            let payload = aes_gcm::aead::Payload {
                msg: plaintext,
                aad: ad,
            };
            cipher
                .encrypt(&aes_gcm::Nonce::from(*nonce), payload)
                .expect("AES-128-GCM encrypt")
        }
        CipherType::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).expect("Aes256Gcm key");
            let payload = aes_gcm::aead::Payload {
                msg: plaintext,
                aad: ad,
            };
            cipher
                .encrypt(&aes_gcm::Nonce::from(*nonce), payload)
                .expect("AES-256-GCM encrypt")
        }
        CipherType::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20 key");
            let payload = chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: ad,
            };
            cipher
                .encrypt(&chacha20poly1305::Nonce::from(*nonce), payload)
                .expect("ChaCha20-Poly1305 encrypt")
        }
    }
}

fn aead_decrypt(
    cipher: CipherType,
    key: &[u8],
    nonce: &[u8; 12],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    match cipher {
        CipherType::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| ())?;
            let payload = aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: ad,
            };
            cipher
                .decrypt(&aes_gcm::Nonce::from(*nonce), payload)
                .map_err(|_| ())
        }
        CipherType::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ())?;
            let payload = aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: ad,
            };
            cipher
                .decrypt(&aes_gcm::Nonce::from(*nonce), payload)
                .map_err(|_| ())
        }
        CipherType::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| ())?;
            let payload = chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: ad,
            };
            cipher
                .decrypt(&chacha20poly1305::Nonce::from(*nonce), payload)
                .map_err(|_| ())
        }
    }
}

fn hkdf_extract(cipher: CipherType, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    compute_hmac(cipher, salt, ikm)
}

fn hkdf_expand_label(
    cipher: CipherType,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: u16,
) -> Vec<u8> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&length.to_be_bytes());
    let full_label = format!("tls13 {label}");
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let mut okm = vec![0u8; length as usize];
    match cipher {
        CipherType::Aes128Gcm | CipherType::ChaCha20Poly1305 => {
            let hk = hkdf::Hkdf::<Sha256>::from_prk(secret).expect("valid prk");
            hk.expand(&hkdf_label, &mut okm).expect("expand");
        }
        CipherType::Aes256Gcm => {
            let hk = hkdf::Hkdf::<Sha384>::from_prk(secret).expect("valid prk");
            hk.expand(&hkdf_label, &mut okm).expect("expand");
        }
    }
    okm
}

fn derive_secret(
    cipher: CipherType,
    secret: &[u8],
    label: &str,
    transcript_hash: &[u8],
) -> Vec<u8> {
    hkdf_expand_label(
        cipher,
        secret,
        label,
        transcript_hash,
        cipher.hash_len() as u16,
    )
}

fn compute_hmac(cipher: CipherType, key: &[u8], data: &[u8]) -> Vec<u8> {
    match cipher {
        CipherType::Aes128Gcm | CipherType::ChaCha20Poly1305 => {
            let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 init");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        CipherType::Aes256Gcm => {
            let mut mac = hmac::Hmac::<Sha384>::new_from_slice(key).expect("HMAC-SHA384 init");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

enum TranscriptHasher {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl TranscriptHasher {
    fn new(cipher: CipherType) -> Self {
        match cipher {
            CipherType::Aes128Gcm | CipherType::ChaCha20Poly1305 => Self::Sha256(Sha256::new()),
            CipherType::Aes256Gcm => Self::Sha384(Sha384::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
        }
    }

    fn current_hash(&self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.clone().finalize().to_vec(),
            Self::Sha384(h) => h.clone().finalize().to_vec(),
        }
    }
}

fn empty_hash(cipher: CipherType) -> Vec<u8> {
    match cipher {
        CipherType::Aes128Gcm | CipherType::ChaCha20Poly1305 => Sha256::digest([]).to_vec(),
        CipherType::Aes256Gcm => Sha384::digest([]).to_vec(),
    }
}

#[derive(Debug, Clone)]
struct DestHandshake {
    server_hello_msg: Vec<u8>,
    cipher_suite: CipherType,
    group: u16,
    key_exchange_offset: usize,
    key_exchange_len: usize,
    handshake_lens: [usize; 7],
}

pub static GLOBAL_POST_HANDSHAKE_RECORDS_LENS: LazyLock<
    RwLock<HashMap<String, Option<Vec<usize>>>>,
> = LazyLock::new(|| RwLock::new(HashMap::new()));

fn compute_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

#[derive(Debug)]
struct NoCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct PostHandshakeRecordDetectStream<S> {
    inner: S,
    ccs_sent: bool,
}

impl<S> PostHandshakeRecordDetectStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            ccs_sent: false,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PostHandshakeRecordDetectStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.len() >= 3 && buf[..3] == [20, 3, 3] {
            self.ccs_sent = true;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PostHandshakeRecordDetectStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.ccs_sent {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

async fn connect_dest_stream(dest: &FallbackDest) -> io::Result<Box<dyn Stream>> {
    let s: Box<dyn Stream> = match dest {
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
    Ok(s)
}

async fn probe_dest_post_handshake_lens(
    dest: &FallbackDest,
    xver: u8,
    sni: &str,
    alpn: u8,
) -> io::Result<Vec<usize>> {
    let mut stream = connect_dest_stream(dest).await?;

    if xver > 0 {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        crate::fallback::write_proxy_header(&mut stream, xver, peer, 443).await?;
    }

    let alpn_list: Vec<Vec<u8>> = match alpn {
        2 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        1 => vec![b"http/1.1".to_vec()],
        _ => vec![],
    };

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier { provider }))
        .with_no_client_auth();
    client_config.alpn_protocols = alpn_list;

    let server_name = ServerName::try_from(sni.to_string())
        .or_else(|_| ServerName::try_from("localhost".to_string()))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let detect_stream = PostHandshakeRecordDetectStream::new(stream);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tls_stream = tokio::time::timeout(
        Duration::from_secs(3),
        connector.connect(server_name, detect_stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e.to_string()))?;

    let (mut detect_stream, _) = tls_stream.into_inner();

    let mut raw_buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let timeout = Duration::from_secs(2);
    let start = tokio::time::Instant::now();

    while start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(start.elapsed());
        match tokio::time::timeout(remaining, detect_stream.inner.read(&mut tmp)).await {
            Ok(Ok(n)) if n > 0 => {
                raw_buf.extend_from_slice(&tmp[..n]);
                let mut offset = 0;
                let mut complete = false;
                while offset + 5 <= raw_buf.len() && raw_buf[offset..offset + 3] == [23, 3, 3] {
                    let rlen =
                        u16::from_be_bytes([raw_buf[offset + 3], raw_buf[offset + 4]]) as usize;
                    if offset + 5 + rlen <= raw_buf.len() {
                        offset += 5 + rlen;
                        complete = true;
                    } else {
                        break;
                    }
                }
                if complete && offset == raw_buf.len() {
                    let _ = tokio::time::timeout(
                        Duration::from_millis(100),
                        detect_stream.inner.read(&mut tmp),
                    )
                    .await;
                    break;
                }
            }
            _ => break,
        }
    }

    let mut post_handshake_lens = Vec::new();
    let mut data = &raw_buf[..];
    while data.len() >= 5 && data[..3] == [23, 3, 3] {
        let rlen = u16::from_be_bytes([data[3], data[4]]) as usize;
        let total_len = 5 + rlen;
        if total_len > data.len() {
            break;
        }
        post_handshake_lens.push(total_len);
        data = &data[total_len..];
    }

    Ok(post_handshake_lens)
}

pub fn detect_post_handshake_records_lens(settings: Arc<RealityInboundSettings>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        for sni in &settings.server_names {
            for alpn in 0..3 {
                let dest_str = settings.dest.to_string();
                let key = format!("{dest_str} {sni} {alpn}");
                {
                    let mut map = GLOBAL_POST_HANDSHAKE_RECORDS_LENS.write().unwrap();
                    if map.contains_key(&key) {
                        continue;
                    }
                    map.insert(key.clone(), None);
                }

                let settings_clone = Arc::clone(&settings);
                let sni = sni.clone();
                let key = key.clone();
                tokio::spawn(async move {
                    let lens = probe_dest_post_handshake_lens(
                        &settings_clone.dest,
                        settings_clone.xver,
                        &sni,
                        alpn,
                    )
                    .await;
                    let mut map = GLOBAL_POST_HANDSHAKE_RECORDS_LENS.write().unwrap();
                    map.insert(key, Some(lens.unwrap_or_default()));
                });
            }
        }
    });
}

impl RealityServer {
    pub fn new(
        settings: RealityInboundSettings,
        inbound_port: u16,
        is_grpc: bool,
        _is_xhttp: bool,
    ) -> Result<Self, String> {
        if settings.server_names.is_empty() {
            return Err(r#"empty "serverNames""#.into());
        }
        if settings.short_ids.is_empty() {
            return Err(r#"empty "shortIds""#.into());
        }
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate()
            .map_err(|e| format!("failed to generate reality ed25519 key: {e:?}"))?;
        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(key_pair.public_key().as_ref());

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

        let mldsa65_key = settings
            .mldsa65_seed
            .as_ref()
            .map(|seed| ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&(*seed).into()));

        let settings_arc = Arc::new(settings);
        detect_post_handshake_records_lens(Arc::clone(&settings_arc));

        Ok(Self {
            settings: settings_arc,
            ed25519_key_pair: Arc::new(key_pair),
            ed25519_pub,
            alpn_protocols,
            inbound_port,
            mldsa65_key,
        })
    }

    async fn connect_dest(&self) -> io::Result<Box<dyn Stream>> {
        connect_dest_stream(&self.settings.dest).await
    }

    pub async fn handle<S>(
        &self,
        mut stream: S,
        peer: SocketAddr,
    ) -> io::Result<Option<Tls13Stream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handshake_timeout = crate::policy::get().handshake;
        // 1. Read 5-byte TLS record header
        let mut record_header = [0u8; 5];
        match tokio::time::timeout(handshake_timeout, stream.read_exact(&mut record_header)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                self.fallback(stream, &[], peer).await?;
                return Ok(None);
            }
            Err(_) => {
                log::debug(format!(
                    "reality handshake from {} timed out",
                    log::mask(peer)
                ));
                return Ok(None);
            }
        }

        let content_type = record_header[0];
        let payload_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        if content_type != 0x16 || payload_len == 0 || payload_len > 16384 {
            self.fallback(stream, &record_header, peer).await?;
            return Ok(None);
        }

        // 2. Read ClientHello payload
        let mut payload = vec![0u8; payload_len];
        match tokio::time::timeout(handshake_timeout, stream.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                let mut early = record_header.to_vec();
                early.extend_from_slice(&payload);
                self.fallback(stream, &early, peer).await?;
                return Ok(None);
            }
            Err(_) => {
                log::debug(format!(
                    "reality handshake from {} timed out",
                    log::mask(peer)
                ));
                return Ok(None);
            }
        }

        let mut full_record = Vec::with_capacity(5 + payload_len);
        full_record.extend_from_slice(&record_header);
        full_record.extend_from_slice(&payload);

        // 3. Connect to dest and forward PROXY header + client's ClientHello
        let mut dest: Box<dyn Stream> = match self.connect_dest().await {
            Ok(d) => d,
            Err(e) => {
                log::info(format!(
                    "REALITY remoteAddr: {peer} failed to connect dest: {e}",
                    peer = log::mask(peer),
                ));
                return Ok(None);
            }
        };

        if let Err(e) = crate::fallback::write_proxy_header(
            &mut dest,
            self.settings.xver,
            peer,
            self.inbound_port,
        )
        .await
        {
            log::info(format!(
                "REALITY remoteAddr: {peer} failed to write proxy header: {e}",
                peer = log::mask(peer),
            ));
            return Ok(None);
        }

        if let Err(e) = dest.write_all(&full_record).await {
            log::info(format!(
                "REALITY remoteAddr: {peer} failed to write ClientHello to dest: {e}",
                peer = log::mask(peer),
            ));
            return Ok(None);
        }

        // 4. Authenticate client
        let auth = self.authenticate(&payload, peer);
        let auth_key = match auth {
            Some(k) => k,
            None => {
                // Unauthenticated client -> forward to dest!
                self.relay_fallback(stream, dest).await?;
                return Ok(None);
            }
        };

        // 5. Read dest's ServerHello and handshake record lengths
        let dest_handshake = match self.read_dest_handshake(&mut dest).await {
            Ok(dh) => dh,
            Err((s2c_saved, reason)) => {
                if self.settings.show {
                    log::info(format!("REALITY remoteAddr: {peer} dest not TLS 1.3 or bad hello ({reason}), forwarding client to dest", peer = log::mask(peer)));
                }
                self.forward_client_to_dest(stream, dest, &s2c_saved)
                    .await?;
                return Ok(None);
            }
        };

        // 6. Complete TLS 1.3 handshake with client, mirroring dest
        let served = match tokio::time::timeout(
            handshake_timeout,
            self.serve_handshake(stream, &payload, &auth_key, dest_handshake),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => Err(io::Error::other("timed out waiting for client Finished")),
        };
        match served {
            Ok(tls_stream) => {
                // Drop dest connection, client is successfully authenticated and served
                drop(dest);
                Ok(Some(tls_stream))
            }
            Err(e) => {
                log::debug(format!(
                    "REALITY handshake from {peer} failed: {e}",
                    peer = log::mask(peer)
                ));
                Ok(None)
            }
        }
    }

    fn authenticate(&self, payload: &[u8], peer: SocketAddr) -> Option<[u8; 32]> {
        let client_hello = xray_transport::reality::parse_reality_client_hello(payload).ok()?;

        let is_sni_match = match &client_hello.server_name {
            Some(sni) => {
                let sni_lower = sni.to_ascii_lowercase();
                self.settings
                    .server_names
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(&sni_lower))
            }
            None => false,
        };
        if !is_sni_match {
            if self.settings.show {
                log::info(format!(
                    "REALITY remoteAddr: {peer} forwarded SNI: {:?}",
                    client_hello.server_name,
                    peer = log::mask(peer),
                ));
            }
            return None;
        }

        let key_share = client_hello.key_share?;
        let decrypted = xray_transport::reality::decrypt_reality_session_id(
            &self.settings.private_key,
            &key_share.public_key,
            &client_hello.random,
            payload,
            client_hello.session_id_offset,
            &client_hello.session_id,
        )
        .ok()?;

        if let Some(min_ver) = &self.settings.min_client_ver {
            if decrypted.version < *min_ver {
                return None;
            }
        }
        if let Some(max_ver) = &self.settings.max_client_ver {
            if decrypted.version > *max_ver {
                return None;
            }
        }

        if self.settings.max_time_diff > 0 {
            let now_secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let client_secs = decrypted.unix_time as u64;
            let diff_ms = now_secs.abs_diff(client_secs).saturating_mul(1000);
            if diff_ms > self.settings.max_time_diff {
                return None;
            }
        }

        if !self.settings.short_ids.contains(&decrypted.short_id) {
            return None;
        }

        if self.settings.show {
            log::info(format!(
                "REALITY remoteAddr: {peer} valid REALITY client: ver={:?}, time={}, short_id={:02x?}",
                decrypted.version, decrypted.unix_time, decrypted.short_id,
                peer = log::mask(peer),
            ));
        }

        Some(decrypted.auth_key)
    }

    async fn read_dest_handshake(
        &self,
        dest: &mut Box<dyn Stream>,
    ) -> Result<DestHandshake, (Vec<u8>, &'static str)> {
        let mut s2c_saved = Vec::new();
        let mut buf = vec![0u8; 8192];
        let mut handshake_lens = [0usize; 7];

        let timeout = crate::policy::get().handshake;
        let read_future = async {
            loop {
                let n = dest.read(&mut buf).await.map_err(|_| "read error")?;
                if n == 0 {
                    return Err("dest closed connection");
                }
                s2c_saved.extend_from_slice(&buf[..n]);

                // Check if we have at least record 0 (ServerHello)
                if s2c_saved.len() < 5 {
                    continue;
                }
                let ctype0 = s2c_saved[0];
                let rlen0 = u16::from_be_bytes([s2c_saved[3], s2c_saved[4]]) as usize;
                if ctype0 != 0x16 || rlen0 == 0 || s2c_saved.len() < 5 + rlen0 {
                    if ctype0 != 0x16 {
                        return Err("dest first record not handshake");
                    }
                    continue;
                }
                handshake_lens[0] = 5 + rlen0;

                // Check if we have record 1 (ChangeCipherSpec, optional in RFC but universal in TLS 1.3)
                let mut offset = 5 + rlen0;
                if offset < s2c_saved.len() && s2c_saved[offset] == 0x14 {
                    if offset + 5 > s2c_saved.len() {
                        continue;
                    }
                    let ccs_len =
                        u16::from_be_bytes([s2c_saved[offset + 3], s2c_saved[offset + 4]]) as usize;
                    if offset + 5 + ccs_len > s2c_saved.len() {
                        continue;
                    }
                    handshake_lens[1] = 5 + ccs_len;
                    offset += 5 + ccs_len;
                }

                if offset < s2c_saved.len() && s2c_saved[offset] != 0x17 {
                    return Err("dest sent unexpected record after ServerHello");
                }

                // Check encrypted handshake records (ApplicationData 0x17)
                if offset < s2c_saved.len() && s2c_saved[offset] == 0x17 {
                    if offset + 5 > s2c_saved.len() {
                        continue;
                    }
                    let rlen2 =
                        u16::from_be_bytes([s2c_saved[offset + 3], s2c_saved[offset + 4]]) as usize;
                    if offset + 5 + rlen2 > s2c_saved.len() {
                        continue;
                    }
                    handshake_lens[2] = 5 + rlen2;
                    offset += 5 + rlen2;

                    // If rlen2 > 512, dest sent coalesced handshake records in one record
                    if handshake_lens[2] > 512 {
                        break;
                    }

                    // Otherwise dest sent separate records: Certificate (3), CertificateVerify (4), Finished (5)
                    // Check Record 3
                    if offset + 5 > s2c_saved.len() || s2c_saved[offset] != 0x17 {
                        continue;
                    }
                    let rlen3 =
                        u16::from_be_bytes([s2c_saved[offset + 3], s2c_saved[offset + 4]]) as usize;
                    if offset + 5 + rlen3 > s2c_saved.len() {
                        continue;
                    }
                    handshake_lens[3] = 5 + rlen3;
                    offset += 5 + rlen3;

                    // Check Record 4
                    if offset + 5 > s2c_saved.len() || s2c_saved[offset] != 0x17 {
                        continue;
                    }
                    let rlen4 =
                        u16::from_be_bytes([s2c_saved[offset + 3], s2c_saved[offset + 4]]) as usize;
                    if offset + 5 + rlen4 > s2c_saved.len() {
                        continue;
                    }
                    handshake_lens[4] = 5 + rlen4;
                    offset += 5 + rlen4;

                    // Check Record 5
                    if offset + 5 > s2c_saved.len() || s2c_saved[offset] != 0x17 {
                        continue;
                    }
                    let rlen5 =
                        u16::from_be_bytes([s2c_saved[offset + 3], s2c_saved[offset + 4]]) as usize;
                    if offset + 5 + rlen5 > s2c_saved.len() {
                        continue;
                    }
                    handshake_lens[5] = 5 + rlen5;
                    offset += 5 + rlen5;

                    // Optional Record 6 (NewSessionTicket / post-handshake)
                    if offset + 5 <= s2c_saved.len() && s2c_saved[offset] == 0x17 {
                        let rlen6 =
                            u16::from_be_bytes([s2c_saved[offset + 3], s2c_saved[offset + 4]])
                                as usize;
                        if offset + 5 + rlen6 <= s2c_saved.len() {
                            handshake_lens[6] = 5 + rlen6;
                        }
                    }

                    break;
                }
            }
            Ok(())
        };

        match tokio::time::timeout(timeout, read_future).await {
            Err(_) => return Err((s2c_saved, "timeout waiting for dest handshake")),
            Ok(Err(reason)) => return Err((s2c_saved, reason)),
            Ok(Ok(())) => {}
        }

        // Parse ServerHello message
        let sh_record_len = handshake_lens[0];
        let sh_msg = s2c_saved[5..sh_record_len].to_vec();
        let parsed = match parse_server_hello(&sh_msg) {
            Some(p) => p,
            None => return Err((s2c_saved, "failed to parse dest ServerHello as TLS 1.3")),
        };

        Ok(DestHandshake {
            server_hello_msg: sh_msg,
            cipher_suite: parsed.cipher_suite,
            group: parsed.group,
            key_exchange_offset: parsed.key_exchange_offset,
            key_exchange_len: parsed.key_exchange_len,
            handshake_lens,
        })
    }

    async fn serve_handshake<S>(
        &self,
        mut stream: S,
        client_hello_payload: &[u8],
        auth_key: &[u8; 32],
        dest_hs: DestHandshake,
    ) -> io::Result<Tls13Stream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let cipher = dest_hs.cipher_suite;
        let mut transcript = TranscriptHasher::new(cipher);
        transcript.update(client_hello_payload);

        // 1. Key exchange
        let (client_x25519, client_hybrid) = find_client_key_shares(client_hello_payload);
        let rng = rand::rngs::OsRng;
        let server_secret = x25519_dalek::StaticSecret::random_from_rng(rng);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);

        let (server_share_data, shared_key) = match dest_hs.group {
            0x001d => {
                // X25519
                let client_pub_bytes = client_x25519
                    .or_else(|| client_hybrid.map(|h| h.1))
                    .ok_or_else(|| io::Error::other("client missing X25519 key share"))?;
                let client_pub = x25519_dalek::PublicKey::from(client_pub_bytes);
                let shared_secret = server_secret.diffie_hellman(&client_pub);
                (
                    server_public.as_bytes().to_vec(),
                    shared_secret.as_bytes().to_vec(),
                )
            }
            0x11ec => {
                // X25519MLKEM768
                let (client_mlkem_bytes, client_x25519_bytes) = client_hybrid
                    .ok_or_else(|| io::Error::other("client missing X25519MLKEM768 key share"))?;
                let client_x25519_pub = x25519_dalek::PublicKey::from(client_x25519_bytes);
                let x25519_shared = server_secret.diffie_hellman(&client_x25519_pub);

                let enc_key = aws_lc_rs::kem::EncapsulationKey::new(
                    &aws_lc_rs::kem::ML_KEM_768,
                    &client_mlkem_bytes,
                )
                .map_err(|e| io::Error::other(format!("invalid ML-KEM key: {e:?}")))?;
                let (ciphertext, mlkem_secret) = enc_key
                    .encapsulate()
                    .map_err(|e| io::Error::other(format!("ML-KEM encapsulate: {e:?}")))?;

                let mut share = Vec::with_capacity(1088 + 32);
                share.extend_from_slice(ciphertext.as_ref());
                share.extend_from_slice(server_public.as_bytes());

                let mut shared = Vec::with_capacity(32 + 32);
                shared.extend_from_slice(mlkem_secret.as_ref());
                shared.extend_from_slice(x25519_shared.as_bytes());

                (share, shared)
            }
            _ => return Err(io::Error::other("unsupported dest key share group")),
        };

        if server_share_data.len() != dest_hs.key_exchange_len {
            return Err(io::Error::other("mismatched key share data length"));
        }

        // 2. Patch dest's ServerHello with our key share
        let mut server_hello_msg = dest_hs.server_hello_msg;
        server_hello_msg
            [dest_hs.key_exchange_offset..dest_hs.key_exchange_offset + dest_hs.key_exchange_len]
            .copy_from_slice(&server_share_data);

        transcript.update(&server_hello_msg);

        // Send ServerHello record
        let sh_len = server_hello_msg.len();
        let mut sh_record = Vec::with_capacity(5 + sh_len);
        sh_record.extend_from_slice(&[
            0x16,
            0x03,
            0x03,
            (sh_len >> 8) as u8,
            (sh_len & 0xff) as u8,
        ]);
        sh_record.extend_from_slice(&server_hello_msg);
        stream.write_all(&sh_record).await?;

        // Send dummy ChangeCipherSpec
        stream
            .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
            .await?;

        // 3. Key schedule: derive handshake traffic secrets
        let hash_len = cipher.hash_len();
        let key_len = cipher.key_len();
        let early_secret = hkdf_extract(cipher, &vec![0u8; hash_len], &vec![0u8; hash_len]);
        let derived_1 = derive_secret(cipher, &early_secret, "derived", &empty_hash(cipher));
        let handshake_secret = hkdf_extract(cipher, &derived_1, &shared_key);

        let transcript_hash_1 = transcript.current_hash();
        let client_hs_secret = derive_secret(
            cipher,
            &handshake_secret,
            "c hs traffic",
            &transcript_hash_1,
        );
        let server_hs_secret = derive_secret(
            cipher,
            &handshake_secret,
            "s hs traffic",
            &transcript_hash_1,
        );

        let client_hs_key =
            hkdf_expand_label(cipher, &client_hs_secret, "key", &[], key_len as u16);
        let mut client_hs_iv = [0u8; 12];
        client_hs_iv.copy_from_slice(&hkdf_expand_label(cipher, &client_hs_secret, "iv", &[], 12));

        let server_hs_key =
            hkdf_expand_label(cipher, &server_hs_secret, "key", &[], key_len as u16);
        let mut server_hs_iv = [0u8; 12];
        server_hs_iv.copy_from_slice(&hkdf_expand_label(cipher, &server_hs_secret, "iv", &[], 12));

        // 4. Construct EncryptedExtensions
        let negotiated_alpn = if dest_hs.handshake_lens[2] >= 37 {
            find_client_alpn(client_hello_payload)
                .into_iter()
                .find(|p| self.alpn_protocols.iter().any(|s| s == p))
        } else {
            None
        };
        let ee_msg = build_encrypted_extensions_msg(negotiated_alpn.as_deref());
        transcript.update(&ee_msg);

        // 5. Construct Certificate
        let cert_der = if let Some(mldsa_key) = &self.mldsa65_key {
            use ml_dsa::Signer;
            let mut mac = <hmac::Hmac<sha2::Sha512> as hmac::KeyInit>::new_from_slice(auth_key)
                .expect("HMAC-SHA512 accepts any key length");
            mac.update(&self.ed25519_pub);
            mac.update(client_hello_payload);
            mac.update(&server_hello_msg);
            let message = mac.finalize().into_bytes();
            let mldsa_sig = mldsa_key.sign(message.as_slice());
            xray_transport::reality::generate_reality_certificate_der_with_mldsa65(
                auth_key,
                &self.ed25519_pub,
                Some(&mldsa_sig.encode()),
            )
        } else {
            xray_transport::reality::generate_reality_certificate_der(auth_key, &self.ed25519_pub)
        };
        let cert_msg = build_certificate_msg(&cert_der);
        transcript.update(&cert_msg);

        // 6. Construct CertificateVerify
        let transcript_hash_cert = transcript.current_hash();
        let mut to_sign = Vec::with_capacity(64 + 33 + 1 + transcript_hash_cert.len());
        to_sign.extend_from_slice(&[0x20; 64]);
        to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
        to_sign.extend_from_slice(&transcript_hash_cert);

        let sig = self.ed25519_key_pair.sign(&to_sign);
        let cv_msg = build_certificate_verify_msg(sig.as_ref());
        transcript.update(&cv_msg);

        // 7. Construct Server Finished
        let transcript_hash_cv = transcript.current_hash();
        let server_finished_key =
            hkdf_expand_label(cipher, &server_hs_secret, "finished", &[], hash_len as u16);
        let server_verify_data = compute_hmac(cipher, &server_finished_key, &transcript_hash_cv);
        let fin_msg = build_finished_msg(&server_verify_data);
        transcript.update(&fin_msg);

        // 8. Send encrypted handshake records with exact dest padding
        let hlens = dest_hs.handshake_lens;
        if hlens[2] > 512 {
            // Coalesced record
            let mut coalesced =
                Vec::with_capacity(ee_msg.len() + cert_msg.len() + cv_msg.len() + fin_msg.len());
            coalesced.extend_from_slice(&ee_msg);
            coalesced.extend_from_slice(&cert_msg);
            coalesced.extend_from_slice(&cv_msg);
            coalesced.extend_from_slice(&fin_msg);

            let pad = hlens[2].saturating_sub(coalesced.len() + 22);
            let rec =
                encrypt_handshake_record(cipher, &server_hs_key, &server_hs_iv, 0, &coalesced, pad);
            stream.write_all(&rec).await?;
        } else {
            // Separate records
            let pad2 = hlens[2].saturating_sub(ee_msg.len() + 22);
            let rec2 =
                encrypt_handshake_record(cipher, &server_hs_key, &server_hs_iv, 0, &ee_msg, pad2);
            stream.write_all(&rec2).await?;

            let pad3 = hlens[3].saturating_sub(cert_msg.len() + 22);
            let rec3 =
                encrypt_handshake_record(cipher, &server_hs_key, &server_hs_iv, 1, &cert_msg, pad3);
            stream.write_all(&rec3).await?;

            let pad4 = hlens[4].saturating_sub(cv_msg.len() + 22);
            let rec4 =
                encrypt_handshake_record(cipher, &server_hs_key, &server_hs_iv, 2, &cv_msg, pad4);
            stream.write_all(&rec4).await?;

            let pad5 = hlens[5].saturating_sub(fin_msg.len() + 22);
            let rec5 =
                encrypt_handshake_record(cipher, &server_hs_key, &server_hs_iv, 3, &fin_msg, pad5);
            stream.write_all(&rec5).await?;
        }
        stream.flush().await?;

        // 9. Derive Application Traffic Secrets
        let transcript_hash_fin = transcript.current_hash();
        let derived_2 = derive_secret(cipher, &handshake_secret, "derived", &empty_hash(cipher));
        let master_secret = hkdf_extract(cipher, &derived_2, &vec![0u8; hash_len]);

        let client_app_secret =
            derive_secret(cipher, &master_secret, "c ap traffic", &transcript_hash_fin);
        let server_app_secret =
            derive_secret(cipher, &master_secret, "s ap traffic", &transcript_hash_fin);

        let client_app_key =
            hkdf_expand_label(cipher, &client_app_secret, "key", &[], key_len as u16);
        let mut client_app_iv = [0u8; 12];
        client_app_iv.copy_from_slice(&hkdf_expand_label(
            cipher,
            &client_app_secret,
            "iv",
            &[],
            12,
        ));

        let server_app_key =
            hkdf_expand_label(cipher, &server_app_secret, "key", &[], key_len as u16);
        let mut server_app_iv = [0u8; 12];
        server_app_iv.copy_from_slice(&hkdf_expand_label(
            cipher,
            &server_app_secret,
            "iv",
            &[],
            12,
        ));

        // 10. Read client Finished
        let client_finished_key =
            hkdf_expand_label(cipher, &client_hs_secret, "finished", &[], hash_len as u16);
        let expected_client_verify_data =
            compute_hmac(cipher, &client_finished_key, &transcript_hash_fin);

        let mut cli_hdr = [0u8; 5];
        stream.read_exact(&mut cli_hdr).await?;
        if cli_hdr[0] == 0x14 {
            // Dummy ChangeCipherSpec from client, read its 1 byte payload and read next record
            let mut ccs_payload = vec![0u8; u16::from_be_bytes([cli_hdr[3], cli_hdr[4]]) as usize];
            stream.read_exact(&mut ccs_payload).await?;
            stream.read_exact(&mut cli_hdr).await?;
        }

        if cli_hdr[0] != 0x17 {
            return Err(io::Error::other(
                "expected encrypted client Finished record",
            ));
        }
        let cli_rec_len = u16::from_be_bytes([cli_hdr[3], cli_hdr[4]]) as usize;
        let mut cli_ct = vec![0u8; cli_rec_len];
        stream.read_exact(&mut cli_ct).await?;

        let cli_plaintext = aead_decrypt(cipher, &client_hs_key, &client_hs_iv, &cli_hdr, &cli_ct)
            .map_err(|_| io::Error::other("decrypt client Finished failed"))?;

        // Strip trailing zeros
        let mut end = cli_plaintext.len();
        while end > 0 && cli_plaintext[end - 1] == 0 {
            end -= 1;
        }
        if end == 0 || cli_plaintext[end - 1] != 0x16 {
            return Err(io::Error::other("invalid content type in client Finished"));
        }
        let cli_fin_msg = &cli_plaintext[..end - 1];
        if cli_fin_msg.len() < 4 + hash_len || cli_fin_msg[0] != 0x14 {
            return Err(io::Error::other("invalid client Finished message shape"));
        }
        let cli_verify_data = &cli_fin_msg[4..4 + hash_len];
        if cli_verify_data != expected_client_verify_data.as_slice() {
            return Err(io::Error::other("client Finished verify_data mismatch"));
        }

        let mut server_seq: u64 = 0;

        let client_alpns = find_client_alpn(client_hello_payload);
        let alpn_code = if client_alpns.is_empty() {
            0
        } else if client_alpns[0] == b"h2" {
            2
        } else {
            1
        };
        let client_hello =
            xray_transport::reality::parse_reality_client_hello(client_hello_payload).ok();
        let sni = client_hello
            .as_ref()
            .and_then(|ch| ch.server_name.as_deref())
            .unwrap_or("");
        let key = format!("{} {} {}", self.settings.dest, sni, alpn_code);

        let cached_lens = {
            let map = GLOBAL_POST_HANDSHAKE_RECORDS_LENS.read().unwrap();
            map.get(&key).cloned().flatten()
        };
        let lens = match cached_lens {
            Some(l) => l,
            None => {
                let probed = probe_dest_post_handshake_lens(
                    &self.settings.dest,
                    self.settings.xver,
                    sni,
                    alpn_code,
                )
                .await
                .unwrap_or_default();
                let mut map = GLOBAL_POST_HANDSHAKE_RECORDS_LENS.write().unwrap();
                map.insert(key, Some(probed.clone()));
                probed
            }
        };

        let client_cipher = AeadCipher::new(cipher, &client_app_key);
        let server_cipher = AeadCipher::new(cipher, &server_app_key);

        for length in lens {
            if length >= 22 {
                let pt_len = length - 21;
                let mut pt = vec![0u8; pt_len];
                pt[0] = 0x17; // ApplicationData
                let nonce = compute_nonce(&server_app_iv, server_seq);
                server_seq += 1;
                let mut header = [0u8; 5];
                header[0] = 0x17;
                header[1] = 0x03;
                header[2] = 0x03;
                let ct_len = (length - 5) as u16;
                header[3] = (ct_len >> 8) as u8;
                header[4] = (ct_len & 0xff) as u8;
                let ciphertext = server_cipher.encrypt(&nonce, &header, &pt).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "AEAD encrypt failed")
                })?;
                stream.write_all(&header).await?;
                stream.write_all(&ciphertext).await?;
                if self.settings.show {
                    log::info(format!("REALITY len(postHandshakeRecord): {length}"));
                }
            }
        }
        stream.flush().await?;

        Ok(Tls13Stream {
            inner: stream,
            cipher,
            client_app_secret,
            client_app_iv,
            client_seq: 0,
            client_cipher,
            server_app_secret,
            server_app_iv,
            server_seq,
            server_cipher,
            read_buf: Vec::new(),
            read_buf_pos: 0,
            raw_read_buf: Vec::new(),
            write_buf: Vec::new(),
            write_buf_pos: 0,
            scratch_buf: Vec::with_capacity(16384 + 256),
            handshake: Box::new(crate::fallback::TlsInfo::new(
                &xray_transport::reality::parse_reality_client_hello(client_hello_payload)
                    .ok()
                    .and_then(|hello| hello.server_name)
                    .unwrap_or_default(),
                negotiated_alpn.as_deref().unwrap_or_default(),
            )),
        })
    }

    async fn relay_fallback<S>(&self, client: S, dest: Box<dyn Stream>) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
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

    async fn forward_client_to_dest<S>(
        &self,
        mut client: S,
        dest: Box<dyn Stream>,
        s2c_saved: &[u8],
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if !s2c_saved.is_empty() {
            client.write_all(s2c_saved).await?;
        }
        self.relay_fallback(client, dest).await
    }

    async fn fallback<S>(&self, client: S, early: &[u8], peer: SocketAddr) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut dest: Box<dyn Stream> = self.connect_dest().await?;
        crate::fallback::write_proxy_header(&mut dest, self.settings.xver, peer, self.inbound_port)
            .await?;

        if !early.is_empty() {
            dest.write_all(early).await?;
        }

        self.relay_fallback(client, dest).await
    }
}

fn encrypt_handshake_record(
    cipher: CipherType,
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    body: &[u8],
    padding: usize,
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(body.len() + 1 + padding);
    plaintext.extend_from_slice(body);
    plaintext.push(0x16); // Handshake content type
    plaintext.resize(plaintext.len() + padding, 0u8);

    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }

    let ct_len = plaintext.len() + 16;
    let header = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, (ct_len & 0xff) as u8];
    let ciphertext = aead_encrypt(cipher, key, &nonce, &header, &plaintext);

    let mut record = Vec::with_capacity(5 + ciphertext.len());
    record.extend_from_slice(&header);
    record.extend_from_slice(&ciphertext);
    record
}

fn build_encrypted_extensions_msg(alpn: Option<&[u8]>) -> Vec<u8> {
    let mut ext_bytes = Vec::new();
    if let Some(proto) = alpn {
        // ALPN extension (0x0010)
        ext_bytes.extend_from_slice(&0x0010u16.to_be_bytes());
        let ext_len = 2 + 1 + proto.len();
        ext_bytes.extend_from_slice(&(ext_len as u16).to_be_bytes());
        let list_len = 1 + proto.len();
        ext_bytes.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext_bytes.push(proto.len() as u8);
        ext_bytes.extend_from_slice(proto);
    }

    let ext_len = ext_bytes.len();
    let body_len = 2 + ext_len;
    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x08); // EncryptedExtensions
    msg.push(0);
    msg.extend_from_slice(&(body_len as u16).to_be_bytes());
    msg.extend_from_slice(&(ext_len as u16).to_be_bytes());
    msg.extend_from_slice(&ext_bytes);
    msg
}

fn build_certificate_msg(cert_der: &[u8]) -> Vec<u8> {
    let entry_len = 3 + cert_der.len() + 2;
    let list_len = entry_len;
    let body_len = 1 + 3 + list_len;

    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x0b); // Certificate
    msg.push((body_len >> 16) as u8);
    msg.push((body_len >> 8) as u8);
    msg.push(body_len as u8);
    msg.push(0); // request context len 0
    msg.push((list_len >> 16) as u8);
    msg.push((list_len >> 8) as u8);
    msg.push(list_len as u8);

    // Single cert entry
    msg.push((cert_der.len() >> 16) as u8);
    msg.push((cert_der.len() >> 8) as u8);
    msg.push(cert_der.len() as u8);
    msg.extend_from_slice(cert_der);
    msg.extend_from_slice(&[0x00, 0x00]); // extensions len 0
    msg
}

fn build_certificate_verify_msg(sig: &[u8]) -> Vec<u8> {
    let body_len = 2 + 2 + sig.len();
    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x0f); // CertificateVerify
    msg.push(0);
    msg.extend_from_slice(&(body_len as u16).to_be_bytes());
    msg.extend_from_slice(&[0x08, 0x07]); // Ed25519
    msg.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    msg.extend_from_slice(sig);
    msg
}

fn build_finished_msg(verify_data: &[u8]) -> Vec<u8> {
    let body_len = verify_data.len();
    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x14); // Finished
    msg.push(0);
    msg.extend_from_slice(&(body_len as u16).to_be_bytes());
    msg.extend_from_slice(verify_data);
    msg
}

struct ParsedServerHello {
    cipher_suite: CipherType,
    group: u16,
    key_exchange_offset: usize,
    key_exchange_len: usize,
}

fn parse_server_hello(sh: &[u8]) -> Option<ParsedServerHello> {
    if sh.len() < 39 || sh[0] != 0x02 {
        return None;
    }
    let sid_len = sh[38] as usize;
    let mut pos = 39 + sid_len;
    if pos + 4 > sh.len() {
        return None;
    }
    let cipher_val = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
    let cipher_suite = CipherType::from_u16(cipher_val)?;
    pos += 2; // skip cipher
    pos += 1; // skip compression method

    if pos + 2 > sh.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([sh[pos], sh[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > sh.len() {
        return None;
    }

    let mut is_tls13 = false;
    let mut group_info = None;

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
        let elen = u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            return None;
        }
        let edata = &sh[pos..pos + elen];
        if etype == 0x002b {
            // supported_versions
            if elen == 2 && edata == [0x03, 0x04] {
                is_tls13 = true;
            }
        } else if etype == 0x0033 {
            // key_share
            if elen >= 4 {
                let grp = u16::from_be_bytes([edata[0], edata[1]]);
                let klen = u16::from_be_bytes([edata[2], edata[3]]) as usize;
                if elen >= 4 + klen && (grp == 0x001d || grp == 0x11ec) {
                    let koffset = pos + 4;
                    group_info = Some((grp, koffset, klen));
                }
            }
        }
        pos += elen;
    }

    if !is_tls13 {
        return None;
    }
    let (group, key_exchange_offset, key_exchange_len) = group_info?;
    Some(ParsedServerHello {
        cipher_suite,
        group,
        key_exchange_offset,
        key_exchange_len,
    })
}

type ClientKeyShares = (Option<[u8; 32]>, Option<([u8; 1184], [u8; 32])>);

fn find_client_key_shares(payload: &[u8]) -> ClientKeyShares {
    if payload.len() < 42 || payload[0] != 0x01 {
        return (None, None);
    }
    let sid_len = payload[38] as usize;
    let mut pos = 39 + sid_len;
    if pos + 2 > payload.len() {
        return (None, None);
    }
    let cs_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos + 1 > payload.len() {
        return (None, None);
    }
    let cm_len = payload[pos] as usize;
    pos += 1 + cm_len;
    if pos + 2 > payload.len() {
        return (None, None);
    }
    let ext_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > payload.len() {
        return (None, None);
    }

    let mut x25519_pub = None;
    let mut hybrid_pub = None;

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let elen = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        if etype == 0x0033 && elen >= 2 {
            let mut sp = pos + 2;
            let send = pos + elen;
            while sp + 4 <= send {
                let grp = u16::from_be_bytes([payload[sp], payload[sp + 1]]);
                let klen = u16::from_be_bytes([payload[sp + 2], payload[sp + 3]]) as usize;
                sp += 4;
                if sp + klen > send {
                    break;
                }
                if grp == 0x001d && klen == 32 {
                    let mut b = [0u8; 32];
                    b.copy_from_slice(&payload[sp..sp + 32]);
                    x25519_pub = Some(b);
                } else if grp == 0x11ec && klen == 1216 {
                    let mut mlkem = [0u8; 1184];
                    let mut x25519 = [0u8; 32];
                    mlkem.copy_from_slice(&payload[sp..sp + 1184]);
                    x25519.copy_from_slice(&payload[sp + 1184..sp + 1216]);
                    hybrid_pub = Some((mlkem, x25519));
                }
                sp += klen;
            }
        }
        pos += elen;
    }

    (x25519_pub, hybrid_pub)
}

fn find_client_alpn(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut alpn = Vec::new();
    if payload.len() < 42 || payload[0] != 0x01 {
        return alpn;
    }
    let sid_len = payload[38] as usize;
    let mut pos = 39 + sid_len;
    if pos + 2 > payload.len() {
        return alpn;
    }
    let cs_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos + 1 > payload.len() {
        return alpn;
    }
    let cm_len = payload[pos] as usize;
    pos += 1 + cm_len;
    if pos + 2 > payload.len() {
        return alpn;
    }
    let ext_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > payload.len() {
        return alpn;
    }

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let elen = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        if etype == 0x0010 && elen >= 2 {
            let mut ap = pos + 2;
            let aend = pos + elen;
            while ap < aend {
                let plen = payload[ap] as usize;
                ap += 1;
                if ap + plen > aend {
                    break;
                }
                alpn.push(payload[ap..ap + plen].to_vec());
                ap += plen;
            }
        }
        pos += elen;
    }

    alpn
}

#[derive(Clone)]
pub(crate) struct AeadCipher(Arc<aws_lc_rs::aead::LessSafeKey>);

impl AeadCipher {
    pub(crate) fn new(cipher: CipherType, key: &[u8]) -> Self {
        let alg = match cipher {
            CipherType::Aes128Gcm => &aws_lc_rs::aead::AES_128_GCM,
            CipherType::Aes256Gcm => &aws_lc_rs::aead::AES_256_GCM,
            CipherType::ChaCha20Poly1305 => &aws_lc_rs::aead::CHACHA20_POLY1305,
        };
        let unbound = aws_lc_rs::aead::UnboundKey::new(alg, key).expect("valid AEAD key");
        Self(Arc::new(aws_lc_rs::aead::LessSafeKey::new(unbound)))
    }

    pub(crate) fn encrypt(
        &self,
        nonce: &[u8; 12],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, io::Error> {
        let mut buf = plaintext.to_vec();
        self.encrypt_in_place(nonce, ad, &mut buf)?;
        Ok(buf)
    }

    #[cfg(test)]
    pub(crate) fn decrypt(
        &self,
        nonce: &[u8; 12],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, io::Error> {
        let mut buf = ciphertext.to_vec();
        self.decrypt_in_place(nonce, ad, &mut buf)?;
        Ok(buf)
    }

    pub(crate) fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        ad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), io::Error> {
        let tag = self
            .0
            .seal_in_place_separate_tag(
                aws_lc_rs::aead::Nonce::assume_unique_for_key(*nonce),
                aws_lc_rs::aead::Aad::from(ad),
                buffer,
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD encrypt failed"))?;
        buffer.extend_from_slice(tag.as_ref());
        Ok(())
    }

    pub(crate) fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        ad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), io::Error> {
        let out = self
            .0
            .open_in_place(
                aws_lc_rs::aead::Nonce::assume_unique_for_key(*nonce),
                aws_lc_rs::aead::Aad::from(ad),
                buffer,
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TLS 1.3 decrypt failed"))?;
        let len = out.len();
        buffer.truncate(len);
        Ok(())
    }
}

pub struct Tls13Stream<S> {
    inner: S,
    cipher: CipherType,
    client_app_secret: Vec<u8>,
    client_app_iv: [u8; 12],
    client_seq: u64,
    client_cipher: AeadCipher,
    server_app_secret: Vec<u8>,
    server_app_iv: [u8; 12],
    server_seq: u64,
    server_cipher: AeadCipher,
    read_buf: Vec<u8>,
    read_buf_pos: usize,
    raw_read_buf: Vec<u8>,
    write_buf: Vec<u8>,
    write_buf_pos: usize,
    scratch_buf: Vec<u8>,
    handshake: Box<crate::fallback::TlsInfo>,
}

impl<S> Tls13Stream<S> {
    /// SNI and ALPN, which select a fallback.
    pub fn handshake_info(&self) -> crate::fallback::TlsInfo {
        (*self.handshake).clone()
    }

    pub fn raw_stream(&self) -> &S {
        &self.inner
    }

    pub fn raw_stream_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn undecrypted_leftover(&self) -> &[u8] {
        &self.raw_read_buf
    }

    pub fn into_parts(self) -> (S, Vec<u8>, Vec<u8>) {
        let decrypted = if self.read_buf_pos < self.read_buf.len() {
            self.read_buf[self.read_buf_pos..].to_vec()
        } else {
            Vec::new()
        };
        (self.inner, self.raw_read_buf, decrypted)
    }

    fn queue_key_update(&mut self) -> io::Result<()> {
        let key_update_msg = [0x18, 0x00, 0x00, 0x01, 0x00];
        let mut pt = Vec::with_capacity(key_update_msg.len() + 1);
        pt.extend_from_slice(&key_update_msg);
        pt.push(0x16); // Handshake content type

        let nonce = compute_nonce(&self.server_app_iv, self.server_seq);
        self.server_seq += 1;

        let ct_len = pt.len() + 16;
        let header = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, (ct_len & 0xff) as u8];
        let ciphertext = self
            .server_cipher
            .encrypt(&nonce, &header, &pt)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "KeyUpdate encrypt failed"))?;

        self.write_buf.extend_from_slice(&header);
        self.write_buf.extend_from_slice(&ciphertext);

        // Update server application traffic secret and keys (RFC 8446 7.2)
        self.server_app_secret = hkdf_expand_label(
            self.cipher,
            &self.server_app_secret,
            "traffic upd",
            &[],
            self.cipher.hash_len() as u16,
        );
        let server_key = hkdf_expand_label(
            self.cipher,
            &self.server_app_secret,
            "key",
            &[],
            self.cipher.key_len() as u16,
        );
        self.server_app_iv.copy_from_slice(&hkdf_expand_label(
            self.cipher,
            &self.server_app_secret,
            "iv",
            &[],
            12,
        ));
        self.server_seq = 0;
        self.server_cipher = AeadCipher::new(self.cipher, &server_key);

        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Tls13Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_buf_pos < this.read_buf.len() {
                let to_copy =
                    std::cmp::min(buf.remaining(), this.read_buf.len() - this.read_buf_pos);
                buf.put_slice(&this.read_buf[this.read_buf_pos..this.read_buf_pos + to_copy]);
                this.read_buf_pos += to_copy;
                if this.read_buf_pos == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_buf_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // Read 5-byte header
            if this.raw_read_buf.len() < 5 {
                let mut temp = [0u8; 5];
                let mut temp_buf = ReadBuf::new(&mut temp[..5 - this.raw_read_buf.len()]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            if this.raw_read_buf.is_empty() {
                                return Poll::Ready(Ok(())); // EOF
                            } else {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated TLS record header",
                                )));
                            }
                        }
                        this.raw_read_buf.extend_from_slice(temp_buf.filled());
                        if this.raw_read_buf.len() < 5 {
                            continue;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let rec_len = u16::from_be_bytes([this.raw_read_buf[3], this.raw_read_buf[4]]) as usize;
            if rec_len > 16384 + 256 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record overflow: record exceeds 16384 + 256 bytes",
                )));
            }
            if rec_len < 16 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record too short: less than AEAD tag size",
                )));
            }
            let total_len = 5 + rec_len;

            // Read record payload
            if this.raw_read_buf.len() < total_len {
                let needed = total_len - this.raw_read_buf.len();
                let mut chunk = vec![0u8; needed];
                let mut chunk_buf = ReadBuf::new(&mut chunk);
                match Pin::new(&mut this.inner).poll_read(cx, &mut chunk_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = chunk_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated TLS record payload",
                            )));
                        }
                        this.raw_read_buf.extend_from_slice(chunk_buf.filled());
                        if this.raw_read_buf.len() < total_len {
                            continue;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Decrypt complete record
            let nonce = compute_nonce(&this.client_app_iv, this.client_seq);
            this.client_seq += 1;

            let header = [
                this.raw_read_buf[0],
                this.raw_read_buf[1],
                this.raw_read_buf[2],
                this.raw_read_buf[3],
                this.raw_read_buf[4],
            ];
            let ciphertext = &this.raw_read_buf[5..total_len];
            this.scratch_buf.clear();
            this.scratch_buf.extend_from_slice(ciphertext);
            this.client_cipher
                .decrypt_in_place(&nonce, &header, &mut this.scratch_buf)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "TLS 1.3 decrypt failed")
                })?;

            this.raw_read_buf.drain(..total_len);

            let mut end = this.scratch_buf.len();
            while end > 0 && this.scratch_buf[end - 1] == 0 {
                end -= 1;
            }
            if end == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS 1.3 record has no content type",
                )));
            }
            let content_type = this.scratch_buf[end - 1];
            let data = &this.scratch_buf[..end - 1];

            match content_type {
                0x17 => {
                    this.read_buf.extend_from_slice(data);
                    this.read_buf_pos = 0;
                    // Loop to serve to caller
                }
                0x15 => {
                    if data.len() >= 2 && data[1] == 0x00 {
                        // close_notify
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "TLS alert received",
                    )));
                }
                0x16 => {
                    if data.len() >= 4 && data[0] == 0x18 {
                        let len = ((data[1] as usize) << 16)
                            | ((data[2] as usize) << 8)
                            | (data[3] as usize);
                        if len != 1 || data.len() < 5 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid KeyUpdate handshake length",
                            )));
                        }
                        let request_update = data[4];
                        if request_update > 1 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid KeyUpdateRequest value",
                            )));
                        }

                        if request_update == 1 {
                            this.queue_key_update()?;
                            if this.write_buf_pos < this.write_buf.len() {
                                let to_write = &this.write_buf[this.write_buf_pos..];
                                if let Poll::Ready(Ok(n)) =
                                    Pin::new(&mut this.inner).poll_write(cx, to_write)
                                {
                                    this.write_buf_pos += n;
                                    if this.write_buf_pos == this.write_buf.len() {
                                        this.write_buf.clear();
                                        this.write_buf_pos = 0;
                                    }
                                }
                            }
                        }

                        // Update client application traffic keys (RFC 8446 7.2)
                        let next_secret = hkdf_expand_label(
                            this.cipher,
                            &this.client_app_secret,
                            "traffic upd",
                            &[],
                            this.cipher.hash_len() as u16,
                        );
                        let client_key = hkdf_expand_label(
                            this.cipher,
                            &next_secret,
                            "key",
                            &[],
                            this.cipher.key_len() as u16,
                        );
                        let client_iv = hkdf_expand_label(this.cipher, &next_secret, "iv", &[], 12);
                        this.client_app_secret = next_secret;
                        this.client_app_iv.copy_from_slice(&client_iv);
                        this.client_seq = 0;
                        this.client_cipher = AeadCipher::new(this.cipher, &client_key);
                        continue;
                    }

                    let msg_type = data.first().copied().unwrap_or(0);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected post-handshake record type: 0x{msg_type:02x}"),
                    )));
                }
                other => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected content type: 0x{other:02x}"),
                    )));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Tls13Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        while this.write_buf_pos < this.write_buf.len() {
            let to_write = &this.write_buf[this.write_buf_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, to_write) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_pos += n;
                    if this.write_buf_pos == this.write_buf.len() {
                        this.write_buf.clear();
                        this.write_buf_pos = 0;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_size = std::cmp::min(buf.len(), 16384);
        let chunk = &buf[..chunk_size];

        let ct_len = chunk_size + 1 + 16;
        let header = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, (ct_len & 0xff) as u8];

        let nonce = compute_nonce(&this.server_app_iv, this.server_seq);
        this.server_seq += 1;

        this.scratch_buf.clear();
        this.scratch_buf.extend_from_slice(chunk);
        this.scratch_buf.push(0x17); // ApplicationData content type
        this.server_cipher
            .encrypt_in_place(&nonce, &header, &mut this.scratch_buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD encrypt failed"))?;

        this.write_buf.clear();
        this.write_buf.extend_from_slice(&header);
        this.write_buf.extend_from_slice(&this.scratch_buf);
        this.write_buf_pos = 0;

        while this.write_buf_pos < this.write_buf.len() {
            let to_write = &this.write_buf[this.write_buf_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, to_write) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_pos += n;
                    if this.write_buf_pos == this.write_buf.len() {
                        this.write_buf.clear();
                        this.write_buf_pos = 0;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        Poll::Ready(Ok(chunk_size))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.write_buf_pos < this.write_buf.len() {
            let to_write = &this.write_buf[this.write_buf_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, to_write) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_pos += n;
                    if this.write_buf_pos == this.write_buf.len() {
                        this.write_buf.clear();
                        this.write_buf_pos = 0;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VisionStreamIo for Tls13Stream<S> {
    fn poll_read_direct(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        if this.read_buf_pos < this.read_buf.len() {
            let to_copy =
                std::cmp::min(output.remaining(), this.read_buf.len() - this.read_buf_pos);
            output.put_slice(&this.read_buf[this.read_buf_pos..this.read_buf_pos + to_copy]);
            this.read_buf_pos += to_copy;
            if this.read_buf_pos == this.read_buf.len() {
                this.read_buf.clear();
                this.read_buf_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        if !this.raw_read_buf.is_empty() {
            let to_copy = std::cmp::min(output.remaining(), this.raw_read_buf.len());
            output.put_slice(&this.raw_read_buf[..to_copy]);
            this.raw_read_buf.drain(..to_copy);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.inner).poll_read(cx, output)
    }

    fn poll_write_direct(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        while this.write_buf_pos < this.write_buf.len() {
            let to_write = &this.write_buf[this.write_buf_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, to_write) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_pos += n;
                    if this.write_buf_pos == this.write_buf.len() {
                        this.write_buf.clear();
                        this.write_buf_pos = 0;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parse_server_hello_rejects_truncated() {
        let mut sh = vec![0u8; 38];
        sh[0] = 0x02;
        assert!(parse_server_hello(&sh).is_none());
    }

    #[tokio::test]
    async fn rejects_empty_short_ids() {
        let settings = RealityInboundSettings {
            dest: FallbackDest::Tcp(crate::vless::Host::Domain("localhost".into()), 80),
            server_names: vec!["example.com".to_string()],
            private_key: [0x11; 32],
            short_ids: vec![],
            min_client_ver: None,
            max_client_ver: None,
            max_time_diff: 0,
            xver: 0,
            show: false,
            alpn: vec![],
            mldsa65_seed: None,
        };
        let err = RealityServer::new(settings, 443, false, false)
            .err()
            .unwrap();
        assert_eq!(err, r#"empty "shortIds""#);
    }

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
            mldsa65_seed: None,
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
            while let Ok((mut socket, _)) = dest_listener.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = socket.read(&mut buf).await {
                    if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                        if s.contains("GET /probe") {
                            let _ = socket
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                                .await;
                            break;
                        }
                    }
                }
            }
        });

        let settings = RealityInboundSettings {
            dest: FallbackDest::Tcp(
                crate::vless::Host::Ip("127.0.0.1".parse().unwrap()),
                dest_port,
            ),
            server_names: vec!["example.com".to_string()],
            private_key: [0x11; 32],
            short_ids: vec![[0u8; 8]],
            min_client_ver: None,
            max_client_ver: None,
            max_time_diff: 0,
            xver: 0,
            show: false,
            alpn: vec![],
            mldsa65_seed: None,
        };
        let srv = RealityServer::new(settings, 8443, false, false).unwrap();

        let srv_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv_listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(srv_addr).await.unwrap();
            client
                .write_all(b"GET /probe HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            client.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let (inbound_stream, peer) = srv_listener.accept().await.unwrap();
        let res = srv.handle(inbound_stream, peer).await.unwrap();
        assert!(res.is_none()); // Was handled via fallback

        let resp_bytes = client_task.await.unwrap();
        assert!(std::str::from_utf8(&resp_bytes)
            .unwrap()
            .contains("HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn test_reality_post_handshake_records_lens_probe() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["test.local".to_string()]).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.into()], key_der)
            .unwrap();

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            // Send 2 dummy post-handshake records with exact lengths 120 and 180
            // Outer header is 23 03 03 len_hi len_lo
            let mut r1 = vec![0u8; 120];
            r1[0] = 23;
            r1[1] = 3;
            r1[2] = 3;
            let ct_len1 = 120 - 5;
            r1[3] = (ct_len1 >> 8) as u8;
            r1[4] = (ct_len1 & 0xff) as u8;

            let mut r2 = vec![0u8; 180];
            r2[0] = 23;
            r2[1] = 3;
            r2[2] = 3;
            let ct_len2 = 180 - 5;
            r2[3] = (ct_len2 >> 8) as u8;
            r2[4] = (ct_len2 & 0xff) as u8;

            let (raw, _) = tls.get_mut();
            raw.write_all(&r1).await.unwrap();
            raw.write_all(&r2).await.unwrap();
            raw.flush().await.unwrap();
        });

        let dest = FallbackDest::Tcp(
            crate::vless::Host::Ip("127.0.0.1".parse().unwrap()),
            dest_port,
        );
        let lens = probe_dest_post_handshake_lens(&dest, 0, "test.local", 2)
            .await
            .unwrap();
        // 184 is rustls server's automatic NewSessionTicket, followed by the two dummy records
        assert_eq!(lens, vec![184, 120, 180]);
    }

    #[tokio::test]
    async fn test_tls13_stream_bounds_inbound_records() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let cipher = CipherType::Aes128Gcm;
        let client_secret = vec![1u8; 32];
        let server_secret = vec![2u8; 32];
        let client_key = hkdf_expand_label(cipher, &client_secret, "key", &[], 16);
        let server_key = hkdf_expand_label(cipher, &server_secret, "key", &[], 16);

        let mut stream = Tls13Stream {
            inner: server_io,
            cipher,
            client_app_secret: client_secret,
            client_app_iv: [3u8; 12],
            client_seq: 0,
            client_cipher: AeadCipher::new(cipher, &client_key),
            server_app_secret: server_secret,
            server_app_iv: [4u8; 12],
            server_seq: 0,
            server_cipher: AeadCipher::new(cipher, &server_key),
            read_buf: Vec::new(),
            read_buf_pos: 0,
            raw_read_buf: Vec::new(),
            write_buf: Vec::new(),
            write_buf_pos: 0,
            scratch_buf: Vec::new(),
            handshake: Box::default(),
        };

        // Client writes header with length > 16384 + 256 = 16640
        let (_client_r, mut client_w) = tokio::io::split(client_io);
        let oversized_len: u16 = 16641;
        let mut hdr = [0x17, 0x03, 0x03, 0, 0];
        hdr[3] = (oversized_len >> 8) as u8;
        hdr[4] = (oversized_len & 0xff) as u8;
        client_w.write_all(&hdr).await.unwrap();

        let mut buf = [0u8; 128];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("record overflow"));
    }

    #[tokio::test]
    async fn test_tls13_stream_rejects_unexpected_handshake() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let cipher = CipherType::Aes128Gcm;
        let client_secret = vec![1u8; 32];
        let server_secret = vec![2u8; 32];
        let client_key = hkdf_expand_label(cipher, &client_secret, "key", &[], 16);
        let server_key = hkdf_expand_label(cipher, &server_secret, "key", &[], 16);
        let client_iv = [3u8; 12];
        let client_cipher = AeadCipher::new(cipher, &client_key);

        let mut stream = Tls13Stream {
            inner: server_io,
            cipher,
            client_app_secret: client_secret,
            client_app_iv: client_iv,
            client_seq: 0,
            client_cipher,
            server_app_secret: server_secret,
            server_app_iv: [4u8; 12],
            server_seq: 0,
            server_cipher: AeadCipher::new(cipher, &server_key),
            read_buf: Vec::new(),
            read_buf_pos: 0,
            raw_read_buf: Vec::new(),
            write_buf: Vec::new(),
            write_buf_pos: 0,
            scratch_buf: Vec::new(),
            handshake: Box::default(),
        };

        // Client sends an unexpected handshake record: ClientHello (type 0x01)
        let mut unexpected_hs = vec![0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        unexpected_hs.push(0x16); // content type Handshake
        let nonce = compute_nonce(&client_iv, 0);
        let ct_len = unexpected_hs.len() + 16;
        let hdr = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, (ct_len & 0xff) as u8];
        let ct = AeadCipher::new(cipher, &client_key)
            .encrypt(&nonce, &hdr, &unexpected_hs)
            .unwrap();

        let (_client_r, mut client_w) = tokio::io::split(client_io);
        client_w.write_all(&hdr).await.unwrap();
        client_w.write_all(&ct).await.unwrap();

        let mut buf = [0u8; 128];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("unexpected post-handshake record"));
    }

    #[tokio::test]
    async fn test_tls13_stream_handles_key_update() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let cipher = CipherType::Aes128Gcm;
        let mut client_secret = vec![1u8; 32];
        let mut server_secret = vec![2u8; 32];
        let client_key = hkdf_expand_label(cipher, &client_secret, "key", &[], 16);
        let server_key = hkdf_expand_label(cipher, &server_secret, "key", &[], 16);
        let mut client_iv = [3u8; 12];
        let mut server_iv = [4u8; 12];
        let mut client_seq = 0u64;

        let mut stream = Tls13Stream {
            inner: server_io,
            cipher,
            client_app_secret: client_secret.clone(),
            client_app_iv: client_iv,
            client_seq: 0,
            client_cipher: AeadCipher::new(cipher, &client_key),
            server_app_secret: server_secret.clone(),
            server_app_iv: server_iv,
            server_seq: 0,
            server_cipher: AeadCipher::new(cipher, &server_key),
            read_buf: Vec::new(),
            read_buf_pos: 0,
            raw_read_buf: Vec::new(),
            write_buf: Vec::new(),
            write_buf_pos: 0,
            scratch_buf: Vec::new(),
            handshake: Box::default(),
        };

        let (mut client_r, mut client_w) = tokio::io::split(client_io);

        // 1. Client sends KeyUpdate with request_update = 1 (update_requested)
        let mut key_update = vec![0x18, 0x00, 0x00, 0x01, 0x01];
        key_update.push(0x16); // ContentType Handshake
        let nonce = compute_nonce(&client_iv, client_seq);
        let ct_len = key_update.len() + 16;
        let hdr = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, (ct_len & 0xff) as u8];
        let ct = AeadCipher::new(cipher, &client_key)
            .encrypt(&nonce, &hdr, &key_update)
            .unwrap();
        client_w.write_all(&hdr).await.unwrap();
        client_w.write_all(&ct).await.unwrap();

        // 2. Client derives its next generation secret and key
        client_secret = hkdf_expand_label(cipher, &client_secret, "traffic upd", &[], 32);
        let next_client_key = hkdf_expand_label(cipher, &client_secret, "key", &[], 16);
        client_iv.copy_from_slice(&hkdf_expand_label(cipher, &client_secret, "iv", &[], 12));
        client_seq = 0; // reset

        // 3. Client sends application data encrypted with next generation key
        let mut app_data = b"ping after key update".to_vec();
        app_data.push(0x17); // ContentType ApplicationData
        let nonce = compute_nonce(&client_iv, client_seq);
        let _ = client_seq; // sequence used for nonce
        let ct_len = app_data.len() + 16;
        let hdr = [0x17, 0x03, 0x03, (ct_len >> 8) as u8, (ct_len & 0xff) as u8];
        let ct = AeadCipher::new(cipher, &next_client_key)
            .encrypt(&nonce, &hdr, &app_data)
            .unwrap();
        client_w.write_all(&hdr).await.unwrap();
        client_w.write_all(&ct).await.unwrap();

        // 4. Server reads the application data (KeyUpdate was handled transparently)
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping after key update");

        // 5. Verify server responded with its own KeyUpdate (request_update = 0)
        let mut srv_hdr = [0u8; 5];
        client_r.read_exact(&mut srv_hdr).await.unwrap();
        assert_eq!(&srv_hdr[..3], &[0x17, 0x03, 0x03]);
        let srv_rec_len = u16::from_be_bytes([srv_hdr[3], srv_hdr[4]]) as usize;
        let mut srv_ct = vec![0u8; srv_rec_len];
        client_r.read_exact(&mut srv_ct).await.unwrap();

        // Decrypt server KeyUpdate with initial server key
        let srv_nonce = compute_nonce(&server_iv, 0);
        let srv_pt = AeadCipher::new(cipher, &server_key)
            .decrypt(&srv_nonce, &srv_hdr, &srv_ct)
            .unwrap();
        assert_eq!(srv_pt.last(), Some(&0x16)); // Handshake
        assert_eq!(&srv_pt[..5], &[0x18, 0x00, 0x00, 0x01, 0x00]); // KeyUpdate(update_not_requested)

        // 6. Server sends application data using next generation key
        stream.write_all(b"pong from server").await.unwrap();
        stream.flush().await.unwrap();

        // Client derives server's next generation secret and key
        server_secret = hkdf_expand_label(cipher, &server_secret, "traffic upd", &[], 32);
        let next_server_key = hkdf_expand_label(cipher, &server_secret, "key", &[], 16);
        server_iv.copy_from_slice(&hkdf_expand_label(cipher, &server_secret, "iv", &[], 12));

        let mut srv_app_hdr = [0u8; 5];
        client_r.read_exact(&mut srv_app_hdr).await.unwrap();
        let srv_app_len = u16::from_be_bytes([srv_app_hdr[3], srv_app_hdr[4]]) as usize;
        let mut srv_app_ct = vec![0u8; srv_app_len];
        client_r.read_exact(&mut srv_app_ct).await.unwrap();

        let srv_app_nonce = compute_nonce(&server_iv, 0);
        let srv_app_pt = AeadCipher::new(cipher, &next_server_key)
            .decrypt(&srv_app_nonce, &srv_app_hdr, &srv_app_ct)
            .unwrap();
        assert_eq!(srv_app_pt.last(), Some(&0x17));
        assert_eq!(&srv_app_pt[..srv_app_pt.len() - 1], b"pong from server");
    }
}
