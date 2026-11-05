//! Inbound VMess server handshake, codecs, and connection stream.

use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fmt, io};

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use xray_routing::{Network, Target, TargetAddr};
use zeroize::{Zeroize, Zeroizing};

use super::records::Records;
use super::stream::{ReadState, WriteState};
use super::{crypto, invalid, Cipher, Options};

/// Precomputed user cryptographic credentials for VMess inbound authentication.
#[derive(Clone)]
pub struct ServerUser {
    pub email: String,
    pub command_key: Zeroizing<[u8; 16]>,
    auth_decryptor: aes::Aes128,
}

impl fmt::Debug for ServerUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerUser")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

impl ServerUser {
    pub fn new(id: &[u8; 16], email: String) -> Self {
        let mut material = Zeroizing::new(id.to_vec());
        material.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let command_key = crypto::md5(&material);
        let auth_key = crypto::kdf(&*command_key, &[b"AES Auth ID Encryption"]);
        let auth_decryptor = aes::Aes128::new_from_slice(&auth_key[..16]).unwrap();
        Self {
            email,
            command_key,
            auth_decryptor,
        }
    }
}

/// The result of a successful VMess server handshake.
pub struct ServerHandshake {
    pub user_index: usize,
    pub network: Network,
    pub target: Target,
    pub cipher: Cipher,
    pub options: Options,
    pub request_key: Zeroizing<[u8; 16]>,
    pub request_iv: Zeroizing<[u8; 16]>,
    pub response_key: Zeroizing<[u8; 16]>,
    pub response_iv: Zeroizing<[u8; 16]>,
    pub response_header: Vec<u8>,
}

/// Performs a VMess AEAD inbound handshake on the given stream against the list of authorized users.
pub async fn handshake<S: AsyncRead + Unpin>(
    stream: &mut S,
    users: &[ServerUser],
) -> io::Result<ServerHandshake> {
    if users.is_empty() {
        return Err(invalid("no VMess users configured"));
    }

    // Step 1: Read Auth ID (16 bytes)
    let mut auth_id = [0u8; 16];
    stream.read_exact(&mut auth_id).await?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system time before unix epoch"))?
        .as_secs();

    let mut matched = None;
    for (idx, user) in users.iter().enumerate() {
        let mut plain = auth_id;
        user.auth_decryptor.decrypt_block((&mut plain).into());
        let timestamp = u64::from_be_bytes(plain[0..8].try_into().unwrap());
        let crc = u32::from_be_bytes(plain[12..16].try_into().unwrap());
        if crc == crc32fast::hash(&plain[..12]) && timestamp.abs_diff(now) <= 120 {
            matched = Some((idx, user));
            break;
        }
    }

    let (user_index, user) = matched.ok_or_else(|| invalid("VMess auth_id mismatch or expired"))?;

    // Step 2: Read Length (18 bytes) and Connection Nonce (8 bytes) = 26 bytes
    let mut length_and_nonce = [0u8; 26];
    stream.read_exact(&mut length_and_nonce).await?;
    let length_bytes = &length_and_nonce[..18];
    let connection_nonce = &length_and_nonce[18..26];

    let (aead_len, nonce_len) = crypto::header_aead(
        &*user.command_key,
        &*user.command_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, connection_nonce],
        &[b"VMess Header AEAD Nonce_Length", &auth_id, connection_nonce],
    );
    let mut length_buf = length_bytes.to_vec();
    aead_len.open(&nonce_len, &auth_id, &mut length_buf)?;
    let plain_len = u16::from_be_bytes(length_buf[..2].try_into().unwrap()) as usize;
    if !(42..=1024).contains(&plain_len) {
        return Err(invalid("invalid VMess request header length"));
    }

    // Step 3: Read encrypted request header payload (plain_len + 16 bytes tag)
    let mut enc_plain = vec![0u8; plain_len + 16];
    stream.read_exact(&mut enc_plain).await?;

    let (aead_hdr, nonce_hdr) = crypto::header_aead(
        &*user.command_key,
        &*user.command_key,
        &[b"VMess Header AEAD Key", &auth_id, connection_nonce],
        &[b"VMess Header AEAD Nonce", &auth_id, connection_nonce],
    );
    let n = aead_hdr.open(&nonce_hdr, &auth_id, &mut enc_plain)?;
    enc_plain.truncate(n);
    let mut plain = Zeroizing::new(enc_plain);

    // Step 4: Parse request header fields
    if plain.len() < 42 || plain[0] != 1 {
        return Err(invalid("invalid VMess version or truncated header"));
    }
    let request_iv: Zeroizing<[u8; 16]> = Zeroizing::new(plain[1..17].try_into().unwrap());
    let request_key: Zeroizing<[u8; 16]> = Zeroizing::new(plain[17..33].try_into().unwrap());
    let response_marker = plain[33];
    let options_wire = plain[34];
    let padding_and_cipher = plain[35];
    let padding_len = (padding_and_cipher >> 4) as usize;
    let cipher_wire = padding_and_cipher & 0x0f;
    let cmd = plain[37];
    let network = match cmd {
        1 => Network::Tcp,
        2 => Network::Udp,
        _ => return Err(invalid("unsupported VMess command")),
    };
    let port = u16::from_be_bytes([plain[38], plain[39]]);
    let atype = plain[40];
    let (target_addr, addr_len) = match atype {
        1 => {
            if plain.len() < 45 {
                return Err(invalid("VMess IPv4 truncated"));
            }
            let octets: [u8; 4] = plain[41..45].try_into().unwrap();
            (TargetAddr::Ip(IpAddr::V4(octets.into())), 4)
        }
        2 => {
            if plain.len() < 42 {
                return Err(invalid("VMess domain length truncated"));
            }
            let dlen = plain[41] as usize;
            if plain.len() < 42 + dlen {
                return Err(invalid("VMess domain truncated"));
            }
            let domain = std::str::from_utf8(&plain[42..42 + dlen])
                .map_err(|_| invalid("invalid VMess domain utf-8"))?
                .to_string();
            (TargetAddr::Domain(domain), 1 + dlen)
        }
        3 => {
            if plain.len() < 57 {
                return Err(invalid("VMess IPv6 truncated"));
            }
            let octets: [u8; 16] = plain[41..57].try_into().unwrap();
            (TargetAddr::Ip(IpAddr::V6(octets.into())), 16)
        }
        _ => return Err(invalid("unsupported VMess address type")),
    };

    let hash_start = 41 + addr_len + padding_len;
    if plain.len() != hash_start + 4 {
        return Err(invalid("VMess header size mismatch"));
    }
    let hash = plain[..hash_start].iter().fold(0x811c9dc5u32, |h, b| {
        (h ^ u32::from(*b)).wrapping_mul(0x1000193)
    });
    if hash.to_be_bytes() != plain[hash_start..hash_start + 4] {
        return Err(invalid("VMess FNV1a checksum mismatch"));
    }

    plain.zeroize();

    let cipher = match cipher_wire {
        3 => Cipher::Aes128Gcm,
        4 => Cipher::ChaCha20Poly1305,
        _ => return Err(invalid("unsupported VMess cipher")),
    };
    let options = Options {
        authenticated_length: (options_wire & 0x10) != 0,
        no_termination_signal: false,
    };
    let target = Target::new(target_addr, port, network);

    // Step 5: Derive response key, IV, and seal the 38-byte response header
    let response_key: Zeroizing<[u8; 16]> =
        Zeroizing::new(crypto::sha256(&*request_key)[..16].try_into().unwrap());
    let response_iv: Zeroizing<[u8; 16]> =
        Zeroizing::new(crypto::sha256(&*request_iv)[..16].try_into().unwrap());

    let (cipher_len, nonce_len) = crypto::header_aead(
        &*response_key,
        &*response_iv,
        &[b"AEAD Resp Header Len Key"],
        &[b"AEAD Resp Header Len IV"],
    );
    let mut len_buf = (4u16).to_be_bytes().to_vec();
    cipher_len.seal(&nonce_len, &[], &mut len_buf)?;

    let (cipher_hdr, nonce_hdr) = crypto::header_aead(
        &*response_key,
        &*response_iv,
        &[b"AEAD Resp Header Key"],
        &[b"AEAD Resp Header IV"],
    );
    let mut hdr_buf = vec![response_marker, 0, 0, 0];
    cipher_hdr.seal(&nonce_hdr, &[], &mut hdr_buf)?;

    let mut response_header = Vec::with_capacity(38);
    response_header.extend_from_slice(&len_buf);
    response_header.extend_from_slice(&hdr_buf);

    Ok(ServerHandshake {
        user_index,
        network,
        target,
        cipher,
        options,
        request_key,
        request_iv,
        response_key,
        response_iv,
        response_header,
    })
}

/// Read half of a VMess server connection.
pub struct ServerReadHalf<S> {
    inner: S,
    state: ReadState,
}

impl<S: AsyncRead + Unpin> AsyncRead for ServerReadHalf<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state
            .poll_read(&mut this.inner, cx, out, |_, _| Ok(()))
    }
}

/// Write half of a VMess server connection.
pub struct ServerWriteHalf<S> {
    inner: S,
    state: WriteState,
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ServerWriteHalf<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.state.poll_write(&mut this.inner, cx, data, true)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state.poll_flush(&mut this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state.poll_shutdown(&mut this.inner, cx)
    }
}

/// Combined full-duplex VMess server connection stream.
pub struct ServerStream<S> {
    inner: S,
    read: ReadState,
    write: WriteState,
}

impl<S> ServerStream<S> {
    pub fn from_handshake(inner: S, handshake: &ServerHandshake) -> Self {
        let packet = handshake.network == Network::Udp;
        let auth_length = if handshake.options.authenticated_length {
            Some((&*handshake.request_key, &*handshake.request_iv))
        } else {
            None
        };
        let reader = Records::new(
            handshake.cipher,
            &handshake.request_key,
            &handshake.request_iv,
            auth_length,
        );
        let writer = Records::new(
            handshake.cipher,
            &handshake.response_key,
            &handshake.response_iv,
            auth_length,
        );
        let read = ReadState::new_server(reader, handshake.options, packet);
        let write = WriteState::new_server(
            writer,
            handshake.options,
            packet,
            handshake.response_header.clone(),
        );
        Self { inner, read, write }
    }

    pub fn split_from_handshake<R, W>(
        reader_io: R,
        writer_io: W,
        handshake: &ServerHandshake,
    ) -> (ServerReadHalf<R>, ServerWriteHalf<W>) {
        let packet = handshake.network == Network::Udp;
        let auth_length = if handshake.options.authenticated_length {
            Some((&*handshake.request_key, &*handshake.request_iv))
        } else {
            None
        };
        let reader = Records::new(
            handshake.cipher,
            &handshake.request_key,
            &handshake.request_iv,
            auth_length,
        );
        let writer = Records::new(
            handshake.cipher,
            &handshake.response_key,
            &handshake.response_iv,
            auth_length,
        );
        (
            ServerReadHalf {
                inner: reader_io,
                state: ReadState::new_server(reader, handshake.options, packet),
            },
            ServerWriteHalf {
                inner: writer_io,
                state: WriteState::new_server(
                    writer,
                    handshake.options,
                    packet,
                    handshake.response_header.clone(),
                ),
            },
        )
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ServerStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write.is_failed() {
            this.read.set_failed();
        }
        this.read.poll_read(&mut this.inner, cx, out, |inner, cx| {
            match this.write.drain(inner, cx) {
                Poll::Ready(result) => result,
                Poll::Pending => Ok(()),
            }
        })
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ServerStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.read.is_failed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        this.write.poll_write(&mut this.inner, cx, data, false)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read.is_failed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        this.write.poll_flush(&mut this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write.poll_shutdown(&mut this.inner, cx)
    }
}
