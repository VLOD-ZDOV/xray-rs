use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, KeyGen, SerDes};
use rand::{rngs::OsRng, RngCore};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    config::{ConfigError, XorMode, MAX_CONFIG_BYTES, MAX_KEYS},
    crypto::{Aead, CipherSuite, HeaderMask},
    crypto_error,
    handshake::{agree, x25519_secret},
    invalid_data,
    padding::Padding,
    EncryptedStream,
};

pub(crate) enum ServerKey {
    X25519 {
        secret: StaticSecret,
        public_bytes: [u8; 32],
        hash32: [u8; 32],
    },
    MlKem768 {
        decaps_key: Box<ml_kem_768::DecapsKey>,
        encaps_bytes: Box<[u8; 1184]>,
        hash32: [u8; 32],
    },
}

impl ServerKey {
    fn public_bytes(&self) -> &[u8] {
        match self {
            Self::X25519 { public_bytes, .. } => public_bytes,
            Self::MlKem768 { encaps_bytes, .. } => encaps_bytes.as_slice(),
        }
    }

    fn hash32(&self) -> &[u8; 32] {
        match self {
            Self::X25519 { hash32, .. } | Self::MlKem768 { hash32, .. } => hash32,
        }
    }

    fn relay_len(&self) -> usize {
        match self {
            Self::X25519 { .. } => 32,
            Self::MlKem768 { .. } => 1088,
        }
    }
}

pub struct ServerConfig {
    pub(crate) mode: XorMode,
    pub(crate) seconds_from: u32,
    pub(crate) seconds_to: u32,
    pub(crate) padding: Padding,
    pub(crate) keys: Vec<ServerKey>,
    pub(crate) relays_len: usize,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessEncryptionServerConfig")
            .field("mode", &self.mode)
            .field("seconds_from", &self.seconds_from)
            .field("seconds_to", &self.seconds_to)
            .field("key_count", &self.keys.len())
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl FromStr for ServerConfig {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Scheme);
        }
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
            return Err(ConfigError::Scheme);
        }
        let mode = match parts[1] {
            "native" => XorMode::Native,
            "xorpub" => XorMode::XorPub,
            "random" => XorMode::Random,
            _ => return Err(ConfigError::Mode),
        };
        let sec_str = parts[2].trim_end_matches('s');
        let (seconds_from, seconds_to) = if let Some((from_str, to_str)) = sec_str.split_once('-') {
            let from = from_str.parse::<u32>().map_err(|_| ConfigError::Rtt)?;
            let to = to_str.parse::<u32>().map_err(|_| ConfigError::Rtt)?;
            (from, to)
        } else {
            let sec = sec_str.parse::<u32>().map_err(|_| ConfigError::Rtt)?;
            (sec, sec)
        };

        let mut padding_tokens = Vec::new();
        let mut key_tokens = Vec::new();
        for token in &parts[3..] {
            if token.len() < 20 {
                padding_tokens.push(*token);
            } else {
                key_tokens.push(*token);
            }
        }

        if key_tokens.is_empty() || key_tokens.len() > MAX_KEYS {
            return Err(ConfigError::Shape);
        }

        let padding = if padding_tokens.is_empty() {
            Padding::default()
        } else {
            Padding::parse(&padding_tokens)?
        };

        let mut keys = Vec::with_capacity(key_tokens.len());
        let mut relays_len = 0;
        for (i, token) in key_tokens.into_iter().enumerate() {
            let bytes = URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| ConfigError::PublicKey)?;
            match bytes.len() {
                32 => {
                    let mut secret_bytes = [0u8; 32];
                    secret_bytes.copy_from_slice(&bytes);
                    let secret = StaticSecret::from(secret_bytes);
                    let public = PublicKey::from(&secret);
                    let hash32 = *blake3::hash(public.as_bytes()).as_bytes();
                    keys.push(ServerKey::X25519 {
                        secret,
                        public_bytes: *public.as_bytes(),
                        hash32,
                    });
                    relays_len += 32;
                }
                64 => {
                    let d: [u8; 32] = bytes[..32].try_into().unwrap();
                    let z: [u8; 32] = bytes[32..].try_into().unwrap();
                    let (ek, dk) = ml_kem_768::KG::keygen_from_seed(d, z);
                    let encaps_bytes: [u8; 1184] = ek.into_bytes();
                    let hash32 = *blake3::hash(&encaps_bytes).as_bytes();
                    keys.push(ServerKey::MlKem768 {
                        decaps_key: Box::new(dk),
                        encaps_bytes: Box::new(encaps_bytes),
                        hash32,
                    });
                    relays_len += 1088;
                }
                _ => return Err(ConfigError::PublicKey),
            }
            if i < parts[3..].len().saturating_sub(padding_tokens.len()) - 1 {
                relays_len += 32; // next key hash
            }
        }

        Ok(Self {
            mode,
            seconds_from,
            seconds_to,
            padding,
            keys,
            relays_len,
        })
    }
}

struct SessionEntry {
    pfs_key: Zeroizing<[u8; 64]>,
    used_nfs_keys: HashSet<[u8; 32]>,
    expires: Instant,
}

#[derive(Clone)]
pub struct Server {
    config: Arc<ServerConfig>,
    sessions: Arc<Mutex<HashMap<[u8; 16], SessionEntry>>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("mode", &self.config.mode)
            .field("relays_len", &self.config.relays_len)
            .finish()
    }
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
    ) -> io::Result<EncryptedStream<S>> {
        let relays_len = self.config.relays_len;
        let mut iv_and_relays = vec![0u8; 16 + relays_len];
        stream.read_exact(&mut iv_and_relays).await?;

        let iv: [u8; 16] = iv_and_relays[..16].try_into().unwrap();
        let mut relays = &mut iv_and_relays[16..];

        let mut nfs_key = Zeroizing::new([0u8; 32]);
        let mut last_mask: Option<HeaderMask> = None;

        for (j, key) in self.config.keys.iter().enumerate() {
            if let Some(mask) = &mut last_mask {
                mask.apply(&mut relays[..32])?;
            }
            let key_len = key.relay_len();
            if self.config.mode != XorMode::Native {
                HeaderMask::new(key.public_bytes(), &iv).apply(&mut relays[..key_len])?;
            }

            match key {
                ServerKey::X25519 { secret, .. } => {
                    if relays[31] > 127 {
                        return Err(invalid_data());
                    }
                    let peer_pub: [u8; 32] = relays[..32].try_into().map_err(|_| invalid_data())?;
                    let shared = secret.diffie_hellman(&PublicKey::from(peer_pub));
                    if !shared.was_contributory() {
                        return Err(invalid_data());
                    }
                    nfs_key.copy_from_slice(shared.as_bytes());
                }
                ServerKey::MlKem768 { decaps_key, .. } => {
                    let ct_bytes: [u8; 1088] =
                        relays[..1088].try_into().map_err(|_| invalid_data())?;
                    let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes)
                        .map_err(|_| invalid_data())?;
                    let shared = decaps_key.try_decaps(&ct).map_err(|_| invalid_data())?;
                    nfs_key.copy_from_slice(&shared.into_bytes());
                }
            }

            if j < self.config.keys.len() - 1 {
                relays = &mut relays[key_len..];
                let mut next_mask = HeaderMask::new(nfs_key.as_ref(), &iv);
                next_mask.apply(&mut relays[..32])?;
                if relays[..32] != *self.config.keys[j + 1].hash32() {
                    return Err(invalid_data());
                }
                relays = &mut relays[32..];
                last_mask = Some(next_mask);
            }
        }

        // Determine AEAD cipher suite (AES-256-GCM or ChaCha20-Poly1305)
        let mut encrypted_len = [0u8; 18];
        stream.read_exact(&mut encrypted_len).await?;

        let mut suite = CipherSuite::Aes256Gcm;
        let mut nfs_aead = Aead::new(&iv, nfs_key.as_ref(), suite)?;
        let mut len_buf = encrypted_len;
        if nfs_aead.open(&mut len_buf, &[]).is_err() {
            suite = CipherSuite::ChaCha20Poly1305;
            nfs_aead = Aead::new(&iv, nfs_key.as_ref(), suite)?;
            len_buf = encrypted_len;
            nfs_aead.open(&mut len_buf, &[])?;
        }

        let length = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;

        // 0-RTT branch
        if length == 32 {
            if self.config.seconds_from == 0 && self.config.seconds_to == 0 {
                return Err(io::Error::other("0-RTT is not allowed"));
            }
            let mut enc_ticket = [0u8; 32];
            stream.read_exact(&mut enc_ticket).await?;
            let mut ticket_buf = enc_ticket;
            nfs_aead.open(&mut ticket_buf, &[])?;
            let ticket: [u8; 16] = ticket_buf[..16].try_into().map_err(|_| invalid_data())?;

            enum SessionLookup {
                Found(Zeroizing<[u8; 64]>),
                Replay,
                Expired,
            }

            let lookup = {
                let now = Instant::now();
                let mut lock = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
                lock.retain(|_, s| s.expires > now);
                match lock.get_mut(&ticket) {
                    Some(session) => {
                        if !session.used_nfs_keys.insert(*nfs_key) {
                            SessionLookup::Replay
                        } else {
                            SessionLookup::Found(session.pfs_key.clone())
                        }
                    }
                    None => SessionLookup::Expired,
                }
            };

            let pfs_key = match lookup {
                SessionLookup::Found(pfs) => pfs,
                SessionLookup::Replay => return Err(io::Error::other("replay detected")),
                SessionLookup::Expired => {
                    let noise_len = between(1279, 2279) as usize;
                    let mut noise = vec![0u8; noise_len];
                    OsRng.fill_bytes(&mut noise);
                    let _ = stream.write_all(&noise).await;
                    return Err(io::Error::other("expired ticket"));
                }
            };

            let mut united_key = Zeroizing::new([0u8; 96]);
            united_key[..64].copy_from_slice(pfs_key.as_ref());
            united_key[64..].copy_from_slice(nfs_key.as_ref());

            let mut prewrite = [0u8; 16];
            OsRng.fill_bytes(&mut prewrite);

            let write_aead = Aead::new(&prewrite, united_key.as_ref(), suite)?;
            let read_aead = Aead::new(&enc_ticket, united_key.as_ref(), suite)?;

            let masks = if self.config.mode == XorMode::Random {
                Some((
                    HeaderMask::new(united_key.as_ref(), &prewrite),
                    HeaderMask::new(united_key.as_ref(), &iv),
                ))
            } else {
                None
            };

            let mut encrypted =
                EncryptedStream::new(stream, united_key, write_aead, Some(read_aead), masks, 0);
            encrypted.set_prewrite(prewrite.to_vec());
            return Ok(encrypted);
        }

        // 1-RTT branch
        if length < 1232 {
            return Err(invalid_data());
        }

        let mut encrypted_client_pfs = vec![0u8; length];
        stream.read_exact(&mut encrypted_client_pfs).await?;
        nfs_aead.open(&mut encrypted_client_pfs, &[])?;
        let client_pfs = &encrypted_client_pfs[..1216];

        let ek_bytes = &client_pfs[..1184];
        let ek = EncapsulationKey::new(&ML_KEM_768, ek_bytes).map_err(|_| invalid_data())?;
        let (ciphertext, mlkem_shared) = ek.encapsulate().map_err(|_| crypto_error())?;

        let client_x_pub: [u8; 32] = client_pfs[1184..1216]
            .try_into()
            .map_err(|_| invalid_data())?;
        let x_secret = x25519_secret()?;
        let x_shared = agree(&x_secret, &client_x_pub)?;
        let server_x_pub = PublicKey::from(&x_secret);

        let mut pfs_key = [0u8; 64];
        pfs_key[..32].copy_from_slice(mlkem_shared.as_ref());
        pfs_key[32..].copy_from_slice(x_shared.as_bytes());

        let mut pfs_public_key = Vec::with_capacity(1088 + 32);
        pfs_public_key.extend_from_slice(ciphertext.as_ref());
        pfs_public_key.extend_from_slice(server_x_pub.as_bytes());

        let mut united_key = Zeroizing::new([0u8; 96]);
        united_key[..64].copy_from_slice(&pfs_key);
        united_key[64..].copy_from_slice(nfs_key.as_ref());

        let mut write_aead = Aead::new(&pfs_public_key, united_key.as_ref(), suite)?;
        let read_aead = Aead::new(client_pfs, united_key.as_ref(), suite)?;

        let mut ticket = [0u8; 16];
        OsRng.fill_bytes(&mut ticket);
        let seconds = if self.config.seconds_from == 0 && self.config.seconds_to == 0 {
            0u16
        } else if self.config.seconds_to == 0 {
            (u64::from(self.config.seconds_from) * u64::from(between(50, 100)) / 100) as u16
        } else {
            between(self.config.seconds_from, self.config.seconds_to) as u16
        };
        ticket[..2].copy_from_slice(&seconds.to_be_bytes());

        if seconds > 0 {
            let mut lock = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            lock.insert(
                ticket,
                SessionEntry {
                    pfs_key: Zeroizing::new(pfs_key),
                    used_nfs_keys: HashSet::new(),
                    expires: Instant::now() + Duration::from_secs(u64::from(seconds)),
                },
            );
        }

        let mut server_pfs = pfs_public_key.clone();
        nfs_aead.seal_server_hello(&mut server_pfs)?;

        let mut sealed_ticket = ticket.to_vec();
        write_aead.seal(&mut sealed_ticket, &[])?;

        let padding_plan = self.config.padding.sample()?;
        let padding_len = padding_plan.total;
        let mut pad_len_buf = ((padding_len.saturating_sub(18)) as u16)
            .to_be_bytes()
            .to_vec();
        write_aead.seal(&mut pad_len_buf, &[])?;

        let mut pad_body = vec![0u8; padding_len.saturating_sub(34)];
        write_aead.seal(&mut pad_body, &[])?;

        let mut server_hello = Vec::with_capacity(
            server_pfs.len() + sealed_ticket.len() + pad_len_buf.len() + pad_body.len(),
        );
        server_hello.extend_from_slice(&server_pfs);
        server_hello.extend_from_slice(&sealed_ticket);
        server_hello.extend_from_slice(&pad_len_buf);
        server_hello.extend_from_slice(&pad_body);

        let prefix_len = server_pfs.len() + sealed_ticket.len();
        let mut position = 0;
        for (index, length) in padding_plan.lengths.into_iter().enumerate() {
            let chunk_len = length + if index == 0 { prefix_len } else { 0 };
            if chunk_len > 0 && position + chunk_len <= server_hello.len() {
                stream
                    .write_all(&server_hello[position..position + chunk_len])
                    .await?;
                stream.flush().await?;
                position += chunk_len;
            }
            if let Some(gap) = padding_plan.gaps.get(index).filter(|gap| !gap.is_zero()) {
                tokio::time::sleep(*gap).await;
            }
        }
        if position < server_hello.len() {
            stream.write_all(&server_hello[position..]).await?;
            stream.flush().await?;
        }

        // Read client's padding
        let mut client_pad_len_enc = [0u8; 18];
        stream.read_exact(&mut client_pad_len_enc).await?;
        nfs_aead.open(&mut client_pad_len_enc, &[])?;
        let client_pad_len =
            u16::from_be_bytes([client_pad_len_enc[0], client_pad_len_enc[1]]) as usize;

        let mut client_pad_body = vec![0u8; client_pad_len];
        stream.read_exact(&mut client_pad_body).await?;
        nfs_aead.open(&mut client_pad_body, &[])?;

        let masks = if self.config.mode == XorMode::Random {
            Some((
                HeaderMask::new(united_key.as_ref(), &ticket),
                HeaderMask::new(united_key.as_ref(), &iv),
            ))
        } else {
            None
        };

        Ok(EncryptedStream::new(
            stream,
            united_key,
            write_aead,
            Some(read_aead),
            masks,
            0,
        ))
    }
}

fn between(low: u32, high: u32) -> u32 {
    if low >= high {
        return low;
    }
    low + (OsRng.next_u32() % (high - low))
}
