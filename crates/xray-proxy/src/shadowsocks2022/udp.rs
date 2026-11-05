use super::{
    crypto::{self, Aead},
    *,
};
use crate::aead::XChaChaKey;
use rand::RngCore;
use std::sync::Arc;

/// A native UDP association. Authentication, response binding and address
/// validation precede replay-state changes. Memory stays constant per session.
pub struct UdpSession {
    method: Arc<Method>,
    id: u64,
    next: Option<u64>,
    local: Aead,
    current: Option<Remote>,
    previous: Option<Remote>,
    previous_seen: u64,
}
struct Remote {
    id: u64,
    aead: Aead,
    replay: Window,
}
struct Window {
    highest: u64,
    ring: [u64; 128],
}
impl Window {
    fn new() -> Self {
        Self {
            highest: 0,
            ring: [0; 128],
        }
    }
    fn check(&self, id: u64) -> bool {
        if id > self.highest {
            return true;
        }
        if self.highest - id > 8128 {
            return false;
        }
        self.ring[((id >> 6) & 127) as usize] & (1 << (id & 63)) == 0
    }
    fn add(&mut self, id: u64) {
        if id > self.highest {
            let old = self.highest >> 6;
            for i in 1..=((id >> 6) - old).min(128) {
                self.ring[((old + i) & 127) as usize] = 0;
            }
            self.highest = id;
        }
        self.ring[((id >> 6) & 127) as usize] |= 1 << (id & 63);
    }
}
impl UdpSession {
    pub fn new(method: Arc<Method>) -> io::Result<Self> {
        let mut id = [0; 8];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| invalid("Shadowsocks 2022 random source failed"))?;
        Ok(Self::with_id(method, u64::from_be_bytes(id)))
    }
    fn with_id(method: Arc<Method>, id: u64) -> Self {
        let local = Aead::session(&method, &id.to_be_bytes());
        Self {
            method,
            id,
            next: Some(0),
            local,
            current: None,
            previous: None,
            previous_seen: 0,
        }
    }
    pub fn encode(&mut self, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut nonce = [0; 24];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| invalid("Shadowsocks 2022 random source failed"))?;
        self.encode_at(target, payload, now()?, nonce)
    }
    fn encode_at(
        &mut self,
        target: &Target,
        payload: &[u8],
        timestamp: u64,
        nonce: [u8; 24],
    ) -> io::Result<Vec<u8>> {
        let address = encode_address(target)?;
        let extra = if self.method.cipher == Cipher::ChaCha20Poly1305 {
            24
        } else {
            (self.method.keys.len() - 1) * 16
        };
        if target.network != Network::Udp
            || 16 + extra + 11 + address.len() + payload.len() + TAG_LENGTH > MAX_UDP_WIRE_LENGTH
        {
            return Err(invalid("invalid Shadowsocks 2022 datagram size or network"));
        }
        let packet_id = self
            .next
            .ok_or_else(|| invalid("Shadowsocks 2022 packet counter exhausted"))?;
        self.next = packet_id.checked_add(1);
        let mut separate = [0; 16];
        separate[..8].copy_from_slice(&self.id.to_be_bytes());
        separate[8..].copy_from_slice(&packet_id.to_be_bytes());
        let mut body = Zeroizing::new(vec![0]);
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&address);
        body.extend_from_slice(payload);
        if self.method.cipher == Cipher::ChaCha20Poly1305 {
            let mut plain = Zeroizing::new(separate.to_vec());
            plain.extend_from_slice(&body);
            XChaChaKey::new(self.method.psk())
                .seal(&nonce, &[], &mut plain)
                .map_err(|_| invalid("Shadowsocks 2022 encryption failed"))?;
            let mut wire = nonce.to_vec();
            wire.extend_from_slice(&plain);
            Ok(wire)
        } else {
            self.local
                .seal(separate[4..].try_into().unwrap(), &mut body)?;
            let mut wire = separate.to_vec();
            for keys in self.method.keys.windows(2) {
                let mut identity = crypto::identity_hash(&keys[1]);
                for (byte, hdr) in identity.iter_mut().zip(separate) {
                    *byte ^= hdr;
                }
                crypto::block(&keys[0], &mut identity, false);
                wire.extend_from_slice(&*identity);
            }
            crypto::block(&self.method.keys[0], &mut separate, false);
            wire[..16].copy_from_slice(&separate);
            wire.extend_from_slice(&body);
            Ok(wire)
        }
    }
    pub fn decode(&mut self, wire: &[u8]) -> io::Result<(Target, Vec<u8>)> {
        self.decode_at(wire, now()?)
    }
    fn decode_at(&mut self, wire: &[u8], timestamp: u64) -> io::Result<(Target, Vec<u8>)> {
        if wire.len() < 16 + 19 + 7 + TAG_LENGTH || wire.len() > MAX_UDP_WIRE_LENGTH {
            return Err(invalid("invalid Shadowsocks 2022 packet length"));
        }
        let mut body;
        let mut separate = [0; 16];
        if self.method.cipher == Cipher::ChaCha20Poly1305 {
            body = Zeroizing::new(wire[24..].to_vec());
            XChaChaKey::new(self.method.psk())
                .open(wire[..24].try_into().unwrap(), &[], &mut body)
                .map_err(|_| invalid("Shadowsocks 2022 authentication failed"))?;
            if body.len() < 16 {
                return Err(invalid("truncated Shadowsocks 2022 packet"));
            }
            separate.copy_from_slice(&body[..16]);
            body.drain(..16);
        } else {
            separate.copy_from_slice(&wire[..16]);
            crypto::block(self.method.psk(), &mut separate, true);
            body = Zeroizing::new(wire[16..].to_vec());
        }
        let id = u64::from_be_bytes(separate[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(separate[8..].try_into().unwrap());
        if id == self.id {
            return Err(invalid("Shadowsocks 2022 reflected session"));
        }
        let remote = self
            .current
            .as_ref()
            .filter(|r| r.id == id)
            .or_else(|| self.previous.as_ref().filter(|r| r.id == id));
        if remote.is_some_and(|r| !r.replay.check(packet_id)) {
            return Err(invalid("replayed Shadowsocks 2022 packet"));
        }
        let candidate = if remote.is_none() {
            Some(Aead::session(&self.method, &separate[..8]))
        } else {
            None
        };
        if self.method.cipher != Cipher::ChaCha20Poly1305 {
            let aead = remote.map(|r| &r.aead).or(candidate.as_ref()).unwrap();
            aead.open(separate[4..].try_into().unwrap(), &mut body)?;
        }
        let mut cursor = Cursor(&body);
        if cursor.u8()? != 1 {
            return Err(invalid("invalid Shadowsocks 2022 packet type"));
        }
        check_time(cursor.u64()?, timestamp)?;
        if cursor.u64()? != self.id {
            return Err(invalid("Shadowsocks 2022 client session mismatch"));
        }
        let padding = cursor.u16()? as usize;
        cursor.take(padding)?;
        let target = cursor.target()?;
        if self.current.as_ref().is_some_and(|r| r.id == id) {
            self.current.as_mut().unwrap().replay.add(packet_id);
        } else if self.previous.as_ref().is_some_and(|r| r.id == id) {
            self.previous.as_mut().unwrap().replay.add(packet_id);
            self.previous_seen = timestamp;
        } else {
            if self.previous.is_some() && timestamp.saturating_sub(self.previous_seen) < 60 {
                return Err(invalid("too many Shadowsocks 2022 remote sessions"));
            }
            self.previous = self.current.take();
            self.previous_seen = timestamp;
            let mut replay = Window::new();
            replay.add(packet_id);
            self.current = Some(Remote {
                id,
                aead: candidate.unwrap(),
                replay,
            });
        }
        Ok((target, cursor.0.to_vec()))
    }
}

/// A bounded server UDP session.
pub struct ServerUdpSession {
    method: Arc<Method>,
    client_id: u64,
    server_id: u64,
    next: Option<u64>,
    replay: Window,
}

impl ServerUdpSession {
    pub fn new(method: Arc<Method>, client_id: u64) -> io::Result<Self> {
        let mut id = [0; 8];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| invalid("Shadowsocks 2022 random source failed"))?;
        Ok(Self {
            method,
            client_id,
            server_id: u64::from_be_bytes(id),
            next: Some(0),
            replay: Window::new(),
        })
    }

    pub fn client_id(&self) -> u64 {
        self.client_id
    }

    pub fn decode_request(
        methods: &[Arc<Method>],
        wire: &[u8],
    ) -> io::Result<(usize, Target, Vec<u8>, u64, u64)> {
        Self::decode_request_at(methods, wire, now()?)
    }

    pub fn decode_request_at(
        methods: &[Arc<Method>],
        wire: &[u8],
        timestamp: u64,
    ) -> io::Result<(usize, Target, Vec<u8>, u64, u64)> {
        if methods.is_empty() {
            return Err(invalid("no Shadowsocks 2022 methods"));
        }
        let first = &methods[0];
        let cipher = first.cipher;

        let mut body;
        let mut separate = [0; 16];
        let (user_idx, _matched_method) = if cipher == Cipher::ChaCha20Poly1305 {
            if wire.len() < 24 + 16 + 11 + TAG_LENGTH {
                return Err(invalid("truncated Shadowsocks 2022 packet"));
            }
            body = Zeroizing::new(wire[24..].to_vec());
            XChaChaKey::new(first.psk())
                .open(wire[..24].try_into().unwrap(), &[], &mut body)
                .map_err(|_| invalid("Shadowsocks 2022 authentication failed"))?;
            if body.len() < 16 {
                return Err(invalid("truncated Shadowsocks 2022 packet"));
            }
            separate.copy_from_slice(&body[..16]);
            body.drain(..16);
            (0, first.clone())
        } else if first.is_multi_user() {
            let id_count = first.keys.len() - 1;
            let header_len = 16 + id_count * 16;
            if wire.len() < header_len + 11 + TAG_LENGTH {
                return Err(invalid("truncated Shadowsocks 2022 packet"));
            }
            separate.copy_from_slice(&wire[..16]);
            crypto::block(first.server_key(), &mut separate, true);

            let mut identity = [0u8; 16];
            identity.copy_from_slice(&wire[16..32]);
            crypto::block(first.server_key(), &mut identity, true);
            for (b, s) in identity.iter_mut().zip(&separate) {
                *b ^= s;
            }

            let (idx, matched) = if methods.len() > 1 {
                let mut found = None;
                for (idx, m) in methods.iter().enumerate() {
                    let user_key = if m.keys.len() > 1 {
                        &m.keys[1]
                    } else {
                        m.psk()
                    };
                    if *crypto::identity_hash(user_key) == identity {
                        found = Some((idx, m.clone()));
                        break;
                    }
                }
                found.ok_or_else(|| invalid("Shadowsocks 2022 user identity mismatch"))?
            } else {
                if *crypto::identity_hash(&first.keys[1]) != identity {
                    return Err(invalid("Shadowsocks 2022 user identity mismatch"));
                }
                (0, first.clone())
            };

            let mut offset = 32;
            for w in matched.keys[1..].windows(2) {
                let mut enc = [0u8; 16];
                enc.copy_from_slice(&wire[offset..offset + 16]);
                crypto::block(&w[0], &mut enc, true);
                for (b, s) in enc.iter_mut().zip(&separate) {
                    *b ^= s;
                }
                if *crypto::identity_hash(&w[1]) != enc {
                    return Err(invalid("Shadowsocks 2022 chained identity mismatch"));
                }
                offset += 16;
            }

            body = Zeroizing::new(wire[offset..].to_vec());
            let aead = Aead::session(&matched, &separate[..8]);
            aead.open(separate[4..].try_into().unwrap(), &mut body)?;
            (idx, matched)
        } else {
            if wire.len() < 16 + 11 + TAG_LENGTH {
                return Err(invalid("truncated Shadowsocks 2022 packet"));
            }
            separate.copy_from_slice(&wire[..16]);
            crypto::block(first.psk(), &mut separate, true);
            body = Zeroizing::new(wire[16..].to_vec());
            let aead = Aead::session(first, &separate[..8]);
            aead.open(separate[4..].try_into().unwrap(), &mut body)?;
            (0, first.clone())
        };

        let client_id = u64::from_be_bytes(separate[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(separate[8..].try_into().unwrap());

        let mut cursor = Cursor(&body);
        if cursor.u8()? != 0 {
            return Err(invalid("invalid Shadowsocks 2022 packet type"));
        }
        check_time(cursor.u64()?, timestamp)?;
        let padding = cursor.u16()? as usize;
        cursor.take(padding)?;
        let mut target = cursor.target()?;
        target.network = Network::Udp;
        let payload = cursor.0.to_vec();

        Ok((user_idx, target, payload, client_id, packet_id))
    }

    pub fn check_replay(&mut self, packet_id: u64) -> bool {
        if !self.replay.check(packet_id) {
            return false;
        }
        self.replay.add(packet_id);
        true
    }

    pub fn encode_response(&mut self, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.encode_response_at(target, payload, now()?)
    }

    pub fn encode_response_at(
        &mut self,
        target: &Target,
        payload: &[u8],
        timestamp: u64,
    ) -> io::Result<Vec<u8>> {
        let address = encode_address(target)?;
        if target.network != Network::Udp
            || 16 + 19 + address.len() + payload.len() + TAG_LENGTH > MAX_UDP_WIRE_LENGTH
        {
            return Err(invalid("invalid Shadowsocks 2022 response size or network"));
        }
        let packet_id = self
            .next
            .ok_or_else(|| invalid("Shadowsocks 2022 packet counter exhausted"))?;
        self.next = packet_id.checked_add(1);

        let mut separate = [0; 16];
        separate[..8].copy_from_slice(&self.server_id.to_be_bytes());
        separate[8..].copy_from_slice(&packet_id.to_be_bytes());

        let mut body = Zeroizing::new(vec![1]); // response type 1
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.extend_from_slice(&self.client_id.to_be_bytes());
        body.extend_from_slice(&[0, 0]); // 0 padding
        body.extend_from_slice(&address);
        body.extend_from_slice(payload);

        if self.method.cipher == Cipher::ChaCha20Poly1305 {
            let mut nonce = [0; 24];
            rand::rngs::OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| invalid("Shadowsocks 2022 random source failed"))?;
            let mut plain = Zeroizing::new(separate.to_vec());
            plain.extend_from_slice(&body);
            XChaChaKey::new(self.method.psk())
                .seal(&nonce, &[], &mut plain)
                .map_err(|_| invalid("Shadowsocks 2022 encryption failed"))?;
            let mut wire = nonce.to_vec();
            wire.extend_from_slice(&plain);
            Ok(wire)
        } else {
            let aead = Aead::session(&self.method, &self.server_id.to_be_bytes());
            aead.seal(separate[4..].try_into().unwrap(), &mut body)?;
            crypto::block(self.method.psk(), &mut separate, false);
            let mut wire = separate.to_vec();
            wire.extend_from_slice(&body);
            Ok(wire)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixtures, unhex};
    use super::*;
    #[test]
    fn ss2022_udp_matches_pinned_go_all_ciphers_and_identity_chains() {
        for case in fixtures() {
            let method = Arc::new(
                Method::new(
                    case["method"].as_str().unwrap(),
                    case["password"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let mut session = UdpSession::with_id(method, case["udpSessionId"].as_u64().unwrap());
            let nonce = unhex(case["udpNonce"].as_str().unwrap());
            let mut fixed = [0; 24];
            if !nonce.is_empty() {
                fixed.copy_from_slice(&nonce);
            }
            let target = Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Udp);
            let wire = session
                .encode_at(
                    &target,
                    &unhex(case["udpPayload"].as_str().unwrap()),
                    1700000000,
                    fixed,
                )
                .unwrap();
            assert_eq!(
                wire,
                unhex(case["udpWire"].as_str().unwrap()),
                "{}",
                case["method"]
            );
        }
    }
    #[test]
    fn ss2022_udp_decodes_pinned_go_server_responses() {
        for case in fixtures() {
            let method = Arc::new(
                Method::new(
                    case["method"].as_str().unwrap(),
                    case["password"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let mut session = UdpSession::with_id(method, case["udpSessionId"].as_u64().unwrap());
            let (target, payload) = session
                .decode_at(
                    &unhex(case["udpResponseWire"].as_str().unwrap()),
                    1700000000,
                )
                .unwrap();
            assert_eq!(
                target,
                Target::new(
                    TargetAddr::Ip("2001:db8::8".parse().unwrap()),
                    53,
                    Network::Udp
                ),
                "{}",
                case["method"]
            );
            assert_eq!(
                payload,
                unhex(case["udpResponsePayload"].as_str().unwrap()),
                "{}",
                case["method"]
            );
        }
    }
    fn response(
        session: &UdpSession,
        remote: u64,
        packet: u64,
        client: u64,
        timestamp: u64,
        padding: u16,
    ) -> Vec<u8> {
        let mut separate = remote.to_be_bytes().to_vec();
        separate.extend(packet.to_be_bytes());
        let mut body = vec![1];
        body.extend(timestamp.to_be_bytes());
        body.extend(client.to_be_bytes());
        body.extend(padding.to_be_bytes());
        body.extend(
            encode_address(&Target::new(
                TargetAddr::Ip("2001:db8::8".parse().unwrap()),
                53,
                Network::Udp,
            ))
            .unwrap(),
        );
        body.extend(b"reply");
        if session.method.cipher == Cipher::ChaCha20Poly1305 {
            separate.extend(body);
            let nonce = [7; 24];
            use chacha20poly1305::{
                aead::{AeadInOut, KeyInit},
                XChaCha20Poly1305,
            };
            // The portable AEAD stays as an independent reference here.
            XChaCha20Poly1305::new_from_slice(session.method.psk())
                .unwrap()
                .encrypt_in_place((&nonce).into(), &[], &mut separate)
                .unwrap();
            let mut wire = nonce.to_vec();
            wire.extend(separate);
            wire
        } else {
            Aead::session(&session.method, &remote.to_be_bytes())
                .seal(separate[4..].try_into().unwrap(), &mut body)
                .unwrap();
            let mut block: [u8; 16] = separate.try_into().unwrap();
            crypto::block(session.method.psk(), &mut block, false);
            let mut wire = block.to_vec();
            wire.extend(body);
            wire
        }
    }
    #[test]
    fn ss2022_udp_checks_authentication_binding_time_padding_before_replay_commit() {
        for case in fixtures() {
            let method = Arc::new(
                Method::new(
                    case["method"].as_str().unwrap(),
                    case["password"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let mut session = UdpSession::with_id(method, 10);
            let time = 1700000000;
            for bad in [
                response(&session, 20, 0, 11, time, 0),
                response(&session, 20, 0, 10, time - 31, 0),
                response(&session, 20, 0, 10, time, 65535),
                response(&session, 10, 0, 10, time, 0),
            ] {
                assert!(session.decode_at(&bad, time).is_err());
            }
            let good = response(&session, 20, 0, 10, time, 0);
            for i in 0..good.len() {
                let mut bad = good.clone();
                bad[i] ^= 1;
                assert!(session.decode_at(&bad, time).is_err());
            }
            assert_eq!(session.decode_at(&good, time).unwrap().1, b"reply");
            assert!(session.decode_at(&good, time).is_err());
            let next = response(&session, 21, 1, 10, time, 0);
            session.decode_at(&next, time).unwrap();
            let overflow = response(&session, 22, 1, 10, time, 0);
            assert!(session.decode_at(&overflow, time).is_err());
            let rotated = response(&session, 22, 1, 10, time + 61, 0);
            session.decode_at(&rotated, time + 61).unwrap();
        }
    }
    #[test]
    fn ss2022_replay_window_and_sender_limits() {
        let mut window = Window::new();
        assert!(window.check(0));
        window.add(0);
        assert!(!window.check(0));
        window.add(10000);
        assert!(!window.check(0));
        assert!(window.check(9999));
        window.add(9999);
        assert!(!window.check(9999));
        window.add(u64::MAX);
        assert!(window.check(u64::MAX - 1));
        assert!(!window.check(10000));
        let method =
            Arc::new(Method::new("2022-blake3-aes-128-gcm", &STANDARD.encode([1; 16])).unwrap());
        let mut session = UdpSession::with_id(method, 10);
        let target = Target::new(
            TargetAddr::Ip("192.0.2.8".parse().unwrap()),
            53,
            Network::Udp,
        );
        assert!(session
            .encode(&target, &vec![0; MAX_UDP_WIRE_LENGTH])
            .is_err());
        assert_eq!(session.next, Some(0));
        session.next = Some(u64::MAX);
        session.encode(&target, b"last").unwrap();
        assert!(session.encode(&target, b"exhausted").is_err());
    }
    #[test]
    fn ss2022_server_udp_and_client_udp_interop() {
        for case in fixtures() {
            let method = Arc::new(
                Method::new(
                    case["method"].as_str().unwrap(),
                    case["password"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let mut client = UdpSession::new(method.clone()).unwrap();
            let target = Target::new(
                TargetAddr::Ip("192.0.2.8".parse().unwrap()),
                53,
                Network::Udp,
            );
            let wire = client.encode(&target, b"dns query").unwrap();

            let (_idx, req_target, req_payload, client_id, packet_id) =
                ServerUdpSession::decode_request(std::slice::from_ref(&method), &wire).unwrap();
            assert_eq!(req_target, target);
            assert_eq!(&req_payload, b"dns query");

            let mut server = ServerUdpSession::new(method.clone(), client_id).unwrap();
            assert!(server.check_replay(packet_id));

            let resp_target = Target::new(
                TargetAddr::Ip("192.0.2.8".parse().unwrap()),
                53,
                Network::Udp,
            );
            let resp_wire = server
                .encode_response(&resp_target, b"dns reply")
                .unwrap();

            let (decoded_target, decoded_payload) = client.decode(&resp_wire).unwrap();
            assert_eq!(decoded_target, resp_target);
            assert_eq!(&decoded_payload, b"dns reply");
        }
    }
}
