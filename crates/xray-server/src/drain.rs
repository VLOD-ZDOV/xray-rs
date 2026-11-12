//! Xray's anti-probe drain (common/drain): a client that fails a VMess or
//! Shadowsocks handshake is read for a server-constant amount plus a little
//! noise before the close, so a probe cannot time the close against the bytes
//! it sent.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::time::{timeout_at, Instant};

/// Bytes to read in all, from a 16-byte (or longer) server seed.
pub fn size(seed: &[u8]) -> u64 {
    let base = u64::from_be_bytes(seed[..8].try_into().unwrap_or_default()) % 3266;
    let rand_max = u64::from_be_bytes(seed[8..16].try_into().unwrap_or_default()) % 64 + 1;
    16 + 38 + base + rand::thread_rng().gen_range(0..rand_max)
}

/// A seed fixed for the process, for inbounds whose keys are not at hand. Xray
/// derives it from the users' keys, which a probe cannot tell apart.
pub fn process_seed() -> &'static [u8; 16] {
    static SEED: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();
    SEED.get_or_init(rand::random)
}

/// Reads and drops what is left of `total` after `read` bytes, until `deadline`.
pub async fn discard<R: AsyncRead + Unpin>(
    reader: &mut R,
    total: u64,
    read: u64,
    deadline: Instant,
) {
    let (mut rest, mut sink) = (reader.take(total.saturating_sub(read)), tokio::io::sink());
    let _ = timeout_at(deadline, tokio::io::copy(&mut rest, &mut sink)).await;
}

/// Counts the bytes a handshake reads.
pub struct Counted<'a, R> {
    pub inner: &'a mut R,
    pub read: u64,
}

impl<'a, R> Counted<'a, R> {
    pub fn new(inner: &'a mut R) -> Self {
        Self { inner, read: 0 }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Counted<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut *self.inner).poll_read(cx, buf);
        self.read += (buf.filled().len() - before) as u64;
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn size_is_server_constant_plus_noise() {
        let seed = Sha256::digest([0x42u8; 16]);
        let base = u64::from_be_bytes(seed[..8].try_into().unwrap()) % 3266;
        let noise = u64::from_be_bytes(seed[8..16].try_into().unwrap()) % 64 + 1;
        for _ in 0..200 {
            assert!((54 + base..54 + base + noise).contains(&size(&seed)));
        }
    }

    #[tokio::test]
    async fn discards_only_the_rest() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::io::AsyncWriteExt::write_all(&mut client, &[0u8; 100])
            .await
            .unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        discard(&mut server, 70, 20, deadline).await;
        let mut left = Vec::new();
        drop(client);
        server.read_to_end(&mut left).await.unwrap();
        assert_eq!(left.len(), 50);
    }
}
