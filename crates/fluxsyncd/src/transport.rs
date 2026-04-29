//! UDP transport. One socket bound to `udp_bind:udp_port`. Each
//! datagram = one ChaCha20-Poly1305 ciphertext (the Noise transport
//! state's output).
//!
//! v0.1 uses a single statically-known peer (passed via `TestPair` for
//! tests, or learned at pair-time in production). MTU-fragmentation
//! (`Chunk` frames) is not yet implemented — items > ~1.4 KiB will
//! fail to send and emit a `WARN`.

use anyhow::Result;
use fluxsync_crypto::Session;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub struct Transport {
    pub socket: Arc<UdpSocket>,
    pub session: Arc<Mutex<Session>>,
    pub peer_addr: SocketAddr,
}

impl Transport {
    pub async fn bind(
        bind: &str,
        port: u16,
        session: Session,
        peer_addr: SocketAddr,
    ) -> Result<Self> {
        let addr = format!("{bind}:{port}");
        let socket = UdpSocket::bind(&addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            session: Arc::new(Mutex::new(session)),
            peer_addr,
        })
    }

    /// Encrypt + send one frame (CBOR bytes) to the peer.
    pub async fn send(&self, plaintext: &[u8]) -> Result<()> {
        let ct = {
            let mut s = self.session.lock().await;
            s.encrypt(plaintext)?
        };
        self.socket.send_to(&ct, self.peer_addr).await?;
        Ok(())
    }

    /// Receive one ciphertext datagram and decrypt it. Returns the
    /// plaintext (CBOR `Frame` bytes).
    pub async fn recv(&self, buf: &mut [u8]) -> Result<Vec<u8>> {
        let (n, _from) = self.socket.recv_from(buf).await?;
        let pt = {
            let mut s = self.session.lock().await;
            s.decrypt(&buf[..n])?
        };
        Ok(pt)
    }
}
