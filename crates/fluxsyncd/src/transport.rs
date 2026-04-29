//! UDP transport with a 1-byte type prefix.
//!
//! Wire layout per datagram:
//!
//! ```text
//! | 1 byte type | rest |
//! ```
//!
//! * `0x01` — Noise IK message 1 (initiator → responder), raw
//! * `0x02` — Noise IK message 2 (responder → initiator), raw
//! * `0x03` — encrypted CBOR `Frame` (snow's `TransportState`
//!            output: ciphertext + 16-byte Poly1305 tag, snow-managed nonce)
//!
//! The handshake messages are plaintext-but-authenticated by Noise
//! itself; encryption only kicks in once both sides finish msg2 and
//! switch to transport mode.

use anyhow::{anyhow, Result};
use fluxsync_crypto::Session;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub const TYPE_HANDSHAKE_INIT: u8 = 0x01;
pub const TYPE_HANDSHAKE_RESP: u8 = 0x02;
pub const TYPE_ENCRYPTED: u8 = 0x03;

pub struct Transport {
    pub socket: Arc<UdpSocket>,
    pub peer_addr: Arc<Mutex<Option<SocketAddr>>>,
    pub session: Arc<Mutex<Option<Session>>>,
}

#[derive(Debug)]
pub enum RecvFrame {
    HandshakeInit { from: SocketAddr, msg: Vec<u8> },
    HandshakeResp { from: SocketAddr, msg: Vec<u8> },
    Encrypted { from: SocketAddr, plaintext: Vec<u8> },
    Other { from: SocketAddr, type_byte: u8 },
}

impl Transport {
    pub async fn bind(bind: &str, port: u16) -> Result<Self> {
        let addr = format!("{bind}:{port}");
        let socket = UdpSocket::bind(&addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            peer_addr: Arc::new(Mutex::new(None)),
            session: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn set_peer_addr(&self, addr: SocketAddr) {
        *self.peer_addr.lock().await = Some(addr);
    }

    pub async fn install_session(&self, session: Session) {
        *self.session.lock().await = Some(session);
    }

    pub async fn drop_session(&self) {
        *self.session.lock().await = None;
    }

    /// Send a typed datagram to the given address, prefixing the body
    /// with the type byte.
    pub async fn send_typed(&self, type_byte: u8, body: &[u8], to: SocketAddr) -> Result<()> {
        let mut buf = Vec::with_capacity(body.len() + 1);
        buf.push(type_byte);
        buf.extend_from_slice(body);
        self.socket.send_to(&buf, to).await?;
        Ok(())
    }

    /// Send an encrypted CBOR `Frame` to the currently-set peer.
    pub async fn send_encrypted(&self, plaintext: &[u8]) -> Result<()> {
        let addr = self
            .peer_addr
            .lock()
            .await
            .ok_or_else(|| anyhow!("no peer addr set"))?;
        let ct = {
            let mut g = self.session.lock().await;
            let s = g.as_mut().ok_or_else(|| anyhow!("no session"))?;
            s.encrypt(plaintext)?
        };
        self.send_typed(TYPE_ENCRYPTED, &ct, addr).await
    }

    /// Receive one datagram and dispatch by type byte.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<RecvFrame> {
        let (n, from) = self.socket.recv_from(buf).await?;
        if n == 0 {
            return Ok(RecvFrame::Other {
                from,
                type_byte: 0,
            });
        }
        let type_byte = buf[0];
        let body = &buf[1..n];
        match type_byte {
            TYPE_HANDSHAKE_INIT => Ok(RecvFrame::HandshakeInit {
                from,
                msg: body.to_vec(),
            }),
            TYPE_HANDSHAKE_RESP => Ok(RecvFrame::HandshakeResp {
                from,
                msg: body.to_vec(),
            }),
            TYPE_ENCRYPTED => {
                let pt = {
                    let mut g = self.session.lock().await;
                    let s = g
                        .as_mut()
                        .ok_or_else(|| anyhow!("encrypted frame but no session"))?;
                    s.decrypt(body)?
                };
                Ok(RecvFrame::Encrypted {
                    from,
                    plaintext: pt,
                })
            }
            other => Ok(RecvFrame::Other {
                from,
                type_byte: other,
            }),
        }
    }
}
