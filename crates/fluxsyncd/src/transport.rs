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
//!   output: ciphertext + 16-byte Poly1305 tag, snow-managed nonce)
//!
//! The handshake messages are plaintext-but-authenticated by Noise
//! itself; encryption only kicks in once both sides finish msg2 and
//! switch to transport mode.
//!
//! ## Session generation tracking
//!
//! A monotonically increasing `session_generation` counter prevents the
//! nonce-reuse vulnerability described in the security audit (A-002).
//! Every `install_session` / `try_install_session` / `drop_session`
//! bumps the generation.  `send_encrypted` snapshots the generation
//! before acquiring the session lock and verifies it after — if it
//! changed, the send is aborted (the session was swapped out mid-flight
//! by a concurrent reconnect).

use anyhow::{anyhow, Result};
use fluxsync_crypto::Session;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};

pub const TYPE_HANDSHAKE_INIT: u8 = 0x01;
pub const TYPE_HANDSHAKE_RESP: u8 = 0x02;
pub const TYPE_ENCRYPTED: u8 = 0x03;

/// Minimum interval between accepted peer-address roams.
pub const ROAM_MIN_INTERVAL_MS: u64 = 30_000;

/// True when a roam may be accepted: at least `ROAM_MIN_INTERVAL_MS`
/// has elapsed since the last accepted roam.
#[must_use]
pub fn roam_allowed(now_ms: u64, last_roam_ms: u64) -> bool {
    now_ms.saturating_sub(last_roam_ms) >= ROAM_MIN_INTERVAL_MS
}

pub struct Transport {
    pub socket: Arc<UdpSocket>,
    pub peer_addr: Arc<Mutex<Option<SocketAddr>>>,
    /// Persistent cache of the last known successful peer address.
    /// Unlike `peer_addr`, this is NOT cleared on `drop_session`.
    pub last_peer_addr: Arc<Mutex<Option<SocketAddr>>>,
    /// Last seen peer ID at `last_peer_addr`. Used for proactive probing.
    pub last_peer_id: Arc<Mutex<Option<[u8; 32]>>>,
    pub session: Arc<Mutex<Option<Session>>>,
    /// Monotonic counter incremented on every session lifecycle event.
    /// Prevents nonce reuse across reconnects by letting `send_encrypted`
    /// detect a session swap that happened while it was waiting for the
    /// mutex.
    session_generation: Arc<AtomicU64>,
    pub(crate) roaming_history: Arc<Mutex<Vec<SocketAddr>>>,
    pub last_rx_ms: Arc<AtomicU64>,
    /// Epoch-ms of the last accepted roam. Rate-limits peer-address
    /// re-pinning so a LAN attacker replaying authentic ciphertext
    /// cannot continuously redirect outbound traffic (FS-034).
    last_roam_ms: Arc<AtomicU64>,
    pub session_established_at_ms: Arc<AtomicU64>,
    pub metrics: Arc<Mutex<crate::metrics::MetricsTracker>>,
    /// Pulsed whenever a session is installed. Lets idle pollers
    /// (the clipboard watcher) sleep instead of busy-ticking while
    /// unpaired (FS-048).
    pub session_notify: Arc<Notify>,
}

#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug)]
pub enum RecvFrame {
    HandshakeInit {
        from: SocketAddr,
        msg: Vec<u8>,
    },
    HandshakeResp {
        from: SocketAddr,
        msg: Vec<u8>,
    },
    Encrypted {
        from: SocketAddr,
        plaintext: Vec<u8>,
    },
    Other {
        from: SocketAddr,
        type_byte: u8,
    },
}

impl Transport {
    pub async fn bind(bind: &str, port: u16) -> Result<(Self, u16)> {
        let addr = format!("{bind}:{port}");
        let socket = UdpSocket::bind(&addr).await?;
        let actual_port = socket.local_addr()?.port();
        Ok((
            Self {
                socket: Arc::new(socket),
                peer_addr: Arc::new(Mutex::new(None)),
                last_peer_addr: Arc::new(Mutex::new(None)),
                last_peer_id: Arc::new(Mutex::new(None)),
                session: Arc::new(Mutex::new(None)),
                session_generation: Arc::new(AtomicU64::new(0)),
                roaming_history: Arc::new(Mutex::new(Vec::new())),
                last_rx_ms: Arc::new(AtomicU64::new(now_ms())),
                last_roam_ms: Arc::new(AtomicU64::new(0)),
                session_established_at_ms: Arc::new(AtomicU64::new(0)),
                metrics: Arc::new(Mutex::new(crate::metrics::MetricsTracker::new())),
                session_notify: Arc::new(Notify::new()),
            },
            actual_port,
        ))
    }

    pub async fn set_peer_addr(&self, addr: SocketAddr) {
        *self.peer_addr.lock().await = Some(addr);
        *self.last_peer_addr.lock().await = Some(addr);
        self.push_history(addr).await;
    }

    pub async fn set_peer_info(&self, id: [u8; 32], addr: SocketAddr) {
        *self.peer_addr.lock().await = Some(addr);
        *self.last_peer_addr.lock().await = Some(addr);
        *self.last_peer_id.lock().await = Some(id);
        self.push_history(addr).await;
    }

    pub async fn install_session(&self, id: [u8; 32], session: Session) {
        *self.session.lock().await = Some(session);
        *self.last_peer_id.lock().await = Some(id);
        self.session_generation.fetch_add(1, Ordering::SeqCst);
        self.session_established_at_ms
            .store(now_ms(), Ordering::SeqCst);
        self.session_notify.notify_one();
    }

    async fn push_history(&self, addr: SocketAddr) {
        let mut h = self.roaming_history.lock().await;
        if !h.contains(&addr) {
            h.insert(0, addr);
            h.truncate(5);
        }
    }

    /// CAS install: installs the session only if none is present.
    /// Returns true if the session was installed, false if a session already existed.
    pub async fn try_install_session(&self, id: [u8; 32], session: Session) -> bool {
        let mut g = self.session.lock().await;
        if g.is_some() {
            tracing::debug!("try_install_session: session already present, rejecting install");
            return false;
        }
        *g = Some(session);
        drop(g);
        *self.last_peer_id.lock().await = Some(id);
        self.session_generation.fetch_add(1, Ordering::SeqCst);
        self.session_established_at_ms
            .store(now_ms(), Ordering::SeqCst);
        self.session_notify.notify_one();
        true
    }

    pub async fn drop_session(&self) {
        *self.session.lock().await = None;
        self.session_generation.fetch_add(1, Ordering::SeqCst);
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
    ///
    /// Snapshots `session_generation` before locking and verifies it
    /// after — if a reconnect swapped the session between the snapshot
    /// and the lock acquisition, the send is aborted to prevent nonce
    /// reuse across session epochs.
    pub async fn send_encrypted(&self, plaintext: &[u8]) -> Result<()> {
        let gen_before = self.session_generation.load(Ordering::SeqCst);

        let addr = self
            .peer_addr
            .lock()
            .await
            .ok_or_else(|| anyhow!("no peer addr set"))?;
        let ct = {
            let mut g = self.session.lock().await;
            // Verify generation hasn't changed since we decided to send.
            let gen_after = self.session_generation.load(Ordering::SeqCst);
            if gen_after != gen_before {
                return Err(anyhow!(
                    "session generation changed ({gen_before} → {gen_after}); \
                     aborting send to prevent nonce reuse"
                ));
            }
            let s = g.as_mut().ok_or_else(|| anyhow!("no session"))?;
            s.encrypt(plaintext)?
        };
        self.send_typed(TYPE_ENCRYPTED, &ct, addr).await
    }

    /// Receive one datagram and dispatch by type byte.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<RecvFrame> {
        let (n, from) = self.socket.recv_from(buf).await?;
        if n == 0 {
            return Ok(RecvFrame::Other { from, type_byte: 0 });
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
                // Decrypt under the `session` lock, then release it before
                // touching `metrics` — acquiring `metrics` while holding
                // `session` would pin a session→metrics lock order and
                // deadlock any future metrics→session path (FS-033).
                let result = {
                    let mut g = self.session.lock().await;
                    let s = g
                        .as_mut()
                        .ok_or_else(|| anyhow!("encrypted frame but no session"))?;
                    s.decrypt(body)
                };
                let pt = match result {
                    Ok(pt) => pt,
                    Err(e) => {
                        self.metrics.lock().await.on_decrypt_failure();
                        return Err(e.into());
                    }
                };

                // ROAMING: decryption success proves the packet is authentic,
                // but a LAN attacker can replay/relay authentic ciphertext to
                // hijack `peer_addr`. Rate-limit re-pinning so at most one roam
                // is accepted per ROAM_MIN_INTERVAL_MS (FS-034).
                {
                    let mut p = self.peer_addr.lock().await;
                    if Some(from) != *p {
                        let now = now_ms();
                        let last_roam = self.last_roam_ms.load(Ordering::Relaxed);
                        if roam_allowed(now, last_roam) {
                            tracing::warn!(
                                old = ?*p, new = ?from,
                                "roaming: updating peer address"
                            );
                            *p = Some(from);
                            *self.last_peer_addr.lock().await = Some(from);
                            self.last_roam_ms.store(now, Ordering::Relaxed);
                            {
                                let mut h = self.roaming_history.lock().await;
                                if !h.contains(&from) {
                                    h.insert(0, from);
                                    h.truncate(5); // Keep last 5 IPs
                                }
                            }
                            // last_peer_id is already set when the session was installed.
                        } else {
                            tracing::warn!(
                                current = ?*p, rejected = ?from,
                                "roaming: rejecting peer-address change (rate-limited)"
                            );
                        }
                    }
                }
                self.last_rx_ms.store(now_ms(), Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::{roam_allowed, ROAM_MIN_INTERVAL_MS};

    #[test]
    fn fs034_roam_rate_limit() {
        assert_eq!(ROAM_MIN_INTERVAL_MS, 30_000);
        // No prior roam (last_roam_ms == 0): always allowed.
        assert!(roam_allowed(100_000, 0));
        // 20s since last roam: too soon, rejected.
        assert!(!roam_allowed(100_000, 80_000));
        // 30s exactly: boundary, allowed.
        assert!(roam_allowed(100_000, 70_000));
        // 10s since last roam: rejected.
        assert!(!roam_allowed(100_000, 90_000));
    }

    /// FS-048: an idle clipboard watcher parks on `session_notify`.
    /// Installing a session must pulse it so the watcher resumes
    /// polling instead of sleeping forever.
    #[tokio::test]
    async fn fs048_install_session_pulses_watcher_notify() {
        use super::Transport;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use std::sync::Arc;
        use std::time::Duration;

        let (transport, _port) = Transport::bind("127.0.0.1", 0).await.unwrap();
        let transport = Arc::new(transport);

        let notify = transport.session_notify.clone();
        let waiter = tokio::spawn(async move { notify.notified().await });
        // Let the waiter register before the session is installed.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let (a, b) = (Identity::generate(), Identity::generate());
        let (session, _peer) = pair_for_test(&a, &b).unwrap();
        transport.install_session([7u8; 32], session).await;

        tokio::time::timeout(Duration::from_millis(500), waiter)
            .await
            .expect("install_session must wake an idle clipboard watcher")
            .unwrap();
    }
}
