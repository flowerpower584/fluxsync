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
use std::collections::BTreeMap;
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

/// DIR-P2-03: a session older than this is due for a planned rekey.
pub const REKEY_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;

/// DIR-P2-03: a session that has carried this much encrypted payload
/// (both directions combined) is due for a planned rekey.
pub const REKEY_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// True once either rekey threshold has been crossed. Pure so the trigger
/// logic (age vs. bytes) is unit-testable without a running daemon; the
/// caller supplies `max_age_ms` / `max_bytes` so tests (and, in principle,
/// a future config knob) can override [`REKEY_MAX_AGE_MS`] /
/// [`REKEY_MAX_BYTES`].
#[must_use]
pub fn rekey_due(age_ms: u64, bytes: u64, max_age_ms: u64, max_bytes: u64) -> bool {
    age_ms >= max_age_ms || bytes >= max_bytes
}

/// DIR-P2-03: deterministic tie-break for which side performs a planned
/// rekey — the peer with the numerically smaller `peer_id` (BLAKE3 of its
/// static Noise key) initiates, the other side just accepts the fresh
/// handshake like it already does for any reconnect. Both daemons compute
/// this independently from `Identity::peer_id()` and the linked peer's id,
/// so the two sides agree without any extra wire coordination.
///
/// Keyed on `peer_id` rather than the raw `static_pub` (unlike the
/// discovery/proactive-probe tie-breaks in `driver.rs`) because the
/// transport layer never retains a linked peer's static key after the
/// handshake completes — `peer_id` is the only peer-identifying value
/// available at rekey-check time.
#[must_use]
pub fn is_rekey_initiator(self_peer_id: [u8; 32], peer_id: [u8; 32]) -> bool {
    self_peer_id < peer_id
}

/// Per-peer connection state. FluxMesh Phase 2: today a `Transport`
/// holds exactly one `PeerConn`; step 2B-2 turns this into a
/// `BTreeMap<PeerId, Arc<PeerConn>>`. Each field keeps its own lock so
/// the granularity — and the FS-033 / FS-034 / nonce-generation
/// invariants built on it — is identical to the previous flat layout.
pub struct PeerConn {
    pub peer_addr: Mutex<Option<SocketAddr>>,
    /// Persistent cache of the last known successful peer address.
    /// Unlike `peer_addr`, this is NOT cleared on `drop_session`.
    pub last_peer_addr: Mutex<Option<SocketAddr>>,
    /// Last seen peer ID at `last_peer_addr`. Used for proactive probing.
    pub last_peer_id: Mutex<Option<[u8; 32]>>,
    pub session: Mutex<Option<Session>>,
    /// Monotonic counter incremented on every session lifecycle event.
    /// Prevents nonce reuse across reconnects by letting `send_encrypted`
    /// detect a session swap that happened while it was waiting for the
    /// mutex.
    session_generation: AtomicU64,
    roaming_history: Mutex<Vec<SocketAddr>>,
    last_rx_ms: AtomicU64,
    /// Epoch-ms of the last accepted roam. Rate-limits peer-address
    /// re-pinning so a LAN attacker replaying authentic ciphertext
    /// cannot continuously redirect outbound traffic (FS-034).
    last_roam_ms: AtomicU64,
    session_established_at_ms: AtomicU64,
    /// DIR-P2-03: sum of encrypted-frame bytes (both directions) since the
    /// current session was installed. Reset to 0 on every install; read by
    /// the rekey watchdog alongside `session_established_at_ms` to decide
    /// whether the session is due for a planned re-handshake.
    bytes_since_established: AtomicU64,
}

impl PeerConn {
    fn new() -> Self {
        Self {
            peer_addr: Mutex::new(None),
            last_peer_addr: Mutex::new(None),
            last_peer_id: Mutex::new(None),
            session: Mutex::new(None),
            session_generation: AtomicU64::new(0),
            roaming_history: Mutex::new(Vec::new()),
            last_rx_ms: AtomicU64::new(now_ms()),
            last_roam_ms: AtomicU64::new(0),
            session_established_at_ms: AtomicU64::new(0),
            bytes_since_established: AtomicU64::new(0),
        }
    }
}

pub struct Transport {
    pub socket: Arc<UdpSocket>,
    /// The primary peer connection — always present, and the slot every
    /// legacy single-peer accessor reads/writes. It is also the peer the
    /// single-peer `State` DTO projects (FluxMesh 2C-b keeps clients
    /// single-peer-compatible).
    conn: Arc<PeerConn>,
    /// FluxMesh 2C-b: additional simultaneous peers, keyed by peer id.
    /// Empty in the single-peer steady state; the first time a *second*
    /// distinct peer installs a session it lands here instead of evicting
    /// the primary. `recv` tries `conn` then each entry; the peer-keyed
    /// accessors (`*_for`) resolve an id to `conn` or one of these.
    extra: Mutex<BTreeMap<[u8; 32], Arc<PeerConn>>>,
    pub metrics: Arc<Mutex<crate::metrics::MetricsTracker>>,
    /// Pulsed whenever a session is installed. Lets idle pollers
    /// (the clipboard watcher) sleep instead of busy-ticking while
    /// unpaired (FS-048).
    pub session_notify: Arc<Notify>,
    /// Serializes every `peers.json` read-modify-write window so that a
    /// concurrent reaper revoke and pair-insert (or two pair-inserts)
    /// cannot interleave and clobber each other. Held across the entire
    /// `load → modify → save` sequence inside the keystore helpers.
    /// (Fixes the F-001 race surfaced by the 2026-05-24 differential
    /// review of VULN-001 fixes.)
    pub(crate) peers_disk_lock: Arc<Mutex<()>>,
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
        /// Peer id whose session decrypted this datagram. FluxMesh 2C-b:
        /// lets the inbound path route per source peer (FS-052 gate, Ack
        /// reply, mesh anti-loop) instead of assuming a single peer.
        peer_id: [u8; 32],
        plaintext: Vec<u8>,
    },
    Other {
        from: SocketAddr,
        type_byte: u8,
    },
}

impl RecvFrame {
    /// Source `SocketAddr` of the datagram, regardless of frame kind.
    /// Used by the driver to apply a uniform `lan_only` filter before
    /// any further dispatch.
    #[must_use]
    pub fn from(&self) -> SocketAddr {
        match self {
            Self::HandshakeInit { from, .. }
            | Self::HandshakeResp { from, .. }
            | Self::Encrypted { from, .. }
            | Self::Other { from, .. } => *from,
        }
    }

    /// Short label used in `tracing` events when a frame is dropped
    /// for policy reasons — keeps the log line readable without
    /// dumping the entire payload.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::HandshakeInit { .. } => "HandshakeInit",
            Self::HandshakeResp { .. } => "HandshakeResp",
            Self::Encrypted { .. } => "Encrypted",
            Self::Other { .. } => "Other",
        }
    }
}

impl Transport {
    pub async fn bind(bind: &str, port: u16) -> Result<(Self, u16)> {
        let addr = format!("{bind}:{port}");
        let socket = UdpSocket::bind(&addr).await?;
        let actual_port = socket.local_addr()?.port();
        Ok((
            Self {
                socket: Arc::new(socket),
                conn: Arc::new(PeerConn::new()),
                extra: Mutex::new(BTreeMap::new()),
                metrics: Arc::new(Mutex::new(crate::metrics::MetricsTracker::new())),
                session_notify: Arc::new(Notify::new()),
                peers_disk_lock: Arc::new(Mutex::new(())),
            },
            actual_port,
        ))
    }

    pub async fn set_peer_addr(&self, addr: SocketAddr) {
        *self.conn.peer_addr.lock().await = Some(addr);
        *self.conn.last_peer_addr.lock().await = Some(addr);
        self.push_history(addr).await;
    }

    pub async fn set_peer_info(&self, id: [u8; 32], addr: SocketAddr) {
        *self.conn.peer_addr.lock().await = Some(addr);
        *self.conn.last_peer_addr.lock().await = Some(addr);
        *self.conn.last_peer_id.lock().await = Some(id);
        self.push_history(addr).await;
    }

    /// Resolve the `PeerConn` a session install for `id` should target.
    /// Reuses the primary slot when it is free, already this peer, or has no
    /// live session; otherwise the peer joins the `extra` map so it runs
    /// alongside the primary instead of evicting it (FluxMesh 2C-b).
    async fn acquire_conn(&self, id: [u8; 32]) -> Arc<PeerConn> {
        {
            let cur = *self.conn.last_peer_id.lock().await;
            let live = self.conn.session.lock().await.is_some();
            if cur == Some(id) || cur.is_none() || !live {
                return self.conn.clone();
            }
        }
        self.extra
            .lock()
            .await
            .entry(id)
            .or_insert_with(|| Arc::new(PeerConn::new()))
            .clone()
    }

    /// Resolve an existing `PeerConn` for `id` (primary or `extra`), or
    /// `None` if that peer is unknown.
    async fn conn_for(&self, id: [u8; 32]) -> Option<Arc<PeerConn>> {
        if *self.conn.last_peer_id.lock().await == Some(id) {
            return Some(self.conn.clone());
        }
        self.extra.lock().await.get(&id).cloned()
    }

    pub async fn install_session(&self, id: [u8; 32], session: Session) {
        let target = self.acquire_conn(id).await;
        *target.session.lock().await = Some(session);
        *target.last_peer_id.lock().await = Some(id);
        target.session_generation.fetch_add(1, Ordering::SeqCst);
        target
            .session_established_at_ms
            .store(now_ms(), Ordering::SeqCst);
        target.bytes_since_established.store(0, Ordering::SeqCst);
        self.session_notify.notify_one();
    }

    async fn push_history(&self, addr: SocketAddr) {
        let mut h = self.conn.roaming_history.lock().await;
        if !h.contains(&addr) {
            h.insert(0, addr);
            h.truncate(5);
        }
    }

    /// CAS install: installs the session only if none is present.
    /// Returns true if the session was installed, false if a session already existed.
    pub async fn try_install_session(&self, id: [u8; 32], session: Session) -> bool {
        let target = self.acquire_conn(id).await;
        let mut g = target.session.lock().await;
        if g.is_some() {
            tracing::debug!("try_install_session: session already present, rejecting install");
            return false;
        }
        *g = Some(session);
        drop(g);
        *target.last_peer_id.lock().await = Some(id);
        target.session_generation.fetch_add(1, Ordering::SeqCst);
        target
            .session_established_at_ms
            .store(now_ms(), Ordering::SeqCst);
        target.bytes_since_established.store(0, Ordering::SeqCst);
        self.session_notify.notify_one();
        true
    }

    /// DIR-P2-03: like [`Self::install_session`] but only commits if the
    /// **primary** slot's `session_generation` is still exactly
    /// `expected_generation` at commit time — i.e. nothing else (a
    /// concurrent drop, a primary failover, or a racing duplicate
    /// handshake reply) touched the primary session since the caller
    /// read that generation.
    ///
    /// Scoped to the primary slot only, unlike `try_install_session` /
    /// `install_session` (which route via `acquire_conn` to primary or
    /// `extra`): a planned rekey always targets whichever peer currently
    /// drives the single FSM, so there is no routing ambiguity to resolve.
    /// This is the mechanism that lets a rekey **replace** a still-live
    /// session — `try_install_session`'s CAS only ever succeeds against an
    /// empty slot, which a live session by definition is not.
    pub async fn install_primary_session_if_generation(
        &self,
        id: [u8; 32],
        session: Session,
        expected_generation: u64,
    ) -> bool {
        let mut g = self.conn.session.lock().await;
        if self.conn.session_generation.load(Ordering::SeqCst) != expected_generation {
            return false;
        }
        *g = Some(session);
        // Bump the generation while `g` is still held: this is the atomic
        // commit point. A concurrent caller blocked on `session.lock()`
        // above will see the new generation once it acquires the lock, so
        // its own `expected_generation` check correctly fails instead of
        // both callers clobbering each other's install.
        self.conn.session_generation.fetch_add(1, Ordering::SeqCst);
        drop(g);
        *self.conn.last_peer_id.lock().await = Some(id);
        self.conn
            .session_established_at_ms
            .store(now_ms(), Ordering::SeqCst);
        self.conn.bytes_since_established.store(0, Ordering::SeqCst);
        self.session_notify.notify_one();
        true
    }

    /// Current `session_generation` of the primary slot. Read by the
    /// rekey watchdog / rekey initiator before starting a (slow) Noise
    /// exchange, then passed back to
    /// [`Self::install_primary_session_if_generation`] as the expected
    /// value so a concurrent change aborts the install instead of
    /// clobbering it.
    #[must_use]
    pub fn primary_session_generation(&self) -> u64 {
        self.conn.session_generation.load(Ordering::SeqCst)
    }

    pub async fn drop_session(&self) {
        *self.conn.session.lock().await = None;
        self.conn.session_generation.fetch_add(1, Ordering::SeqCst);
    }

    // ── Per-peer state accessors ──────────────────────────────────
    // FluxMesh Phase 2 scaffolding: every read/write of the per-peer
    // connection state goes through these so the backing storage can
    // later become a per-peer map without re-touching every call site.
    // Single-peer semantics are unchanged — each accessor takes one
    // lock independently, introducing no new lock-ordering.

    pub async fn has_session(&self) -> bool {
        self.conn.session.lock().await.is_some()
    }

    pub async fn current_peer_addr(&self) -> Option<SocketAddr> {
        *self.conn.peer_addr.lock().await
    }

    pub async fn cached_peer_addr(&self) -> Option<SocketAddr> {
        *self.conn.last_peer_addr.lock().await
    }

    pub async fn cached_peer_id(&self) -> Option<[u8; 32]> {
        *self.conn.last_peer_id.lock().await
    }

    pub async fn set_cached_peer_id(&self, id: [u8; 32]) {
        *self.conn.last_peer_id.lock().await = Some(id);
    }

    pub async fn roaming_history_snapshot(&self) -> Vec<SocketAddr> {
        self.conn.roaming_history.lock().await.clone()
    }

    #[must_use]
    pub fn last_rx(&self) -> u64 {
        self.conn.last_rx_ms.load(Ordering::Relaxed)
    }

    pub fn set_last_rx(&self, ms: u64) {
        self.conn.last_rx_ms.store(ms, Ordering::Relaxed);
    }

    #[must_use]
    pub fn session_established_at(&self) -> u64 {
        self.conn.session_established_at_ms.load(Ordering::SeqCst)
    }

    /// M6 residual fix: like [`Self::session_established_at`] but resolves
    /// to whichever `PeerConn` currently holds `peer_id` — the primary slot
    /// or a FluxMesh `extra` secondary — instead of assuming the primary.
    /// `install_session`/`try_install_session` already stamp
    /// `session_established_at_ms` on whatever `PeerConn` they target (via
    /// `acquire_conn`), so a secondary's own established time has been
    /// tracked all along; this just exposes it per-peer. Returns `None` if
    /// `peer_id` has no known `PeerConn` (never installed, or already
    /// removed from `extra`).
    #[must_use]
    pub async fn session_established_at_for(&self, peer_id: [u8; 32]) -> Option<u64> {
        let c = self.conn_for(peer_id).await?;
        Some(c.session_established_at_ms.load(Ordering::SeqCst))
    }

    /// DIR-P2-03: encrypted-frame bytes (both directions) carried by the
    /// primary session since it was installed. Reset to 0 on every
    /// install (fresh pairing, reconnect, or rekey).
    #[must_use]
    pub fn session_bytes(&self) -> u64 {
        self.conn.bytes_since_established.load(Ordering::Relaxed)
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
        Self::send_on(&self.socket, &self.conn, plaintext).await
    }

    /// FluxMesh 2C-b: encrypt+send to a specific peer (primary or `extra`).
    /// Used by the mesh forward path and per-source replies (Ack, Heartbeat
    /// pong, Nak). Carries the same nonce-reuse guard as `send_encrypted`.
    pub async fn send_encrypted_to(&self, peer_id: [u8; 32], plaintext: &[u8]) -> Result<()> {
        let conn = self
            .conn_for(peer_id)
            .await
            .ok_or_else(|| anyhow!("no connection for peer"))?;
        Self::send_on(&self.socket, &conn, plaintext).await
    }

    /// Shared encrypt-and-send over one `PeerConn`. Snapshots
    /// `session_generation` before locking and verifies it after, aborting if
    /// a reconnect swapped the session mid-flight (nonce-reuse guard, A-002).
    async fn send_on(socket: &UdpSocket, conn: &PeerConn, plaintext: &[u8]) -> Result<()> {
        let gen_before = conn.session_generation.load(Ordering::SeqCst);
        let addr = conn
            .peer_addr
            .lock()
            .await
            .ok_or_else(|| anyhow!("no peer addr set"))?;
        let ct = {
            let mut g = conn.session.lock().await;
            let gen_after = conn.session_generation.load(Ordering::SeqCst);
            if gen_after != gen_before {
                return Err(anyhow!(
                    "session generation changed ({gen_before} → {gen_after}); \
                     aborting send to prevent nonce reuse"
                ));
            }
            let s = g.as_mut().ok_or_else(|| anyhow!("no session"))?;
            s.encrypt(plaintext)?
        };
        // DIR-P2-03: count the full wire frame (nonce + ciphertext + tag)
        // toward this session's rekey byte budget.
        conn.bytes_since_established
            .fetch_add(ct.len() as u64, Ordering::Relaxed);
        let mut buf = Vec::with_capacity(ct.len() + 1);
        buf.push(TYPE_ENCRYPTED);
        buf.extend_from_slice(&ct);
        socket.send_to(&buf, addr).await?;
        Ok(())
    }

    /// True if a live session exists for `peer_id`.
    pub async fn has_session_for(&self, peer_id: [u8; 32]) -> bool {
        match self.conn_for(peer_id).await {
            Some(c) => c.session.lock().await.is_some(),
            None => false,
        }
    }

    /// Drop only `peer_id`'s session (other peers stay linked).
    pub async fn drop_session_for(&self, peer_id: [u8; 32]) {
        if let Some(c) = self.conn_for(peer_id).await {
            *c.session.lock().await = None;
            c.session_generation.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Set the current peer address for `peer_id`, if known.
    pub async fn set_peer_addr_for(&self, peer_id: [u8; 32], addr: SocketAddr) {
        if let Some(c) = self.conn_for(peer_id).await {
            *c.peer_addr.lock().await = Some(addr);
            *c.last_peer_addr.lock().await = Some(addr);
        }
    }

    /// Current peer address for `peer_id`, if any.
    pub async fn peer_addr_for(&self, peer_id: [u8; 32]) -> Option<SocketAddr> {
        match self.conn_for(peer_id).await {
            Some(c) => *c.peer_addr.lock().await,
            None => None,
        }
    }

    /// Every peer id that currently has a live session (primary + `extra`).
    pub async fn linked_peer_ids(&self) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        if self.conn.session.lock().await.is_some() {
            if let Some(id) = *self.conn.last_peer_id.lock().await {
                out.push(id);
            }
        }
        for (id, c) in self.extra.lock().await.iter() {
            if c.session.lock().await.is_some() {
                out.push(*id);
            }
        }
        out
    }

    /// FluxMesh robustness: every *secondary* peer (in `extra`) that has a
    /// live session, paired with its last-rx epoch-ms. The heartbeat loop
    /// pings and ghost-times-out each one independently of the primary —
    /// `last_rx`/`set_last_rx` only ever touch the primary `conn`, so a
    /// vanished secondary would otherwise leave a stale `extra` session
    /// forever.
    pub async fn secondary_liveness(&self) -> Vec<([u8; 32], u64)> {
        let mut out = Vec::new();
        for (id, c) in self.extra.lock().await.iter() {
            if c.session.lock().await.is_some() {
                out.push((*id, c.last_rx_ms.load(Ordering::Relaxed)));
            }
        }
        out
    }

    /// FluxMesh robustness slice 2 (primary failover): move any one live
    /// secondary peer into the primary `conn` slot and return its id. Called
    /// when the primary link dies while a secondary session is still up, so
    /// the single-peer State can rebind to the survivor instead of dropping to
    /// "disconnected". The `Session` (with its nonce + replay state) is moved
    /// intact; `recv` already routes by `last_peer_id`, so continuity holds.
    pub async fn promote_secondary(&self) -> Option<[u8; 32]> {
        // Pick + detach the first secondary that still has a live session.
        let (id, sec) = {
            let mut extra = self.extra.lock().await;
            let mut chosen = None;
            for (id, c) in extra.iter() {
                if c.session.lock().await.is_some() {
                    chosen = Some(*id);
                    break;
                }
            }
            let id = chosen?;
            match extra.remove(&id) {
                Some(c) => (id, c),
                None => return None,
            }
        };

        // Move the live session out of the secondary into the primary slot.
        let session = sec.session.lock().await.take()?;
        *self.conn.session.lock().await = Some(session);
        *self.conn.last_peer_id.lock().await = Some(id);
        let addr = *sec.peer_addr.lock().await;
        *self.conn.peer_addr.lock().await = addr;
        if let Some(a) = addr {
            *self.conn.last_peer_addr.lock().await = Some(a);
        }
        self.conn
            .last_rx_ms
            .store(sec.last_rx_ms.load(Ordering::Relaxed), Ordering::Relaxed);
        // Set the session, THEN bump the generation (same order as
        // install_session) so any send that snapshotted the pre-swap session
        // aborts rather than reusing a nonce across the promotion.
        self.conn.session_generation.fetch_add(1, Ordering::SeqCst);
        self.conn
            .session_established_at_ms
            .store(now_ms(), Ordering::SeqCst);
        // DIR-P2-03: mirrors the age reset above — the promoted session is
        // treated as fresh from this slot's point of view, same as age.
        self.conn.bytes_since_established.store(0, Ordering::SeqCst);
        self.session_notify.notify_one();
        Some(id)
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
                // FluxMesh 2C-b: try every peer's session. `Session::decrypt`
                // re-pins its receiving nonce per call and only advances the
                // replay window after a successful auth, so offering a datagram
                // to the wrong peer's session fails cleanly — no nonce desync,
                // no replay-window corruption. Decrypt under the `session` lock,
                // then release it before touching `metrics` (session→metrics
                // lock order would deadlock a future metrics→session path,
                // FS-033).
                let mut candidates: Vec<([u8; 32], Arc<PeerConn>)> = Vec::new();
                if let Some(id) = *self.conn.last_peer_id.lock().await {
                    candidates.push((id, self.conn.clone()));
                }
                for (id, c) in self.extra.lock().await.iter() {
                    candidates.push((*id, c.clone()));
                }

                let mut tried_any = false;
                for (peer_id, c) in candidates {
                    let result = {
                        let mut g = c.session.lock().await;
                        match g.as_mut() {
                            Some(s) => {
                                tried_any = true;
                                s.decrypt(body)
                            }
                            None => continue,
                        }
                    };
                    // not this peer's datagram; try the next session
                    let Ok(pt) = result else { continue };

                    // DIR-P2-03: count the full wire frame toward this
                    // session's rekey byte budget — only for a datagram
                    // that actually decrypted under this peer's session.
                    c.bytes_since_established
                        .fetch_add(body.len() as u64, Ordering::Relaxed);

                    // ROAMING: decryption success proves the packet is authentic,
                    // but a LAN attacker can replay/relay authentic ciphertext to
                    // hijack `peer_addr`. Rate-limit re-pinning so at most one roam
                    // is accepted per ROAM_MIN_INTERVAL_MS, on THIS peer (FS-034).
                    {
                        let mut p = c.peer_addr.lock().await;
                        if Some(from) != *p {
                            let now = now_ms();
                            // F-CT1: CAS on `last_roam_ms` so two concurrent
                            // recv() paths cannot both pass the rate-limit check
                            // by reading the same stale timestamp.
                            let last_roam = c.last_roam_ms.load(Ordering::Acquire);
                            let allowed = roam_allowed(now, last_roam)
                                && c.last_roam_ms
                                    .compare_exchange(
                                        last_roam,
                                        now,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok();
                            if allowed {
                                tracing::warn!(
                                    old = ?*p, new = ?from,
                                    "roaming: updating peer address"
                                );
                                *p = Some(from);
                                *c.last_peer_addr.lock().await = Some(from);
                                {
                                    let mut h = c.roaming_history.lock().await;
                                    if !h.contains(&from) {
                                        h.insert(0, from);
                                        h.truncate(5); // Keep last 5 IPs
                                    }
                                }
                                // last_peer_id is already set at session install.
                            } else {
                                tracing::warn!(
                                    current = ?*p, rejected = ?from,
                                    "roaming: rejecting peer-address change (rate-limited or CAS lost)"
                                );
                            }
                        }
                    }
                    c.last_rx_ms.store(now_ms(), Ordering::Relaxed);
                    return Ok(RecvFrame::Encrypted {
                        from,
                        peer_id,
                        plaintext: pt,
                    });
                }

                if tried_any {
                    self.metrics.lock().await.on_decrypt_failure();
                    Err(anyhow!("encrypted frame failed to decrypt under any session"))
                } else {
                    Err(anyhow!("encrypted frame but no session"))
                }
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
    use super::{
        is_rekey_initiator, rekey_due, roam_allowed, ROAM_MIN_INTERVAL_MS, REKEY_MAX_AGE_MS,
        REKEY_MAX_BYTES,
    };

    #[test]
    fn dir_p2_03_rekey_thresholds_are_24h_and_1gib() {
        assert_eq!(REKEY_MAX_AGE_MS, 24 * 60 * 60 * 1000);
        assert_eq!(REKEY_MAX_BYTES, 1024 * 1024 * 1024);
    }

    #[test]
    fn dir_p2_03_rekey_due_age_trigger() {
        // Age alone crosses the threshold; bytes stay well under.
        assert!(rekey_due(REKEY_MAX_AGE_MS, 0, REKEY_MAX_AGE_MS, REKEY_MAX_BYTES));
        assert!(rekey_due(
            REKEY_MAX_AGE_MS + 1,
            0,
            REKEY_MAX_AGE_MS,
            REKEY_MAX_BYTES
        ));
        assert!(!rekey_due(
            REKEY_MAX_AGE_MS - 1,
            0,
            REKEY_MAX_AGE_MS,
            REKEY_MAX_BYTES
        ));
    }

    #[test]
    fn dir_p2_03_rekey_due_bytes_trigger() {
        // Bytes alone crosses the threshold; age stays well under.
        assert!(rekey_due(0, REKEY_MAX_BYTES, REKEY_MAX_AGE_MS, REKEY_MAX_BYTES));
        assert!(rekey_due(
            0,
            REKEY_MAX_BYTES + 1,
            REKEY_MAX_AGE_MS,
            REKEY_MAX_BYTES
        ));
        assert!(!rekey_due(
            0,
            REKEY_MAX_BYTES - 1,
            REKEY_MAX_AGE_MS,
            REKEY_MAX_BYTES
        ));
    }

    #[test]
    fn dir_p2_03_rekey_due_neither_trigger_stays_false() {
        assert!(!rekey_due(0, 0, REKEY_MAX_AGE_MS, REKEY_MAX_BYTES));
        assert!(!rekey_due(
            REKEY_MAX_AGE_MS / 2,
            REKEY_MAX_BYTES / 2,
            REKEY_MAX_AGE_MS,
            REKEY_MAX_BYTES
        ));
    }

    /// DIR-P2-03: exactly one side of a pair is ever the rekey initiator,
    /// determined purely from the two `peer_id`s — no wire coordination.
    #[test]
    fn dir_p2_03_is_rekey_initiator_exactly_one_side() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(is_rekey_initiator(a, b));
        assert!(!is_rekey_initiator(b, a));
        // Never both, never neither.
        assert_ne!(is_rekey_initiator(a, b), is_rekey_initiator(b, a));
    }

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

    /// FluxMesh robustness slice 1: a second peer lands in `extra` and is the
    /// ONLY peer `secondary_liveness` reports (the primary is monitored via
    /// `last_rx`). Dropping that peer's session clears it from both views,
    /// which is exactly what lets the heartbeat loop ghost-time-out a silent
    /// secondary without disturbing the primary.
    #[tokio::test]
    async fn secondary_liveness_tracks_extra_peers() {
        use super::Transport;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use std::sync::Arc;

        let (transport, _port) = Transport::bind("127.0.0.1", 0).await.unwrap();
        let transport = Arc::new(transport);

        let me = Identity::generate();
        let (sess1, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        let (sess2, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        let (id1, id2) = ([1u8; 32], [2u8; 32]);

        // First install takes the primary slot; the second peer, arriving with
        // the primary still live, is routed to `extra`.
        transport.install_session(id1, sess1).await;
        transport.install_session(id2, sess2).await;

        assert_eq!(transport.linked_peer_ids().await, vec![id1, id2]);
        let secondaries = transport.secondary_liveness().await;
        assert_eq!(secondaries.len(), 1);
        assert_eq!(secondaries[0].0, id2);

        // Ghost-timeout path: drop only the secondary.
        transport.drop_session_for(id2).await;
        assert_eq!(transport.linked_peer_ids().await, vec![id1]);
        assert!(transport.secondary_liveness().await.is_empty());
    }

    /// M6 residual fix: `session_established_at_for` must resolve to the
    /// SAME `PeerConn` `conn_for` would pick — the primary slot for the
    /// first-installed peer, the matching `extra` entry for a second
    /// simultaneous peer, each with its OWN established time — and `None`
    /// for a peer_id that has no `PeerConn` at all. This is what lets the
    /// secondary ghost-timeout (`heartbeat_loop`) and `Msg::Bye` teardown
    /// sites in `driver.rs` compute a secondary's own uptime for
    /// `PeerBackoff::on_session_ended`, instead of assuming the primary's.
    #[tokio::test]
    async fn session_established_at_for_resolves_primary_vs_secondary_vs_unknown() {
        use super::{now_ms, Transport};
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use std::sync::Arc;

        let (transport, _port) = Transport::bind("127.0.0.1", 0).await.unwrap();
        let transport = Arc::new(transport);

        let me = Identity::generate();
        let (sess1, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        let (sess2, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        let (id1, id2) = ([1u8; 32], [2u8; 32]);

        // Never-installed peer: no `PeerConn` exists yet.
        assert_eq!(transport.session_established_at_for(id1).await, None);

        // First install takes the primary slot.
        let before_primary = now_ms();
        transport.install_session(id1, sess1).await;
        let primary_established = transport
            .session_established_at_for(id1)
            .await
            .expect("primary must report an established time");
        assert!(primary_established >= before_primary);
        assert_eq!(primary_established, transport.session_established_at());

        // Second peer, arriving with the primary still live, routes to
        // `extra` and gets its OWN established time, distinct bookkeeping
        // from the primary's.
        let before_secondary = now_ms();
        transport.install_session(id2, sess2).await;
        let secondary_established = transport
            .session_established_at_for(id2)
            .await
            .expect("secondary must report its own established time");
        assert!(secondary_established >= before_secondary);
        // The primary's timestamp is untouched by the secondary's install.
        assert_eq!(
            transport.session_established_at_for(id1).await,
            Some(primary_established)
        );

        // Dropping the secondary's session (the ghost-timeout / Msg::Bye
        // teardown path) must NOT erase its established-time bookkeeping —
        // callers read it BEFORE `drop_session_for`, exactly like the
        // primary paths do, so this must stay available after the drop too.
        transport.drop_session_for(id2).await;
        assert_eq!(
            transport.session_established_at_for(id2).await,
            Some(secondary_established)
        );

        // A peer_id with no `PeerConn` at all (never primary, never extra)
        // resolves to `None`.
        assert_eq!(transport.session_established_at_for([9u8; 32]).await, None);
    }

    /// FluxMesh robustness slice 2: promoting a secondary moves it into the
    /// primary `conn` slot so single-peer accessors (`cached_peer_id`,
    /// `has_session`) follow the survivor. With no secondaries left it returns
    /// `None`.
    #[tokio::test]
    async fn promote_secondary_moves_survivor_into_primary() {
        use super::Transport;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use std::sync::Arc;

        let (transport, _port) = Transport::bind("127.0.0.1", 0).await.unwrap();
        let transport = Arc::new(transport);

        let me = Identity::generate();
        let (sess1, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        let (sess2, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        let (id1, id2) = ([1u8; 32], [2u8; 32]);
        transport.install_session(id1, sess1).await;
        transport.install_session(id2, sess2).await;
        assert_eq!(transport.cached_peer_id().await, Some(id1));

        // Primary lost → promote the secondary.
        assert_eq!(transport.promote_secondary().await, Some(id2));
        assert_eq!(transport.cached_peer_id().await, Some(id2));
        assert!(transport.has_session().await);
        assert_eq!(transport.linked_peer_ids().await, vec![id2]);
        assert!(transport.secondary_liveness().await.is_empty());

        // No secondaries remain.
        assert_eq!(transport.promote_secondary().await, None);
    }

    /// DIR-P2-03: `install_primary_session_if_generation` is the mechanism a
    /// planned rekey uses to replace a still-live session. Proves the two
    /// halves of its contract: (1) it commits and advances
    /// `primary_session_generation` when the expected generation still
    /// matches, and (2) it is a no-op CAS failure — the live session is left
    /// untouched — when a stale/duplicate caller races in with an outdated
    /// expectation.
    #[tokio::test]
    async fn dir_p2_03_install_primary_session_if_generation_is_a_cas() {
        use super::Transport;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use std::sync::Arc;

        let (transport, _port) = Transport::bind("127.0.0.1", 0).await.unwrap();
        let transport = Arc::new(transport);

        let me = Identity::generate();
        let peer_id = [3u8; 32];

        // Fresh pairing: generation starts at 0, install bumps it to 1.
        let (sess_a, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        assert_eq!(transport.primary_session_generation(), 0);
        transport.install_session(peer_id, sess_a).await;
        assert_eq!(transport.primary_session_generation(), 1);

        // A rekey attempt that read generation 1 and finishes cleanly: CAS
        // succeeds, generation advances to 2, byte counter resets.
        let (sess_b, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        assert!(
            transport
                .install_primary_session_if_generation(peer_id, sess_b, 1)
                .await
        );
        assert_eq!(transport.primary_session_generation(), 2);
        assert_eq!(transport.session_bytes(), 0);

        // A second, stale attempt (e.g. a duplicate HandshakeInit reply)
        // that still believes the generation is 1 must lose the race: the
        // live session (now generation 2) is left untouched.
        let (sess_c, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        assert!(
            !transport
                .install_primary_session_if_generation(peer_id, sess_c, 1)
                .await
        );
        assert_eq!(
            transport.primary_session_generation(),
            2,
            "a lost CAS must not advance the generation"
        );
    }

    /// The generation bump must happen while still holding the `session`
    /// mutex, not after `.await`ing on `last_peer_id`. Otherwise two
    /// concurrent callers with the same `expected_generation` (e.g. a
    /// replayed HandshakeInit spawning two responder tasks) can both pass
    /// the generation check before either commits, and both install —
    /// clobbering each other's session. With the fix, the second caller
    /// blocks on the mutex until the first fully commits (including the
    /// bump), then observes the advanced generation and correctly loses
    /// the race. Uses a multi-thread runtime so the two calls can genuinely
    /// run in parallel rather than just interleave cooperatively.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn install_primary_session_if_generation_is_atomic_under_concurrency() {
        use super::Transport;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use std::sync::Arc;

        let (transport, _port) = Transport::bind("127.0.0.1", 0).await.unwrap();
        let transport = Arc::new(transport);

        let me = Identity::generate();
        let peer_id = [7u8; 32];

        let (sess_a, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        transport.install_session(peer_id, sess_a).await;
        let expected_generation = transport.primary_session_generation();

        let (sess_b, _) = pair_for_test(&me, &Identity::generate()).unwrap();
        let (sess_c, _) = pair_for_test(&me, &Identity::generate()).unwrap();

        let t1 = transport.clone();
        let t2 = transport.clone();
        let h1 = tokio::spawn(async move {
            t1.install_primary_session_if_generation(peer_id, sess_b, expected_generation)
                .await
        });
        let h2 = tokio::spawn(async move {
            t2.install_primary_session_if_generation(peer_id, sess_c, expected_generation)
                .await
        });

        let (r1, r2) = tokio::join!(h1, h2);
        let (r1, r2) = (r1.unwrap(), r2.unwrap());

        assert_ne!(
            r1, r2,
            "exactly one of two concurrent installs with the same expected_generation must win"
        );
        assert_eq!(
            transport.primary_session_generation(),
            expected_generation + 1,
            "the generation must advance exactly once, not twice"
        );
    }
}
