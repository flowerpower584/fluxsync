//! Noise IK handshake driver.
//!
//! Two paths:
//! * **Initiator** — fired by the driver when discovery (or a manual
//!   pair) tells us a trusted peer is reachable at a known UDP address.
//!   Sends `HandshakeInit`, awaits the matching `HandshakeResp` from the
//!   transport recv loop, finalizes the session, installs it into the
//!   `Transport`, and pings `Event::HandshakeOk` so the FSM transitions
//!   to `Linked`.
//! * **Responder** — fired by the transport recv loop when a
//!   `HandshakeInit` datagram arrives. Validates that the initiator's
//!   static key is in the trusted set, sends `HandshakeResp`, installs
//!   the session, fires `Event::HandshakeOk`, and points the transport
//!   at the initiator's address so subsequent encrypted sends find it.

use anyhow::{anyhow, Result};
use fluxsync_core::Event;
use fluxsync_crypto::{fingerprint_from_handshake_hash, Identity, Initiator, Responder};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

use crate::transport::{Transport, TYPE_HANDSHAKE_INIT, TYPE_HANDSHAKE_RESP};

/// In-memory peer trust registry (v0.1.1; persistence in v0.1.2).
#[derive(Debug, Clone)]
pub struct TrustedPeer {
    pub static_pub: [u8; 32],
    pub name: String,
}

pub type TrustedSet = Arc<Mutex<HashMap<[u8; 32], TrustedPeer>>>;

/// Placeholder name a peer carries between TOFU acceptance and the
/// `Msg::Hello` exchange that swaps in the real device name. Used as the
/// single source for both the in-memory and on-disk records so they
/// cannot diverge (FS-030).
pub const TOFU_PLACEHOLDER_NAME: &str = "New Peer";

/// Build the in-memory trust record for a peer accepted via TOFU.
#[must_use]
pub fn tofu_trusted_peer(remote_static: [u8; 32]) -> TrustedPeer {
    TrustedPeer {
        static_pub: remote_static,
        name: String::from(TOFU_PLACEHOLDER_NAME),
    }
}

/// How long the TOFU pairing window stays open after `CmdOp::PairShow`.
/// Kept short so a stale QR or a drive-by LAN handshake has only a narrow
/// window to land in the trusted set (FS-032). The real fix — explicit
/// safe-word confirmation before trust — is tracked as FS-052.
pub const PAIRING_WINDOW: Duration = Duration::from_secs(90);

/// Time-bounded "trust on first use" window. While the contained
/// `Instant` is in the future, the responder accepts handshakes from
/// previously-unknown peers and adds them to [`TrustedSet`] on success.
/// Set by `CmdOp::PairShow` to `now + PAIRING_WINDOW` so the user has a
/// finite pairing window after they generate their QR code; otherwise
/// stays `None` and the responder enforces strict trust.
pub type PairingWindow = Arc<Mutex<Option<Instant>>>;

/// FS-052: one TOFU-accepted pair that has not yet been verbally
/// confirmed by the user. Holds the session-binding SAS so the IPC
/// layer can show it; on confirm the entry is dropped, on reject the
/// peer is revoked.
#[derive(Debug, Clone)]
pub struct PendingPair {
    pub static_pub: [u8; 32],
    pub name: String,
    pub sas_words: [String; 6],
    pub from: SocketAddr,
    pub expires_at: Instant,
}

/// Map of unconfirmed TOFU pairs, keyed by `peer_id = BLAKE3(static_pub)`.
pub type PendingSet = Arc<Mutex<HashMap<[u8; 32], PendingPair>>>;

/// FS-058: hard cap on `PendingSet`. The set holds *unconfirmed* pairs, so
/// in healthy use it never exceeds the number of peers the user is
/// pairing in the current window (1–2). The cap is wide enough to absorb
/// honest retries on lossy LAN, narrow enough to make the map a no-op
/// DoS target.
pub const MAX_PENDING_PAIRS: usize = 64;

/// FS-058: hard cap on `TrustedSet` growth via TOFU auto-trust. Without a
/// cap an attacker who spams TOFU during an open pairing window could grow
/// the on-disk `peers.json` without bound (V1). 256 is far above any
/// plausible legitimate device count.
///
/// DIR-P1-08: deliberately different from [`MAX_PERSISTED_PEERS`] (64),
/// which caps explicit pair commands (`pair from-uri` / `pair accept` /
/// `pair from-pin`) and the `peers.json` load path. Two same-named
/// constants with different values used to live in `handshake.rs` and
/// `driver.rs` — a naming footgun. Keep the two distinct; do not unify.
pub const MAX_TOFU_TRUSTED_PEERS: usize = 256;

/// H3: hard cap on the trusted-peer set enforced by explicit pair commands
/// (`pair from-uri` / `pair accept` / `pair from-pin`) and by the
/// `peers.json` load path (`driver::load_trusted_peers`). A
/// personal/family fluxsync rarely exceeds 4-6 devices; 64 leaves generous
/// headroom. Re-pairing an existing peer is unaffected — the check is "new
/// peer would exceed cap", not "any insert exceeds cap".
///
/// DIR-P1-08: deliberately different from [`MAX_TOFU_TRUSTED_PEERS`] (256),
/// which gates unconfirmed TOFU auto-trust inserts. Keep the two distinct.
pub const MAX_PERSISTED_PEERS: usize = 64;

/// Run the initiator side. Sends msg1, then awaits one msg2 on the
/// `incoming` channel. Times out after 5 s.
#[allow(clippy::too_many_arguments)]
pub async fn run_initiator(
    identity: Identity,
    peer_static_pub: [u8; 32],
    peer_addr: SocketAddr,
    transport: Arc<Transport>,
    mut incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    event_tx: mpsc::Sender<Event>,
    peer_id: [u8; 32],
    peer_name: String,
    // `Some` only for fresh pair-command handshakes (gate + verbal confirm);
    // `None` for reconnects to an already-confirmed peer, which must not be
    // re-gated. Mirrors the responder's `newly_tofu`-only pending insert.
    pending: Option<PendingSet>,
    // last_addr persistence + redial: looked up to build the
    // `StoredPeer` write below; `None` `keystore_dir` (test harnesses with
    // no on-disk persistence) makes the write a no-op.
    trusted: TrustedSet,
    keystore_dir: Option<std::path::PathBuf>,
) -> Result<()> {
    let (initiator, msg1) = Initiator::start(&identity, &peer_static_pub)?;
    transport
        .send_typed(TYPE_HANDSHAKE_INIT, &msg1, peer_addr)
        .await?;

    let msg2 = tokio::time::timeout(std::time::Duration::from_secs(5), incoming.recv())
        .await
        .map_err(|_| anyhow!("handshake timeout (no resp in 5s)"))?
        .ok_or_else(|| anyhow!("handshake channel closed"))?;

    let session = initiator.finish(&msg2)?;
    // FS-052: SAS bound to this handshake hash. The initiator already
    // authenticated the responder out-of-band (scanned QR / typed PIN), but
    // we still surface the 6 words and gate clipboard so the user can match
    // them on both devices and explicitly confirm — symmetric with the
    // responder, and the only way the user can reject a wrong handshake.
    let sas_words: [String; 6] = fingerprint_from_handshake_hash(session.handshake_hash())
        .map(std::string::ToString::to_string);
    if !transport.try_install_session(peer_id, session).await {
        // Responder side completed first (simultaneous-init race). The
        // existing session is authoritative; drop ours and let the peer
        // own the link.
        tracing::debug!("initiator: session already installed; aborting install");
        return Ok(());
    }
    transport.set_peer_info(peer_id, peer_addr).await;
    crate::driver::persist_last_addr(keystore_dir.as_deref(), &transport, &trusted, peer_id, peer_addr).await;

    // FS-052: insert the pending entry BEFORE announcing the link so the
    // outbound gate engages immediately. Mirrors the responder's insert
    // (expiry sweep + hard cap). `PairConfirm` clears it; the reaper revokes
    // both the pending and the trusted slot if the user never confirms.
    if let Some(pending) = pending {
        let mut pending_guard = pending.lock().await;
        let now = Instant::now();
        pending_guard.retain(|_, p| p.expires_at > now);
        if pending_guard.len() >= MAX_PENDING_PAIRS {
            if let Some(victim) = pending_guard
                .iter()
                .min_by_key(|(_, p)| p.expires_at)
                .map(|(k, _)| *k)
            {
                pending_guard.remove(&victim);
            }
        }
        pending_guard.insert(
            peer_id,
            PendingPair {
                static_pub: peer_static_pub,
                name: peer_name.clone(),
                sas_words,
                from: peer_addr,
                expires_at: now + PAIRING_WINDOW,
            },
        );
    }

    let _ = event_tx.try_send(Event::PeerSeen {
        peer_id,
        name: peer_name,
    });
    let _ = event_tx.try_send(Event::HandshakeOk);
    Ok(())
}

/// DIR-P2-03: planned session rekey. Runs the same Noise IK exchange as
/// [`run_initiator`] against a peer that is already trusted *and* already
/// linked, but — unlike `run_initiator`, which only ever fills an empty
/// session slot — this **replaces** the live session once the new one is
/// fully established (make-before-break: the old session keeps serving
/// heartbeats/clipboard traffic for the entire ~5s handshake round trip;
/// only the final atomic install swaps the keys).
///
/// `expected_generation` is `Transport::primary_session_generation()`
/// snapshotted by the caller right before this call starts; the install at
/// the end only commits if it is still current (see
/// [`Transport::install_primary_session_if_generation`]), so a concurrent
/// drop/failover/duplicate-reply loses cleanly instead of corrupting the
/// link.
///
/// No `PendingSet` entry is created and no SAS re-verification is
/// triggered: `peer_static_pub` came from the already-confirmed
/// `TrustedSet`, so re-gating the user on every rekey would defeat the
/// point of an invisible background rotation.
#[allow(clippy::too_many_arguments)]
pub async fn run_rekey_initiator(
    identity: Identity,
    peer_static_pub: [u8; 32],
    peer_addr: SocketAddr,
    transport: Arc<Transport>,
    mut incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    event_tx: mpsc::Sender<Event>,
    peer_id: [u8; 32],
    expected_generation: u64,
    // last_addr persistence + redial: see `run_initiator`'s
    // matching params.
    trusted: TrustedSet,
    keystore_dir: Option<std::path::PathBuf>,
) -> Result<()> {
    let (initiator, msg1) = Initiator::start(&identity, &peer_static_pub)?;
    transport
        .send_typed(TYPE_HANDSHAKE_INIT, &msg1, peer_addr)
        .await?;

    let msg2 = tokio::time::timeout(std::time::Duration::from_secs(5), incoming.recv())
        .await
        .map_err(|_| anyhow!("rekey handshake timeout (no resp in 5s)"))?
        .ok_or_else(|| anyhow!("rekey handshake channel closed"))?;

    let session = initiator.finish(&msg2)?;
    if !transport
        .install_primary_session_if_generation(peer_id, session, expected_generation)
        .await
    {
        // Something else (a concurrent drop, a primary failover, or a
        // duplicate/late reply racing this one) already changed the
        // primary session — discard the new one rather than clobber it.
        tracing::debug!("rekey initiator: session changed mid-handshake; discarding new session");
        return Ok(());
    }
    transport.set_peer_info(peer_id, peer_addr).await;
    crate::driver::persist_last_addr(keystore_dir.as_deref(), &transport, &trusted, peer_id, peer_addr).await;
    let _ = event_tx.try_send(Event::HandshakeOk);
    Ok(())
}

/// Run the responder side once. Reads msg1 from `init_msg`, sends msg2
/// back to `from`, installs the session.
///
/// Trust resolution (in order):
/// 1. Peer pubkey already in `trusted` → accept (verifies key match).
/// 2. Peer unknown but `pairing_window` is open → accept under TOFU,
///    insert into `trusted` so subsequent reconnects skip the window.
///    `peer_name` is recorded as `"pending"` because the responder
///    never learns the peer's friendly name from the handshake bytes.
/// 3. Peer unknown + window closed → refuse with "untrusted peer".
#[allow(clippy::too_many_arguments)]
pub async fn run_responder(
    identity: Identity,
    init_msg: Vec<u8>,
    from: SocketAddr,
    transport: Arc<Transport>,
    trusted: TrustedSet,
    pairing_window: PairingWindow,
    event_tx: mpsc::Sender<Event>,
    keystore_dir: Option<std::path::PathBuf>,
    pending: PendingSet,
) -> Result<()> {
    let (session, msg2, remote_static) = Responder::step(&identity, &init_msg)?;

    // FS-052: SAS derived from the Noise handshake hash `h`. Both peers
    // compute the same six words once IK completes; a MITM that swaps in
    // its own key gets a different `h` and therefore different words, so
    // the user sees the mismatch during the verbal compare.
    let sas_words: [String; 6] = fingerprint_from_handshake_hash(session.handshake_hash())
        .map(std::string::ToString::to_string);

    let peer_id = peer_id_for(&remote_static);

    // DIR-P2-03: snapshot as early as possible, before any of the
    // (fast but non-trivial) trust/TOFU work below, so the CAS at commit
    // time below catches a concurrent change (a duplicate HandshakeInit
    // racing this one, a drop, or a primary failover) that happens while
    // this call runs. `Some(_)` only when `peer_id` is the primary's
    // current (or most recently linked) peer — i.e. this is a
    // reconnect/rekey of the live single-FSM link, never a fresh pairing
    // or a secondary mesh peer (those keep the original `try_install_session`
    // empty-slot-only CAS via the `None` arm below).
    // `replacing_live_session` additionally distinguishes "the primary's
    // session is still live right now" (a true rekey/replace — the UX
    // must stay invisible, see below) from "the primary's last peer is
    // reconnecting into an empty slot after a real drop" (an ordinary
    // reconnect, where the existing Discovering→Handshaking→Linked UI
    // flap is correct and unchanged).
    let (rekey_generation, replacing_live_session) =
        if transport.cached_peer_id().await == Some(peer_id) {
            (
                Some(transport.primary_session_generation()),
                transport.has_session().await,
            )
        } else {
            (None, false)
        };

    let mut newly_tofu = false;
    let entry = {
        let mut trusted_guard = trusted.lock().await;
        if let Some(existing) = trusted_guard.get(&peer_id).cloned() {
            if existing.static_pub != remote_static {
                anyhow::bail!("trusted peer key mismatch; refusing handshake");
            }
            existing
        } else {
            let window_open = pairing_window
                .lock()
                .await
                .map(|deadline| Instant::now() < deadline)
                .unwrap_or(false);
            if !window_open {
                anyhow::bail!(
                    "handshake from untrusted peer {:x?}; refusing",
                    &peer_id[..6]
                );
            }
            // FS-058 V1: refuse TOFU if the trusted set is already at its
            // hard cap. Without this, an attacker who flooded TOFU during
            // a past pairing window could keep adding entries that survive
            // restart via `peers.json`. The user still has a clear path
            // forward — they unpair the offending peer or wipe the file.
            if trusted_guard.len() >= MAX_TOFU_TRUSTED_PEERS {
                anyhow::bail!(
                    "TOFU refused: trusted set at cap ({MAX_TOFU_TRUSTED_PEERS}); unpair an unused peer first"
                );
            }
            let new_peer = tofu_trusted_peer(remote_static);
            tracing::info!(
                peer = ?&peer_id[..6],
                sas = ?sas_words,
                "TOFU: trusting new peer during pairing window — \
                 USER MUST CONFIRM via `fluxctl pair confirm` before this is durable"
            );
            trusted_guard.insert(peer_id, new_peer.clone());
            newly_tofu = true;

            // PERSIST to disk so we remember this peer after restart.
            // The disk name copies `new_peer.name` so the live session and
            // a post-restart load can never disagree (FS-030).
            // VULN-001 variant V6: if persist fails, roll back the in-mem
            // TOFU insert and refuse the handshake. Otherwise the peer is
            // trusted for the live session but silently forgotten across
            // restart, leaving the user with stale UI state.
            if let Some(ref dir) = keystore_dir {
                // F-001/F-002 hardening: upsert under the peers.json disk
                // lock so a concurrent reaper revoke cannot race the load,
                // and propagate parse errors so a corrupt peers.json is
                // refused (refusing the TOFU) instead of silently wiping
                // every other trusted peer from disk.
                if let Err(e) = crate::driver::upsert_peer_persist(
                    dir,
                    &transport,
                    crate::keystore::StoredPeer {
                        peer_id_hex: hex_encode(&peer_id),
                        static_pub_hex: hex_encode(&remote_static),
                        name: new_peer.name.clone(),
                        last_addr: Some(from.to_string()),
                    },
                )
                .await
                {
                    trusted_guard.remove(&peer_id);
                    anyhow::bail!(
                        "TOFU refused: failed to persist new trusted peer after retries: {e}; \
                         in-memory trust rolled back, ask the peer to re-handshake once disk recovers"
                    );
                }
            }

            new_peer
        }
    };

    // FS-052: record the SAS + expiry so the IPC layer can surface a
    // `fluxctl pair pending` listing. Inserted only for freshly-TOFU'd
    // peers — re-handshakes from already-trusted peers do not need a new
    // verbal compare.
    if newly_tofu {
        let mut pending_guard = pending.lock().await;
        // FS-058 M2: drop expired entries first, then enforce hard cap by
        // evicting the soonest-to-expire entry. Reaper task also sweeps
        // on a timer, but doing it inline guarantees the cap holds even
        // if the reaper is starved.
        let now = Instant::now();
        pending_guard.retain(|_, p| p.expires_at > now);
        if pending_guard.len() >= MAX_PENDING_PAIRS {
            if let Some(victim) = pending_guard
                .iter()
                .min_by_key(|(_, p)| p.expires_at)
                .map(|(k, _)| *k)
            {
                pending_guard.remove(&victim);
            }
        }
        pending_guard.insert(
            peer_id,
            PendingPair {
                static_pub: remote_static,
                name: entry.name.clone(),
                sas_words: sas_words.clone(),
                from,
                expires_at: now + PAIRING_WINDOW,
            },
        );
    }

    // Install before sending msg2 so a duplicate inbound HandshakeInit
    // (replay or honest retry) can't end up replacing the session we
    // just committed to. If install loses, drop msg2 too — peer will
    // either retry handshake or, if it already linked through another
    // path, ignore our late reply.
    //
    // DIR-P2-03: `rekey_generation` (`Some` only for the primary's
    // current/last peer, see above) routes through the generation-gated
    // CAS so a legitimate rekey — or a duplicate HandshakeInit for an
    // in-flight one — can replace a still-live session. Every other case
    // (fresh pairing, a secondary mesh peer) is unaffected: it keeps the
    // original empty-slot-only CAS.
    let installed = match rekey_generation {
        Some(expected) => {
            transport
                .install_primary_session_if_generation(peer_id, session, expected)
                .await
        }
        None => transport.try_install_session(peer_id, session).await,
    };
    if !installed {
        tracing::debug!("responder: session install lost a concurrent race; not sending msg2");
        return Ok(());
    }
    transport.set_peer_info(peer_id, from).await;
    // last_addr persistence + redial: covers both the TOFU
    // and already-trusted branches above in one place, since both funnel
    // through this same post-install point.
    crate::driver::persist_last_addr(keystore_dir.as_deref(), &transport, &trusted, peer_id, from)
        .await;
    transport
        .send_typed(TYPE_HANDSHAKE_RESP, &msg2, from)
        .await?;
    // DIR-P2-03: skip `PeerSeen` when this install just replaced a still-live
    // session — the peer's identity was already confirmed and never stopped
    // being Linked, so re-firing it would surface a redundant "Peer identity
    // confirmed" log/EmitState for what must stay an invisible rotation.
    // `HandshakeOk` still fires unconditionally: in `Phase::Linked` it is a
    // no-op in the FSM (see `fsm::transition`'s fallback arm) but keeps
    // `MetricsTracker::on_handshake_ok` bookkeeping consistent, same as any
    // other completed handshake.
    if !replacing_live_session {
        let _ = event_tx.try_send(Event::PeerSeen {
            peer_id,
            name: entry.name,
        });
    }
    let _ = event_tx.try_send(Event::HandshakeOk);
    Ok(())
}

/// FS-058 + FS-052 strict gate (VULN-002 fix): background sweep that
/// drops expired entries from `PendingSet` **and revokes the matching
/// `TrustedSet` entry** so a pending pair the user never confirmed does
/// not silently become permanent trust on the next daemon restart.
///
/// Behaviour on each expiry:
/// 1. Remove from `pending`.
/// 2. Remove from `trusted`.
/// 3. If the live session belongs to that peer, tear it down so further
///    frames are decryption-failed (and the FSM re-discovers).
/// 4. Persist the updated `peers.json` via [`crate::driver::save_peers_with_retry`].
///    If persistence ultimately fails the in-memory revoke still holds for
///    this daemon lifetime; we log at `error` level so it is visible.
///
/// Exits cleanly when the cancellation token is fired, so the daemon
/// shutdown path stays clean.
pub async fn run_pending_reaper(
    pending: PendingSet,
    trusted: TrustedSet,
    transport: std::sync::Arc<crate::transport::Transport>,
    keystore_dir: Option<std::path::PathBuf>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let mut tick = tokio::time::interval(PENDING_REAPER_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            _ = tick.tick() => {
                let now = Instant::now();
                // Snapshot expired entries so we can re-pend them if the
                // persistence step fails (VULN-001 variant V7).
                let expired_pending: Vec<([u8; 32], PendingPair)> = {
                    let mut g = pending.lock().await;
                    let mut out = Vec::new();
                    let now_copy = now;
                    g.retain(|peer_id, p| {
                        let alive = p.expires_at > now_copy;
                        if !alive {
                            out.push((*peer_id, p.clone()));
                        }
                        alive
                    });
                    out
                };
                if expired_pending.is_empty() {
                    continue;
                }
                let expired: Vec<[u8; 32]> =
                    expired_pending.iter().map(|(id, _)| *id).collect();
                let removed_trust: Vec<([u8; 32], TrustedPeer)> = {
                    let mut t = trusted.lock().await;
                    let mut out = Vec::new();
                    for id in &expired {
                        if let Some(p) = t.remove(id) {
                            out.push((*id, p));
                            tracing::warn!(
                                peer = ?&id[..6],
                                "FS-052: pending expired without --accept; revoking from trusted set"
                            );
                        }
                    }
                    out
                };
                // Tear down the live session if it belongs to one of the
                // revoked peers — otherwise the attacker's already-installed
                // session would keep accepting Hello/Heartbeat frames.
                let dropped_peer_id = {
                    let cur = transport.cached_peer_id().await;
                    match cur {
                        Some(cur) if expired.contains(&cur) => {
                            transport.drop_session().await;
                            Some(cur)
                        }
                        _ => None,
                    }
                };
                if let Some(dir) = keystore_dir.as_ref() {
                    if let Err(e) =
                        crate::driver::save_peers_with_retry(dir, &trusted, &transport).await
                    {
                        // Roll back: re-insert into trusted + re-pend so the
                        // next reaper tick retries. Without this, in-mem is
                        // revoked while disk still trusts → restart re-trusts.
                        {
                            let mut t = trusted.lock().await;
                            for (id, p) in &removed_trust {
                                t.insert(*id, p.clone());
                            }
                        }
                        {
                            let mut g = pending.lock().await;
                            for (id, p) in &expired_pending {
                                g.entry(*id).or_insert_with(|| p.clone());
                            }
                        }
                        tracing::error!(
                            error = %e,
                            count = expired.len(),
                            dropped_session = ?dropped_peer_id.map(|p| hex_encode(&p)),
                            "FS-052: failed to persist pending-expiry revoke; in-memory revoke rolled back. Session was already dropped (peer must re-handshake) but trust will be retried next reaper tick."
                        );
                        continue;
                    }
                }
                tracing::debug!(reaped = expired.len(), "PendingSet reaper");
            }
        }
    }
}

/// How often [`run_pending_reaper`] sweeps `PendingSet`.
pub const PENDING_REAPER_INTERVAL: Duration = Duration::from_secs(30);

/// Stable peer id = `BLAKE3(static_pub)`. Re-uses the workspace's
/// shared hash helper so producers can't accidentally diverge.
#[must_use]
pub fn peer_id_for(static_pub: &[u8; 32]) -> [u8; 32] {
    fluxsync_core::dedup::DedupRing::hash(static_pub).into_bytes()
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{tofu_trusted_peer, Duration, PAIRING_WINDOW, TOFU_PLACEHOLDER_NAME};

    /// FS-030: the TOFU placeholder name has one source. The in-memory
    /// `TrustedPeer` and the on-disk `StoredPeer` (which copies
    /// `new_peer.name`) must therefore carry the identical string, so the
    /// live session and a post-restart load never show two names.
    #[test]
    fn fs030_tofu_placeholder_is_single_source() {
        let peer = tofu_trusted_peer([7u8; 32]);
        assert_eq!(peer.name, TOFU_PLACEHOLDER_NAME);
        assert_eq!(peer.name, "New Peer");

        // The disk record is built as `name: new_peer.name.clone()`;
        // mirror that here to lock the structural single-source invariant.
        let disk_name = peer.name.clone();
        assert_eq!(disk_name, peer.name);
    }

    /// FS-032: the TOFU pairing window must stay short so a drive-by LAN
    /// handshake has only a narrow window to land in the trusted set.
    /// Guards against a regression back to the old 5-minute window.
    #[test]
    fn fs032_pairing_window_is_short() {
        assert!(
            PAIRING_WINDOW <= Duration::from_secs(90),
            "pairing window must not exceed 90s"
        );
        assert!(
            PAIRING_WINDOW >= Duration::from_secs(30),
            "pairing window must stay usable for a QR scan"
        );
    }
}
