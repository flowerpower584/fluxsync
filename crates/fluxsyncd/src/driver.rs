// Image dims (image crate caps), packet idx (u16-bounded), and saturated
// durations are the cast sources here — all safe at runtime.
#![allow(clippy::cast_possible_truncation)]

//! Daemon driver — composes [`fluxsync_core::App`] with IPC, transport,
//! mDNS discovery, and the Noise IK handshake.
//!
//! `run(cfg, shutdown)` is the public entry point. It spawns:
//! * IPC accept loop
//! * transport receive loop (typed wire dispatcher)
//! * mDNS discovery dispatcher (skipped in test mode or when disabled)
//! * the central event loop that owns the `App`
//!
//! Shutdown: a single `tokio_util::sync::CancellationToken`. Every loop
//! selects on `token.cancelled()` and exits. Cancellation is sticky —
//! a task that is not parked on `cancelled()` at the instant of
//! `cancel()` still observes it on its next poll, so no task can miss
//! the signal. The driver returns once all background tasks have
//! joined, so callers (test harness, `main.rs`) get a deterministic
//! shutdown deadline.

use crate::backoff::PeerBackoff;
use crate::cmd::{Channel, CmdData, CmdOp, CmdRequest, CmdResponse, PeerEntry, Subscribe};
use crate::config::{DaemonConfig, TestPair};
use crate::discovery::{self, DiscoveryEvent};
use crate::handshake::{
    self, PairingWindow, PendingSet, TrustedPeer, TrustedSet, MAX_PERSISTED_PEERS,
};
use crate::ipc::{IpcConn, IpcServer};
use crate::logs::LogTail;
use crate::metrics::{DisconnectReason, MetricsTracker};
use crate::rate_limit::HandshakeRateLimiter;
use crate::transport::{is_rekey_initiator, now_ms, rekey_due, RecvFrame, Transport};
use anyhow::{anyhow, Context, Result};
use base32::Alphabet;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use crate::history_store::{self, VaultEntry};
use crate::outbox::{Entry as OutboxEntry, Outbox};
use crate::seq_store::SeqStore;
use fluxsync_core::{
    dedup::DedupRing, kind_of, Action, App, Config as CoreConfig, Decision, DeviceId, Direction,
    Event, EventId, HistoryItem, LogEntry, LogLevel, PeerInfo, SeenSet, State, WallClock,
};
use fluxsync_crypto::gen_pair_pin;
use fluxsync_crypto::{fingerprint, Identity};
use fluxsync_proto::{
    negotiate_caps, ClipboardItem, Frame, Kind, Msg, ResyncOffer, ResyncPull, MAX_CHUNK_DATA,
    MAX_PAYLOAD, MAX_RESYNC_HASHES, PROTOCOL_VERSION, SUPPORTED_CAPS,
};
use hex;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const BASE32_ALPHA: Alphabet = Alphabet::Rfc4648 { padding: false };

/// This device's OS family, sent in `Msg::Hello` so the peer renders the
/// correct device icon. Mobile builds compile `fluxsyncd` for `android`/`ios`
/// via `fluxsync-mobile-ffi`, so those arms are reachable too.
const fn self_platform() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

// ─────────────────────────────────────────────────────────────────
// PR2 — PIN-method pairing state
// ─────────────────────────────────────────────────────────────────

/// PR2: the PIN currently advertised on mDNS. `Some` while the TOFU
/// pair window is open, `None` after expiry / pair success.
#[derive(Debug, Clone)]
pub struct PinAd {
    pub pin: String,
    pub expires_at: Instant,
}

pub type PinAdvertisement = Arc<Mutex<Option<PinAd>>>;

/// PR2: discovery cache. Every peer the daemon has seen on mDNS in
/// the last [`DISCOVERY_CACHE_TTL`], regardless of trust state.
/// `PairFromPin` reads this to resolve an as-yet-untrusted peer.
#[derive(Debug, Clone)]
pub struct ResolvedPeer {
    pub static_pub: [u8; 32],
    pub addr: SocketAddr,
    pub name: String,
    pub pair_pin: Option<String>,
    pub last_seen: Instant,
}

pub type DiscoveryCache = Arc<Mutex<HashMap<[u8; 32], ResolvedPeer>>>;

/// DIR-P1-02: per-peer reconnect backoff state, keyed by peer-id. See
/// [`crate::backoff::PeerBackoff`]. Purged wherever `DiscoveryCache` is
/// purged (unpair / revoke / vault wipe) — same trust-removal paths.
pub type BackoffMap = Arc<Mutex<HashMap<[u8; 32], PeerBackoff>>>;

/// FS-052 wire mutual confirm (`sas-confirm` capability): peer-ids the
/// local user already accepted (`CmdOp::PairConfirm { accept: true }`)
/// before that peer's `Hello` — and therefore its negotiated caps — had
/// arrived. The `Msg::Hello` handler in `dispatch_inbound_frame` flushes
/// (and removes) the deferred `Msg::PairConfirm { accept: true }` send the
/// moment it learns the peer actually supports the capability.
pub type DeferredSasConfirm = Arc<Mutex<HashSet<[u8; 32]>>>;

/// Asymmetric-trust echo-ack guard: peer-ids we have already sent a
/// `Msg::PairConfirm { accept: true }` echo-ack to (see
/// `dispatch_inbound_frame`'s `Msg::PairConfirm` handling) since their
/// session was established. A malformed/hostile peer that keeps resending
/// `PairConfirm{accept:true}` outside a live SAS flow gets exactly one
/// echo back per session, not an unbounded ping-pong. Cleared on `Bye` /
/// `Revoke` / an explicit local reject, same lifecycle as `PeerMeta`.
pub type EchoAckSent = Arc<Mutex<HashSet<[u8; 32]>>>;

/// PR2: cache TTL. mdns-sd re-resolves periodically so an honest peer
/// is refreshed well before this; the TTL only fires for peers that
/// physically left the LAN.
pub const DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(120);

/// PR2: mDNS daemon + identity fields needed to re-publish the
/// service record when the PIN rotates.
#[derive(Clone)]
pub struct MdnsContext {
    pub daemon: mdns_sd::ServiceDaemon,
    pub instance_name: String,
    pub peer_id_hex: String,
    pub static_pub_hex: String,
    pub bind_ip: std::net::IpAddr,
    pub udp_port: u16,
}

pub type MdnsCtx = Arc<Mutex<Option<MdnsContext>>>;

/// H2 fix: bounded, TTL'd record of content hashes deliberately cleared via
/// `CmdOp::ClearHistory`. `ClearHistory` is LOCAL-ONLY by design — never
/// propagated to peers — so a peer that still holds a cleared item in its
/// own outbox (see `outbox.rs`) re-offers it via the next `ResyncOffer`
/// after a relink. `missing_resync_hashes` consults this set so a
/// deliberately-cleared item is never re-pulled back into history. Keyed by
/// content hash -> the `Instant` it was cleared; entries age out past
/// `crate::outbox::MAX_AGE` (the offering peer's own outbox would have
/// dropped the item by then anyway, so there is nothing left to guard
/// against). Gates PULLS only — a local re-copy/send of the same content is
/// unaffected.
pub type ClearedTombstone = Arc<Mutex<HashMap<[u8; 32], Instant>>>;

/// Hard cap on `ClearedTombstone` size. A single "clear history" only ever
/// tombstones a bounded number of hashes at once; this is generous headroom
/// against repeated clears over a long uptime, not a realistic ceiling.
/// Oldest-cleared evicted first if ever exceeded.
const MAX_CLEARED_TOMBSTONE: usize = 4096;

/// Record `hashes` as deliberately cleared. Purges tombstone entries older
/// than `crate::outbox::MAX_AGE` first, then evicts the oldest surviving
/// entries if the insert would exceed `MAX_CLEARED_TOMBSTONE`.
async fn mark_cleared(tombstone: &ClearedTombstone, hashes: &[[u8; 32]]) {
    if hashes.is_empty() {
        return;
    }
    let now = Instant::now();
    let mut g = tombstone.lock().await;
    g.retain(|_, cleared_at| now.saturating_duration_since(*cleared_at) <= crate::outbox::MAX_AGE);
    for h in hashes {
        g.insert(*h, now);
    }
    while g.len() > MAX_CLEARED_TOMBSTONE {
        let Some(oldest) = g.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k) else {
            break;
        };
        g.remove(&oldest);
    }
}

/// Hex-encoded, still-live (non-expired) cleared hashes, for feeding
/// straight into `missing_resync_hashes`'s exclusion list.
async fn cleared_hex_snapshot(tombstone: &ClearedTombstone) -> Vec<String> {
    let now = Instant::now();
    tombstone
        .lock()
        .await
        .iter()
        .filter(|(_, cleared_at)| now.saturating_duration_since(**cleared_at) <= crate::outbox::MAX_AGE)
        .map(|(h, _)| hex::encode(h))
        .collect()
}

/// Bug #7 (pending_pulls stale suppression): hex-encoded hashes we already
/// have an outstanding `ResyncPull` in flight for, to ANY peer, still fresh
/// (`RESYNC_PULL_TIMEOUT`). Feeding this into `missing_resync_hashes`'s
/// exclusion list stops a second peer's `ResyncOffer` from starting a
/// SECOND pull for a hash already being chased — without this, two peers
/// offering the same hash both got asked, but only one response can ever be
/// first-sight (`mesh_seen` drops the other, identical-`EventId` arrival
/// before it reaches `take_pending_pull`), leaving the loser's entry stale
/// until timeout — long enough to misclassify that peer's next genuinely
/// fresh copy of the same content as resync catch-up and silently drop it.
async fn in_flight_pull_hashes(pending_pulls: &PendingPulls) -> Vec<String> {
    pending_pulls
        .lock()
        .await
        .values()
        .flat_map(|per_peer| per_peer.iter())
        .filter(|(_, asked_at)| asked_at.elapsed() < RESYNC_PULL_TIMEOUT)
        .map(|(h, _)| hex::encode(h))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect()
}

/// Drive a daemon to completion, returning once `shutdown` fires and
/// every background task has joined.
pub async fn run(cfg: DaemonConfig, shutdown: CancellationToken) -> Result<()> {
    let DaemonConfig {
        identity,
        peer_name_self,
        udp_port,
        udp_bind,
        ipc_path,
        // Plumbed for the upcoming peers.json wire-up. Both fields are
        // intentionally unused inside the driver right now: `main.rs`
        // already writes `identity.bin` via `keystore::load_or_create_identity`,
        // and the trusted-peer set will be persisted in `peers.json`
        // alongside it once the wire-up lands.
        trusted_peer_keys: _,
        keystore_dir,
        charge_override,
        wall_clock,
        disable_mdns,
        disable_clipboard,
        start_on,
        test_pair,
        test_pairs,
        test_pending_pair,
        test_peer_static_pub,
        rekey_max_age_ms,
        rekey_max_bytes,
        lan_only_handshakes,
        firewall,
    } = cfg;

    // Chantier A: the on-disk firewall policy is authoritative when a keystore
    // is present, so a SetFirewall survives restarts. With no keystore (tests),
    // keep whatever the caller injected.
    let firewall = match keystore_dir.as_ref() {
        Some(dir) => crate::keystore::load_firewall(dir),
        None => firewall,
    };

    // DIR-P3-01: same rationale as the firewall load above — a persisted
    // `CmdOp::SetDeviceName` is authoritative across restarts. Falls back to
    // whatever `main.rs` resolved (hostname or `--peer-name`) when no rename
    // has ever been persisted. This is the single source `CoreConfig`, mDNS
    // advertisement, and the initial `Msg::Hello` all read below.
    let peer_name_self = match keystore_dir.as_ref() {
        Some(dir) => crate::keystore::load_device_name(dir).unwrap_or(peer_name_self),
        None => peer_name_self,
    };

    // ── App + channels ────────────────────────────────────────────
    let mut app = App::new_with_device(
        CoreConfig {
            peer_name_self: peer_name_self.clone(),
            charge_override,
            version: String::from(env!("CARGO_PKG_VERSION")),
            build_id: String::from(env!("FLUXSYNCD_BUILD_ID")),
            cipher: String::from("chacha20-poly1305"),
            firewall,
            mdns_enabled: !disable_mdns,
        },
        // This daemon's stable mesh identity: the BLAKE3 id of its Noise
        // static key, the same bytes peers see as `peer_id`. Stamped as
        // `EventId.origin` on every locally-copied item.
        fluxsync_core::DeviceId::from(identity.peer_id()),
    );

    // ── Restore the persisted outgoing event-seq horizon ──────────
    // `App.local_seq` (stamped as `EventId.seq` on every locally-originated
    // item, see `next_local_event_id`) used to reset to 0 on every restart,
    // so a peer's mesh anti-loop `SeenSet` could wrongly treat freshly
    // re-issued low seqs as replays of items it had already recorded. See
    // `seq_store.rs` for the reserve-ahead persistence scheme. No keystore
    // dir (test mode) means no restored seq and no persistence — `app`
    // simply keeps its fresh `local_seq == 0`, same as before this fix.
    let mut seq_store: Option<SeqStore> = if let Some(dir) = keystore_dir.as_ref() {
        let (initial_seq, store) = SeqStore::load(dir);
        app.set_local_seq(initial_seq);
        Some(store)
    } else {
        None
    };

    // ── FluxVault: rehydrate persisted history ────────────────────
    // Decrypt the on-disk history (if any) and seed it into the App
    // *before* the first snapshot, so every consumer sees the restored
    // list immediately. Best-effort: a load failure (wrong identity,
    // tampered file) logs and starts empty rather than aborting boot.
    let vault: Option<(PathBuf, zeroize::Zeroizing<[u8; 32]>, Vec<VaultEntry>)> =
        if let Some(dir) = keystore_dir.as_ref() {
            let key = identity.derive_at_rest_key(history_store::AT_REST_CONTEXT);
            let entries = match history_store::load(
                dir,
                &key,
                now_ms(),
                history_store::DEFAULT_TTL_SECS,
            ) {
                Ok(entries) => {
                    app.restore_history(entries.iter().map(|e| e.item.clone()).collect());
                    tracing::info!(count = entries.len(), "rehydrated history from vault");
                    entries
                }
                Err(e) => {
                    tracing::warn!(error = %e, "vault load failed; starting with empty history");
                    Vec::new()
                }
            };
            Some((dir.clone(), key, entries))
        } else {
            None
        };

    let initial = app.snapshot().clone();
    let (state_watch_tx, state_watch_rx) = watch::channel(initial);

    let (logs_bcast_tx, _) = broadcast::channel::<LogEntry>(64);
    // M-DAEMON-11: bounded so a hostile LAN flood (mDNS spam → DiscoveryEvent,
    // or forged frames → Event) can't grow the daemon's memory without bound.
    // Every producer uses `try_send` and drops on full (all sends are already
    // fire-and-forget); the cap is far above any legitimate burst. The M-DAEMON-17
    // fix removed the per-frame fsync that used to stall this consumer.
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(EVENT_CHANNEL_CAP);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<DriverCmd>();
    let log_tail = Arc::new(LogTail::new());

    // ── Trusted peers ─────────────────────────────────────────────
    // FS-039: persistent pairing. Reload the trusted set from
    // `peers.json` so a paired peer survives a daemon restart.
    let trusted: TrustedSet = Arc::new(Mutex::new(HashMap::new()));
    // Persisted redial hints (`last_addr` redial), collected
    // alongside the trust reload below and applied to `transport` once it
    // is bound (see the seed loop after `Transport::bind`). Relocated here
    // (rather than reviving `main.rs`'s old per-peer parse into a single
    // `DaemonConfig` field) because `run()` already independently reloads
    // `peers.json` via `load_trusted_peers` to build `trusted` — this is
    // the natural single place to also learn every peer's last address.
    let mut last_known_addrs: Vec<([u8; 32], SocketAddr)> = Vec::new();
    // Item 4 (secondary redial): the same persisted `last_addr` per trusted
    // peer, kept as a lookup map so the proactive redial tick can find a
    // SECONDARY's last known address even when it has never held a session
    // on `transport` this boot (so `roaming_history_snapshot_for` is empty
    // for it) — see `discovery_dispatcher`'s redial tick.
    let mut persisted_peer_addrs: HashMap<[u8; 32], SocketAddr> = HashMap::new();
    if let Some(dir) = keystore_dir.as_ref() {
        let loaded = load_trusted_peers(dir);
        let count = loaded.len();
        {
            let mut g = trusted.lock().await;
            for (peer_id, peer, last_addr) in loaded {
                g.insert(peer_id, peer);
                if let Some(addr) = last_addr {
                    last_known_addrs.push((peer_id, addr));
                    persisted_peer_addrs.insert(peer_id, addr);
                }
            }
        }
        tracing::info!(count, "loaded trusted peers from keystore");
    }

    // ── Transport (always bound; session/peer_addr filled later) ───
    let (transport_inner, actual_port) = Transport::bind(&udp_bind, udp_port)
        .await
        .with_context(|| format!("bind UDP {udp_bind}:{udp_port}"))?;
    let transport = Arc::new(transport_inner);
    let metrics = transport.metrics.clone();
    let udp_port = actual_port; // Shadow with the real port (in case it was 0)
    tracing::info!(port = udp_port, "UDP transport bound");

    // Pending initiator coordination: at most one handshake in flight
    // (single peer in v0.1.1). transport_recv routes msg2 here.
    let pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(Mutex::new(None));

    // Pairing window for TOFU on the responder side. Set by `PairShow`
    // to `now + 5 min`; outside the window the responder enforces strict
    // trust against `trusted_peer_keys` / previously-paired peers.
    let pairing_window: PairingWindow = Arc::new(Mutex::new(None));

    // FS-052: peers auto-trusted under TOFU but not yet verbally
    // confirmed by the user. Each entry carries the 6-word SAS computed
    // from the Noise handshake hash so `fluxctl pair pending` /
    // `fluxctl pair confirm` can surface and resolve them.
    let pending_pairs: PendingSet = Arc::new(Mutex::new(HashMap::new()));

    // FS-052 wire mutual confirm: peer-ids whose local `--accept` send is
    // deferred until their `Hello` (and therefore negotiated caps) arrives.
    // See `DeferredSasConfirm`.
    let deferred_sas_confirm: DeferredSasConfirm = Arc::new(Mutex::new(HashSet::new()));

    // Asymmetric-trust echo-ack: peer-ids we've already echoed a
    // `Msg::PairConfirm{accept:true}` back to during the current session.
    // See `EchoAckSent`.
    let echo_ack_sent: EchoAckSent = Arc::new(Mutex::new(HashSet::new()));

    // PR2: PIN-method pairing state. `pin_advert` holds the current
    // PIN + expiry; `disc_cache` lets `PairFromPin` resolve an
    // untrusted peer by its TXT `pair_pin`; `mdns_ctx` is populated
    // once mDNS is up so the PIN-rotation watchdog can re-publish.
    let pin_advert: PinAdvertisement = Arc::new(Mutex::new(None));
    let disc_cache: DiscoveryCache = Arc::new(Mutex::new(HashMap::new()));
    // DIR-P1-02: reconnect backoff, one entry per peer-id. Created
    // alongside `disc_cache` so it can be threaded to the same purge
    // sites (unpair/revoke/wipe) and the same reconnect call sites.
    let backoff: BackoffMap = Arc::new(Mutex::new(HashMap::new()));
    let mdns_ctx: MdnsCtx = Arc::new(Mutex::new(None));
    // H2 fix: content hashes deliberately cleared via `CmdOp::ClearHistory`,
    // so a peer's later `ResyncOffer` for one of them can never re-pull it.
    let cleared_tombstone: ClearedTombstone = Arc::new(Mutex::new(HashMap::new()));

    // ── Long-lived tasks ──────────────────────────────────────────
    // Declared here (rather than just before the IPC task below) so the
    // vault persister — which must be tracked in this `JoinSet` rather than
    // bare-`tokio::spawn`ed, see DEFECT 2's fix — can join it too.
    let mut tasks = JoinSet::new();

    // Persist history off the state-watch channel: a dedicated task wakes
    // on every state change, diffs the history list, and writes the vault
    // only when it actually changed (skipping the frequent battery /
    // heartbeat / peer-list EmitStates). Lives only when a keystore dir is
    // configured; exits on `shutdown` (or when the watch sender drops).
    // Spawned here (after `disc_cache` exists) so the persister can also
    // purge it on a security wipe (DIR-P2-04a).
    if let Some((dir, key, entries)) = vault {
        let ctx = VaultCtx {
            dir,
            key,
            last: app.snapshot().history.clone(),
            entries,
        };
        // Seed the persister's wipe-gen baseline from the snapshot it is
        // constructed against (0 at boot), so a security wipe published before
        // the task's first poll is still observed as a change (see the note in
        // run_vault_persister).
        let initial_wipe_gen = app.snapshot().vault_wipe_gen;
        // Clone every shared handle BEFORE the `async move` block: the
        // block captures by move, and `disc_cache`/`backoff`/`state_watch_tx`
        // are all still needed by later setup (the transport recv loop, the
        // main event loop) in the rest of `run()`.
        let state_rx_for_persister = state_watch_tx.subscribe();
        let disc_cache_for_persister = disc_cache.clone();
        let backoff_for_persister = backoff.clone();
        // DEFECT 2 fix: tracked in `tasks` (not a bare detached `tokio::spawn`)
        // and handed a clone of `shutdown`, so `run()`'s final
        // `while tasks.join_next().await.is_some() {}` actually waits for this
        // task's last-write flush before the caller can exit. See
        // `run_vault_persister`'s doc comment.
        let shutdown_for_persister = shutdown.clone();
        tasks.spawn(async move {
            run_vault_persister(
                ctx,
                state_rx_for_persister,
                initial_wipe_gen,
                disc_cache_for_persister,
                backoff_for_persister,
                shutdown_for_persister,
            )
            .await;
            Ok(())
        });
    }

    if let Some(tpp) = test_pending_pair {
        pending_pairs.lock().await.insert(
            tpp.peer_id,
            crate::handshake::PendingPair {
                static_pub: tpp.static_pub,
                name: tpp.name,
                sas_words: tpp.sas_words,
                from: tpp.from,
                expires_at: Instant::now() + tpp.expires_in,
            },
        );
    }

    // Last clipboard payload we wrote to the OS clipboard (i.e., received
    // from the peer). The clipboard watcher dedups against this so it
    // doesn't immediately read its own write back, fire LocalClipboardChange,
    // and ping-pong the same item back to the peer.
    let last_written_hashes: Arc<Mutex<VecDeque<[u8; 32]>>> =
        Arc::new(Mutex::new(VecDeque::with_capacity(10)));

    // Outbound items awaiting acks. Shared between the action dispatch
    // (inserts on SendItem), the inbound frame handler (removes on Ack),
    // and the transport loop's retransmit timer.
    let inflight: InflightMap = Arc::new(Mutex::new(HashMap::new()));

    // FluxMesh 2C-b: shared mesh anti-loop guard (EventId seen-set). Used by
    // the recv loop to forward each item exactly once and never loop.
    let mesh_seen: MeshSeen = Arc::new(Mutex::new(SeenSet::default()));

    // FluxMesh Phase 3: per-peer UI metadata feeding the State `peers` list.
    // Written by the recv loop (every peer's Hello/Battery), read at EmitState.
    let peer_meta: PeerMetaMap = Arc::new(Mutex::new(BTreeMap::new()));

    // Resync-on-reconnect (resync-1): recent non-sensitive outbound/inbound
    // items, kept just long enough to re-offer to a peer that reconnects
    // after missing them. Written on SendItem and on first-sight reception,
    // read to build a ResyncOffer and to serve a ResyncPull.
    let outbox: SharedOutbox = Arc::new(Mutex::new(Outbox::new()));
    // resync-1 apply-suppression fix: hashes we've asked a peer for via
    // ResyncPull, so the receive path can tell "I requested this catch-up
    // item" apart from a fresh copy. See `PendingPulls`'s doc comment.
    let pending_pulls: PendingPulls = Arc::new(Mutex::new(HashMap::new()));
    // Outbox admission gate fix: an inbound item the firewall parks under
    // `Ask` is not yet admitted to history, so it must not enter `outbox`
    // yet either — but its (origin, seq) wire metadata is only known at
    // receive time, and is lost by the time a later `ResolvePending`
    // resolves it (`fluxsync_core`'s `PendingPayload` carries no such
    // fields). This staging map bridges that gap: `complete_reassembled_item`
    // / `dispatch_inbound_frame` park an `Ask`-decided item's full
    // `OutboxEntry` here instead of in `outbox`, and `CmdOp::ResolvePending`
    // promotes it into the real `outbox` on `allow: true` (or drops it
    // otherwise). See `PendingOutboxStage`'s doc comment.
    let outbox_stage: PendingOutboxStage = Arc::new(Mutex::new(HashMap::new()));

    // ── Test path: install session + jump to Linked ────────────────
    if let Some(tp) = test_pair {
        let TestPair {
            session,
            peer_addr,
            peer_name,
            peer_id,
        } = tp;
        transport.install_session(peer_id, session).await;
        transport.set_peer_addr(peer_addr).await;
        // Add peer to trusted set under a placeholder pubkey (or, if the
        // test injected one via `test_peer_static_pub`, the real key — a
        // DIR-P2-03 rekey test needs a genuine key so the forced rekey's
        // Noise IK exchange can actually complete against the peer) so the
        // App's peer_name lookup paths still find an entry.
        trusted.lock().await.insert(
            peer_id,
            TrustedPeer {
                static_pub: test_peer_static_pub.unwrap_or([0u8; 32]),
                name: peer_name.clone(),
            },
        );
        event_tx.try_send(Event::ToggleOn).ok();

        event_tx
            .try_send(Event::PeerSeen {
                peer_id,
                name: peer_name,
            })
            .ok();
        event_tx.try_send(Event::HandshakeOk).ok();
        event_tx
            .try_send(Event::BatteryChangedSelf {
                level: 80,
                charging: false,
            })
            .ok();
        event_tx
            .try_send(Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            })
            .ok();
    }

    // FluxMesh 2C-b: install ADDITIONAL pre-paired peers (mesh test harness).
    // Secondary peers get a session + trust + address so clipboard fans out
    // and relays to them, but they do NOT drive the single FSM — the primary
    // `test_pair` already drove it to Linked.
    for tp in test_pairs {
        let TestPair {
            session,
            peer_addr,
            peer_name,
            peer_id,
        } = tp;
        transport.install_session(peer_id, session).await;
        transport.set_peer_addr_for(peer_id, peer_addr).await;
        trusted.lock().await.insert(
            peer_id,
            TrustedPeer {
                static_pub: [0u8; 32],
                name: peer_name,
            },
        );
    }

    // Seed the transport's per-peer reconnect cache from each trusted
    // peer's persisted `last_addr` (collected above, alongside the trust
    // reload). `set_peer_info` records both the address AND the peer id
    // together, which is what lets the always-on proactive-probe redial
    // (see `discovery_dispatcher`) recognize "no session yet, but we know
    // who and where to try" immediately at boot — with zero mDNS
    // involvement. If more than one trusted peer has a persisted address,
    // the last one processed here wins the shared "primary" redial slot;
    // this matches the rest of the driver's single-primary-peer reconnect
    // model (see `Transport::cached_peer_addr`/`cached_peer_id`).
    for (peer_id, addr) in last_known_addrs {
        // L4 fix: a `peers.json` written before this fix (or corrupted by
        // hand) could hold a bogus address class; never seed a redial from
        // one, matching the same-shape guard now in `persist_last_addr`.
        if is_redialable_addr(addr.ip()) {
            transport.set_peer_info(peer_id, addr).await;
        } else {
            tracing::warn!(
                peer = %hex::encode(&peer_id[..6]),
                %addr,
                "L4: refusing to seed a boot-time redial from a link-local/multicast/unspecified address"
            );
        }
    }

    // Inform App about trusted peers for UI hints.
    {
        let g = trusted.lock().await;
        let primary_id = transport.cached_peer_id().await;
        if let Some(peer) = choose_boot_trusted_peer(&g, primary_id) {
            tracing::info!(peer = %peer.name, "Boot: informing UI about trusted peer");
            event_tx
                .try_send(Event::SetTrustedPeer {
                    name: peer.name.clone(),
                })
                .ok();
        }
    }

    // ── State-Aware Boot: Auto-toggle ON if requested ─────────────
    if start_on {
        tracing::info!("State-Aware Boot: auto-starting sync");
        event_tx.try_send(Event::ToggleOn).ok();
    }

    // IPC.
    let ipc_server = IpcServer::bind(&ipc_path)
        .await
        .with_context(|| format!("bind ipc socket {}", ipc_path.display()))?;
    {
        let cmd_tx = cmd_tx.clone();
        let state_rx = state_watch_rx.clone();
        let logs_tx = logs_bcast_tx.clone();
        let log_tail = log_tail.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            ipc_accept_loop(ipc_server, cmd_tx, state_rx, logs_tx, log_tail, shutdown).await
        });
    }

    // Transport receive loop.
    {
        let transport = transport.clone();
        let identity = identity.clone();
        let trusted = trusted.clone();
        let pending = pending_initiator_tx.clone();
        let window = pairing_window.clone();
        let event_tx = event_tx.clone();
        let shutdown = shutdown.clone();
        let kd = keystore_dir.clone();
        let metrics = metrics.clone();
        let inflight = inflight.clone();
        let pending_pairs_for_recv = pending_pairs.clone();
        let mesh_seen_for_recv = mesh_seen.clone();
        let peer_meta_for_recv = peer_meta.clone();
        let disc_cache_for_recv = disc_cache.clone();
        let backoff_for_recv = backoff.clone();
        let outbox_for_recv = outbox.clone();
        let pending_pulls_for_recv = pending_pulls.clone();
        let outbox_stage_for_recv = outbox_stage.clone();
        let state_rx_for_recv = state_watch_tx.subscribe();
        let deferred_sas_confirm_for_recv = deferred_sas_confirm.clone();
        let echo_ack_sent_for_recv = echo_ack_sent.clone();
        let cleared_tombstone_for_recv = cleared_tombstone.clone();
        tasks.spawn(async move {
            transport_recv_loop(
                transport,
                identity,
                trusted,
                window,
                pending,
                event_tx,
                shutdown,
                kd,
                metrics,
                inflight,
                pending_pairs_for_recv,
                mesh_seen_for_recv,
                peer_meta_for_recv,
                disc_cache_for_recv,
                backoff_for_recv,
                lan_only_handshakes,
                outbox_for_recv,
                pending_pulls_for_recv,
                outbox_stage_for_recv,
                state_rx_for_recv,
                deferred_sas_confirm_for_recv,
                echo_ack_sent_for_recv,
                cleared_tombstone_for_recv,
            )
            .await
        });
    }

    // FS-058: background reaper that drops expired PendingSet entries.
    // FS-052 strict gate (VULN-002): on expiry, revoke the matching
    // trusted entry + drop the live session + persist `peers.json` so a
    // pending peer the user never confirmed cannot survive across reboot.
    {
        let pending = pending_pairs.clone();
        let trusted_r = trusted.clone();
        let transport_r = transport.clone();
        let kd = keystore_dir.clone();
        let s = shutdown.clone();
        let event_tx_r = event_tx.clone();
        tasks.spawn(async move {
            handshake::run_pending_reaper(pending, trusted_r, transport_r, kd, s, event_tx_r).await;
            Ok(())
        });
    }

    // This device's latest battery reading, shared with the heartbeat loop so
    // it can re-broadcast the current level to the primary peer every tick.
    // Battery is otherwise only sent on change (macOS poll) or via the Android
    // broadcast — a steady level would never refresh on the peer after the
    // handshake. 255 = "not read yet" → the heartbeat skips sending until real.
    let self_batt_level = Arc::new(std::sync::atomic::AtomicU8::new(255));
    let self_batt_charging = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Heartbeat loop.
    {
        let transport = transport.clone();
        let event_tx = event_tx.clone();
        let shutdown = shutdown.clone();
        let metrics = metrics.clone();
        let peer_meta = peer_meta.clone();
        let self_batt_level = self_batt_level.clone();
        let self_batt_charging = self_batt_charging.clone();
        let backoff_for_heartbeat = backoff.clone();
        tasks.spawn(async move {
            if let Err(e) = heartbeat_loop(
                transport,
                event_tx,
                shutdown,
                metrics,
                backoff_for_heartbeat,
                peer_meta,
                self_batt_level,
                self_batt_charging,
            )
            .await
            {
                tracing::warn!(error = %e, "heartbeat loop exited");
            }
            Ok(())
        });
    }

    // DIR-P2-03: automatic session rekey watchdog.
    {
        let identity = identity.clone();
        let transport = transport.clone();
        let trusted = trusted.clone();
        let pending_initiator_tx = pending_initiator_tx.clone();
        let event_tx = event_tx.clone();
        let backoff = backoff.clone();
        let shutdown = shutdown.clone();
        let kd = keystore_dir.clone();
        tasks.spawn(async move {
            rekey_watchdog(
                identity,
                transport,
                trusted,
                pending_initiator_tx,
                event_tx,
                backoff,
                rekey_max_age_ms,
                rekey_max_bytes,
                kd,
                shutdown,
            )
            .await
        });
    }

    // mDNS discovery. The `discovery_dispatcher` task below is ALWAYS
    // spawned, regardless of `disable_mdns` or test mode: it also drives
    // the mDNS-independent proactive-probe redial (persisted `last_addr`
    // seeded above + roaming history), which must keep working with mDNS
    // fully off (`--disable-mdns` silences both directions,
    // but redial-by-persisted-address must not depend on mDNS at all).
    // Only the actual `discovery::start` call — binding a real
    // `ServiceDaemon`, registering (making us discoverable), and browsing
    // (making us discover others) — is gated: that is the "both
    // directions of mDNS" this flag controls. When gated off, `disc_tx`
    // is dropped immediately without ever being handed to a live mDNS
    // daemon, so `discovery_dispatcher`'s `disc_rx.recv()` branch cleanly
    // resolves to `None` (channel closed) forever after — `select!`
    // treats a non-matching `Some(x) = ...` pattern as "not ready" and
    // simply re-polls on the next loop iteration, so this never busy-loops.
    let mut _mdns_daemon = None;
    let we_are_test_mode = transport.has_session().await;
    let (disc_tx, disc_rx) = mpsc::channel::<DiscoveryEvent>(DISCOVERY_CHANNEL_CAP);
    if !disable_mdns && !we_are_test_mode {
        // mDNS must advertise (and egress on) the real LAN interface, not
        // 0.0.0.0. On multi-interface hosts (macOS awdl0/utunN) an
        // unspecified bind_ip makes mdns-sd announce on every interface and
        // pick a non-LAN one, so peers never see us. Resolve the egress LAN
        // IP and pin mDNS to it.
        let bind_ip: std::net::IpAddr = local_lan_addr(&udp_bind, udp_port)
            .rsplit_once(':')
            .and_then(|(ip, _)| ip.parse().ok())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let peer_id_hex = hex::encode(identity.peer_id());
        let static_pub_hex = hex::encode(identity.public_key());
        match discovery::start(
            &peer_name_self,
            &peer_id_hex,
            &static_pub_hex,
            bind_ip,
            udp_port,
            disc_tx,
            shutdown.clone(),
        ) {
            Ok(daemon) => {
                _mdns_daemon = Some(daemon.clone());
                // PR2: record mDNS context so PIN rotations can re-publish
                // without re-binding the daemon.
                *mdns_ctx.lock().await = Some(MdnsContext {
                    daemon: daemon.clone(),
                    instance_name: peer_name_self.clone(),
                    peer_id_hex: peer_id_hex.clone(),
                    static_pub_hex: static_pub_hex.clone(),
                    bind_ip,
                    udp_port,
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "mDNS unavailable; pairing requires --addr in pair-accept");
            }
        }
    } else {
        drop(disc_tx);
    }
    let persisted_peer_addrs = Arc::new(persisted_peer_addrs);
    {
        let identity = identity.clone();
        let trusted = trusted.clone();
        let transport = transport.clone();
        let pending = pending_initiator_tx.clone();
        let event_tx = event_tx.clone();
        let shutdown = shutdown.clone();
        let disc_cache = disc_cache.clone();
        let backoff = backoff.clone();
        let kd = keystore_dir.clone();
        let persisted_peer_addrs = persisted_peer_addrs.clone();
        tasks.spawn(async move {
            discovery_dispatcher(
                disc_rx, identity, trusted, transport, pending, event_tx, disc_cache, backoff,
                persisted_peer_addrs,
                kd, shutdown,
            )
            .await
        });
    }

    // Clipboard watcher (read side). Polls the OS clipboard every
    // 200ms, dedups, and routes any change through the same `Push`
    // command path the IPC `push` op uses — so dedup + lamport
    // allocation + send-to-peer all reuse existing logic.
    //
    // Android target excluded: there's no daemon-side clipboard API
    // (it'd require background read which the OS denies anyway).
    // `MainActivity` registers a `ClipboardManager` listener instead
    // and pushes via the FFI's `push_text`.
    #[cfg(not(target_os = "android"))]
    if disable_clipboard {
        tracing::info!(disable_clipboard, "Clipboard watcher disabled by config");
    } else {
        tracing::info!("Spawning clipboard watcher task");
        let cmd_tx = cmd_tx.clone();
        let transport = transport.clone();
        let last_written = last_written_hashes.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            tracing::info!("Clipboard watcher task started");
            if let Err(e) = clipboard_watcher_loop(transport, cmd_tx, last_written, shutdown).await
            {
                tracing::error!(error = %e, "clipboard_watcher_loop exited with error");
            }
            Ok(())
        });
    }

    // Ghost Timeout watchdog.
    // If we are in Discovering phase with a known peer, and 10 minutes
    // pass without reconnecting, drop the peer to prevent permanent ghosting.
    //
    // The pairing window is NOT opened here: it opens only on an explicit
    // `PairShow` IPC command. A watchdog re-opening it would keep the TOFU
    // window permanently open while unpaired (FS-040).
    {
        let state_rx = state_watch_rx.clone();
        let event_tx_clone = event_tx.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            let mut rx = state_rx;
            let mut last_discovering_with_peer: Option<std::time::Instant> = None;
            loop {
                let state = rx.borrow().clone();

                // Ghost Timeout Check
                if state.phase == "discovering" && !state.peer_name.is_empty() {
                    if let Some(start) = last_discovering_with_peer {
                        if Instant::now().duration_since(start) > Duration::from_secs(600) {
                            tracing::warn!("Ghost Timeout: 10 minutes elapsed without reconnection. Unpairing.");
                            let _ = event_tx_clone.try_send(Event::GhostTimeout);
                            last_discovering_with_peer = None;
                        }
                    } else {
                        last_discovering_with_peer = Some(Instant::now());
                    }
                } else {
                    last_discovering_with_peer = None;
                }

                let loop_start = Instant::now();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = rx.changed() => {},
                    () = tokio::time::sleep(Duration::from_secs(5)) => {}
                }

                // [REMEDIATION] Wake Jump Protection: If the loop paused for >30s,
                // we likely just woke up from sleep. Reset the timer.
                if loop_start.elapsed() > Duration::from_secs(30) {
                    last_discovering_with_peer = None;
                }
            }
            Ok(())
        });
    }

    // Battery watcher (desktop OSes; Android is event-driven via the FFI).
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let event_tx = event_tx.clone();
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            if let Err(e) = crate::battery::battery_watcher_loop(event_tx, shutdown).await {
                tracing::warn!(error = %e, "battery watcher loop exited");
            }
            Ok(())
        });
    }

    // FIX3 (synchronous security-wipe disk clear): tracks the last
    // `vault_wipe_gen` this loop has already reacted to, so it can tell a
    // fresh bump apart from one it already handled. Seeded from the current
    // snapshot (0 at a fresh boot) — same rationale as the vault
    // persister's own `initial_wipe_gen` above.
    let mut last_wipe_gen_sync: u64 = app.snapshot().vault_wipe_gen;

    // ── Main event loop ────────────────────────────────────────────
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            Some(event) = event_rx.recv() => {
                if let Event::HandshakeOk = event {
                    metrics.lock().await.on_handshake_ok();
                }
                if let Event::BatteryChangedSelf { level, charging } = &event {
                    self_batt_level.store(*level, std::sync::atomic::Ordering::Relaxed);
                    self_batt_charging.store(*charging, std::sync::atomic::Ordering::Relaxed);
                }
                // FluxMesh: only `GhostTimeout`/`PeerSeen` (FS-046 swap) ever
                // consult the secondary-peer set (see `App::other_linked_peers`),
                // so only refresh it for those — avoids an extra transport lock
                // on every other event. `App` stays sync/transport-free; this is
                // its one source of truth for "are other peers still linked".
                if matches!(event, Event::GhostTimeout | Event::PeerSeen { .. }) {
                    app.set_other_linked_peers(
                        transport.secondary_liveness().await.into_iter().map(|(id, _)| id),
                    );
                }
                let actions = app.handle(event.clone(), &*wall_clock);
                if !actions.is_empty() {
                    tracing::debug!(?event, ?actions, phase=?app.snapshot().phase, "FSM transition");
                }
                // FIX1 (P0 parked-payload leak): the silent-secondary-timeout
                // path (`heartbeat_loop`) has no direct access to `app` or
                // `outbox_stage`, so it routes its `Event::PeerRevoked`
                // through `event_tx` instead of calling `app.handle`
                // inline like `CmdOp::Revoke` does. Purge here too so both
                // producers of that event converge on the same cleanup.
                purge_dropped_pending_from_outbox_stage(&actions, &outbox_stage).await;
                // FIX3: a security trigger (untrusted-peer, ghost-timeout,
                // peer-swap — the only events reaching this arm that bump
                // `vault_wipe_gen`; `CmdOp::ClearHistory` also bumps it but is
                // handled entirely in `handle_driver_cmd`, never here, so it
                // can't misfire this block) just cleared `App`'s in-memory
                // history synchronously inside `app.handle` above. Mirror
                // that to disk and purge the outbox HERE — before `dispatch`
                // below runs `Action::EmitState` and publishes the new state
                // to subscribers — so a crash right after this point leaves
                // disk wiped (safe) rather than memory wiped with the
                // secret still recoverable from disk or re-offered via
                // resync. The persister's own gen-check stays as
                // belt-and-braces (see `persist_history_change`).
                sync_security_wipe_if_needed(
                    &app,
                    &mut last_wipe_gen_sync,
                    &outbox,
                    &outbox_stage,
                    &inflight,
                    keystore_dir.as_ref(),
                )
                .await;
                // Bug #9: the silent-secondary-timeout path is the other
                // producer of `Event::PeerRevoked` (see
                // `purge_dropped_pending_from_outbox_stage`'s doc comment) —
                // mirror its inflight purge here too, or a revoked-by-timeout
                // peer keeps getting retransmits.
                if let Event::PeerRevoked { peer_id } = &event {
                    purge_peer_from_inflight(*peer_id, &inflight).await;
                }
                dispatch(actions, &mut app, &transport, &trusted, keystore_dir.as_ref(), &state_watch_tx, &logs_bcast_tx, &log_tail, &last_written_hashes, &metrics, &inflight, &peer_meta, &outbox, &pending_pairs, &mut seq_store).await;
            }
            Some(driver_cmd) = cmd_rx.recv() => {
                match driver_cmd {
                    DriverCmd::PushImage { hash, png, preview } => {
                        use fluxsync_core::Clock;
                        let lamport = app.clock.tick();
                        let actions = app.handle(
                            Event::LocalClipboardChange {
                                hash,
                                kind: Kind::Image,
                                payload: png,
                                preview,
                                // DIR-P2-05 boundary: an image copied to the OS
                                // clipboard and picked up by this watcher (as
                                // opposed to an explicit `fluxctl push-image
                                // --sensitive` / mobile FFI push) is never
                                // marked sensitive — unlike text's
                                // `is_sensitive`, there is no image-content
                                // classifier, so a screenshotted secret is
                                // only protected when the caller explicitly
                                // flags it via the IPC push path.
                                sensitive: false,
                                lamport,
                            },
                            &*wall_clock,
                        );
                        let actions = gate_outbound(actions, &transport, &pending_pairs).await;
                        dispatch(actions, &mut app, &transport, &trusted, keystore_dir.as_ref(), &state_watch_tx, &logs_bcast_tx, &log_tail, &last_written_hashes, &metrics, &inflight, &peer_meta, &outbox, &pending_pairs, &mut seq_store).await;
                    }
                    run_cmd @ DriverCmd::Run { .. } => {
                        handle_driver_cmd(
                            run_cmd,
                            &mut app,
                            &wall_clock,
                            &identity,
                            &trusted,
                            &pairing_window,
                            &transport,
                            &pending_initiator_tx,
                            &event_tx,
                            &state_watch_tx,
                            &logs_bcast_tx,
                            &log_tail,
                            &last_written_hashes,
                            keystore_dir.as_ref(),
                            &udp_bind,
                            udp_port,
                            &metrics,
                            &inflight,
                            &peer_meta,
                            &pending_pairs,
                            &pin_advert,
                            &disc_cache,
                            &backoff,
                            &mdns_ctx,
                            &shutdown,
                            &outbox,
                            &outbox_stage,
                            &mut seq_store,
                            &deferred_sas_confirm,
                            &cleared_tombstone,
                        ).await;
                    }
                }
                // `CmdOp::ClearHistory` (handled inside `handle_driver_cmd`,
                // above) also bumps `vault_wipe_gen` — it is a user-requested
                // "clear history" action with its own already-correct,
                // SELECTIVE outbox purge (`outbox.remove_many` on exactly the
                // cleared hashes), not a security wipe, and must NOT also
                // trigger `sync_security_wipe_if_needed`'s blanket
                // `clear_all`. `App`'s `vault_wipe_gen` is one shared counter
                // across both `tokio::select!` arms, though, so without this
                // resync the event-loop arm's NEXT event (an unrelated
                // battery tick, say) would see the gen it didn't itself bump
                // and wipe the outbox anyway as collateral damage. Re-sync
                // the tracked baseline to whatever `app` holds now so only a
                // bump made BY the event-loop arm's own `app.handle` (the
                // real security triggers) is ever observed as "new".
                last_wipe_gen_sync = app.snapshot().vault_wipe_gen;
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Internal request from an IPC handler to the driver.
enum DriverCmd {
    Run {
        op: CmdOp,
        reply: oneshot::Sender<CmdResponse>,
        req_id: u64,
    },
    /// Image copied to the local OS clipboard, forwarded by the clipboard
    /// watcher. Carries the PNG-encoded payload, the RGBA-derived dedup
    /// hash, and the history label. No IPC reply — fire-and-forget.
    PushImage {
        hash: [u8; 32],
        png: Vec<u8>,
        preview: String,
    },
}

// ─────────────────────────────────────────────────────────────────
// Action dispatch
// ─────────────────────────────────────────────────────────────────

/// M-DAEMON-01 / H-DAEMON-01: strip outbound `SendItem` actions when the
/// active peer landed via TOFU but has not been verbally confirmed (SAS) yet.
/// Mirrors the inbound FS-052 gate in `dispatch_inbound_frame`, so clipboard
/// never flows in *either* direction to an unconfirmed peer during the pairing
/// window. Non-clipboard actions (state/log/battery) pass through untouched and
/// local history is unaffected — only the wire send is held back.
async fn gate_outbound(
    actions: Vec<Action>,
    transport: &Arc<Transport>,
    pending_pairs: &PendingSet,
) -> Vec<Action> {
    let pending = match transport.cached_peer_id().await {
        Some(id) => pending_pairs.lock().await.contains_key(&id),
        None => false,
    };
    if !pending {
        return actions;
    }
    actions
        .into_iter()
        .filter(|a| {
            if matches!(a, Action::SendItem { .. }) {
                tracing::warn!(
                    "FS-052 gate: suppressing outbound clipboard — peer not yet verbally confirmed"
                );
                false
            } else {
                true
            }
        })
        .collect()
}

/// FIX3 (synchronous security-wipe disk clear): if `app`'s `vault_wipe_gen`
/// has advanced past `*last_wipe_gen` since the last call, synchronously
/// clear the resync outbox — both the real `SharedOutbox` and its
/// `Ask`-staged entries (FIX2) — and the on-disk vault, AWAITING both
/// before returning. Returns whether a wipe actually ran.
///
/// Callers MUST run this after `app.handle` but before the resulting
/// `Action`s are `dispatch`ed — `dispatch`'s `Action::EmitState` is what
/// publishes the new state to IPC/watch subscribers, and this must finish
/// first so nobody can observe "history cleared" while the outbox or
/// `history.enc` still hold the wiped secret. See the call site in `run()`'s
/// main event loop.
///
/// Factored out of that loop (rather than left inline) so it is
/// independently unit-testable — see the tests below — the same rationale
/// `persist_history_change` is its own function for.
async fn sync_security_wipe_if_needed(
    app: &App,
    last_wipe_gen: &mut u64,
    outbox: &SharedOutbox,
    outbox_stage: &PendingOutboxStage,
    inflight: &InflightMap,
    keystore_dir: Option<&PathBuf>,
) -> bool {
    let gen_now = app.snapshot().vault_wipe_gen;
    if gen_now == *last_wipe_gen {
        return false;
    }
    *last_wipe_gen = gen_now;
    outbox.lock().await.clear_all();
    outbox_stage.lock().await.clear();
    // Bug #9: a sensitive item's outbound frames are tracked in `inflight`
    // regardless of sensitivity (only the `outbox` insert is sensitive-
    // gated), so without this a wiped item's plaintext frames survive the
    // wipe in RAM and keep retransmitting to its targets.
    inflight.lock().await.clear();
    // L1 fix: a security wipe must also purge any inbound image bytes
    // stashed in `IMAGE_CACHE` (`WriteClipboard`'s image handler, every
    // platform) — a process-wide store with no other trigger to clear it,
    // so a wiped peer's approved-but-not-yet-fetched image could otherwise
    // still be pulled via `CmdOp::FetchItem` after the rest of the vault is
    // gone.
    if let Ok(mut g) = image_cache().lock() {
        g.clear();
    }
    if let Some(dir) = keystore_dir {
        let dir = dir.clone();
        match tokio::task::spawn_blocking(move || history_store::clear(&dir)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(
                error = %e,
                "synchronous security-wipe disk clear failed; persister will retry"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "synchronous security-wipe disk clear task join failed"
            ),
        }
    }
    true
}

/// FIX1 (P0 parked-payload leak): scan `actions` for the `Action::
/// PendingDropped` signal `App::handle` emits when `Event::PeerRevoked`
/// drops a peer's parked `Ask` items (`App::drop_pending_for`), and purge
/// the matching `PendingOutboxStage` entries too — otherwise a revoked
/// peer's staged (not-yet-admitted-to-history) outbox entry has no other
/// trigger to clear it once the `state.pending` row it mirrored is gone,
/// and leaks in the stage map forever. Idempotent: removing an
/// already-absent hash is a no-op. Called at both places `Event::
/// PeerRevoked` can be produced: `CmdOp::Revoke` (direct `app.handle` call)
/// and `run()`'s main event loop (the silent-secondary-timeout path in
/// `heartbeat_loop` only has an `event_tx`, so it routes through there).
async fn purge_dropped_pending_from_outbox_stage(
    actions: &[Action],
    outbox_stage: &PendingOutboxStage,
) {
    let mut stage = outbox_stage.lock().await;
    for action in actions {
        if let Action::PendingDropped { hashes } = action {
            for hash in hashes {
                stage.remove(hash);
            }
        }
    }
}

/// Bug #9 (inflight survives revoke): drop `peer_id` from every
/// `Inflight.pending_peers` — otherwise the retransmit timer keeps firing at
/// a permanently-revoked peer, and if that peer id later re-TOFU-joins
/// within `INFLIGHT_MAX_AGE` the stale retransmit delivers straight into its
/// new, unconfirmed session (a second FS-052 bypass). An entry whose
/// `pending_peers` becomes empty is dropped outright rather than left to
/// expire on its own. Called at every place a peer is permanently torn
/// down: `CmdOp::Revoke`, `CmdOp::PairConfirm{accept: false}` (mirrors
/// Revoke), and the silent-secondary-timeout `Event::PeerRevoked` path in
/// `run()`'s main loop.
async fn purge_peer_from_inflight(peer_id: [u8; 32], inflight: &InflightMap) {
    inflight
        .lock()
        .await
        .retain(|_, inf| {
            inf.pending_peers.remove(&peer_id);
            !inf.pending_peers.is_empty()
        });
}

#[allow(clippy::too_many_arguments, clippy::cast_possible_truncation)]
async fn dispatch(
    actions: Vec<Action>,
    app: &mut App,
    transport: &Arc<Transport>,
    _trusted: &TrustedSet,
    _keystore_dir: Option<&std::path::PathBuf>,
    state_watch_tx: &watch::Sender<State>,
    logs_bcast_tx: &broadcast::Sender<LogEntry>,
    log_tail: &Arc<LogTail>,
    last_written_hashes: &Arc<Mutex<VecDeque<[u8; 32]>>>,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
    peer_meta: &PeerMetaMap,
    outbox: &SharedOutbox,
    pending_pairs: &PendingSet,
    seq_store: &mut Option<SeqStore>,
) {
    for action in actions {
        tracing::debug!(?action, "dispatching action");
        match action {
            Action::EmitState => {
                let m = metrics.lock().await.snapshot();
                app.set_metrics(Some(m));
                // FluxMesh Phase 3: enrich the single-peer snapshot with the
                // live mesh peer list before publishing.
                let mut snap = app.snapshot().clone();
                let primary = transport.cached_peer_id().await;
                snap.peers = build_peers(transport, peer_meta, primary).await;
                let _ = state_watch_tx.send(snap);
            }
            Action::EmitLog(entry) => {
                tracing::info!(level = ?entry.level, msg = %entry.msg, "log");
                log_tail.push(entry.clone());
                let _ = logs_bcast_tx.send(entry);
            }
            Action::SendItem {
                hash,
                kind,
                payload,
                sensitive,
            } => {
                use fluxsync_core::Clock;

                if payload.len() > MAX_PAYLOAD {
                    // Unreachable backstop: every producer caps upstream now —
                    // the watcher (text + image), CmdOp::Push (text), and
                    // CmdOp::PushImage (image) all reject over-cap payloads
                    // before they reach here. Fail closed if one ever slips
                    // through anyway: drop the item rather than truncate (a
                    // truncated PNG/text blob is corrupt, and sending it
                    // would silently desync the peer). `debug_assert!` turns
                    // this into a hard test failure if an upstream cap is
                    // ever removed or bypassed.
                    tracing::error!(
                        size = payload.len(),
                        cap = MAX_PAYLOAD,
                        "BUG: over-cap payload reached SendItem; dropping item (an upstream cap was bypassed)"
                    );
                    debug_assert!(
                        false,
                        "over-cap payload ({} bytes > {MAX_PAYLOAD} cap) reached Action::SendItem",
                        payload.len()
                    );
                    continue;
                }

                // FluxMesh: stamp this item with its origin device + a
                // per-origin sequence so the mesh dedups/anti-loops on
                // identity rather than content hash. Allocated once per
                // item; the chunked header carries the same EventId.
                let event_id = app.next_local_event_id();
                let origin = event_id.origin.into_bytes();
                let event_seq = event_id.seq;

                // Persist the reserve-ahead horizon past this seq (cheap
                // no-op unless the counter just reached it) so a restart
                // never re-issues a seq a peer's SeenSet has already
                // recorded. See `seq_store.rs`.
                if let Some(store) = seq_store.as_mut() {
                    if let Err(e) = store.advance(event_seq + 1) {
                        tracing::warn!(
                            error = %e,
                            "seq_store: failed to persist advanced outgoing-seq horizon"
                        );
                    }
                }

                // Build every datagram for this item up front, encoded. The
                // same bytes are kept in the inflight table so the retransmit
                // timer can re-send them verbatim until acked.
                let frames = build_item_frames(
                    app.clock.now(),
                    hash,
                    kind,
                    &payload,
                    sensitive,
                    origin,
                    event_seq,
                );

                if frames.is_empty() {
                    tracing::error!("SendItem: nothing to send (encode failed)");
                } else {
                    // FluxMesh 2C-b: fan the item out to every linked peer.
                    let targets = transport.linked_peer_ids().await;
                    if targets.is_empty() {
                        // DEFECT 3 fix: an item copied while fully unlinked
                        // must never enter the outbox. The resync-1 promise is
                        // narrow — recover items whose DELIVERY was actually
                        // attempted but went unacked when the link dropped —
                        // not "resurface anything ever copied offline" (that
                        // was a privacy leak: an old private copy from hours
                        // earlier, made with no peer connected, would flush to
                        // whichever peer links next). Gating on a non-empty
                        // `targets` here, computed BEFORE the outbox write,
                        // is what proves delivery was attempted. Compare the
                        // receive-side inserts (`complete_reassembled_item`,
                        // the non-chunked first-sight path): those are
                        // inherently fine, since receiving/relaying a frame at
                        // all requires an active linked session with the peer
                        // that sent it.
                        tracing::warn!("SendItem: no linked peers; nothing to send");
                    } else {
                        // Resync-on-reconnect (resync-1): keep a resend copy so
                        // a *different* peer that reconnects later can be
                        // offered this item too. Sensitive items must never
                        // enter the outbox (see `crate::outbox`'s security
                        // invariant). Deliberately inside the `targets`
                        // non-empty branch — see the DEFECT 3 note above.
                        if !sensitive {
                            outbox.lock().await.insert(
                                hash,
                                OutboxEntry {
                                    payload: payload.clone(),
                                    kind,
                                    origin,
                                    seq: event_seq,
                                    created: Instant::now(),
                                },
                            );
                        }
                        // FS-052 gate (egress hole fix): `gate_outbound` above
                        // only suppresses this SendItem entirely when the
                        // PRIMARY peer is pending — a pending SECONDARY mesh
                        // peer still shows up in `targets` and must not get
                        // plaintext clipboard before its human verbally
                        // confirms the SAS words. Filter it out of the actual
                        // wire fan-out (and out of who we await an ack from)
                        // here, per-target.
                        let send_targets: Vec<[u8; 32]> = {
                            let pending = pending_pairs.lock().await;
                            targets
                                .iter()
                                .copied()
                                .filter(|p| !pending.contains_key(p))
                                .collect()
                        };
                        if send_targets.len() != targets.len() {
                            tracing::debug!(
                                suppressed = targets.len() - send_targets.len(),
                                "FS-052 gate: suppressing SendItem to unconfirmed pending peer(s)"
                            );
                        }
                        tracing::info!(
                            peers = send_targets.len(),
                            frames = frames.len(),
                            "SendItem: fanning item out to linked peers"
                        );
                        // DIR-P1-09: counts logical items handed to the
                        // transport, not wire frames — a chunked image is
                        // still one `items_sent`.
                        metrics.lock().await.on_item_sent();
                        let multi = frames.len() > 1;
                        for peer in &send_targets {
                            for (i, bytes) in frames.iter().enumerate() {
                                if let Err(e) = transport.send_encrypted_to(*peer, bytes).await {
                                    tracing::error!(error = %e, "SendItem: send_encrypted_to FAILED");
                                }
                                // Pace multi-frame (chunked) items to avoid UDP
                                // congestion. A flat 10 ms per chunk would cost
                                // ~163 s for a 16 MiB image (16384 chunks); burst
                                // 16 frames then pause 2 ms instead (~2 s total).
                                if multi && (i + 1) % 16 == 0 {
                                    tokio::time::sleep(Duration::from_millis(2)).await;
                                }
                            }
                        }
                        // Retransmit until every targeted peer acks this hash.
                        // Without this a single dropped datagram loses the item —
                        // UDP gives no delivery guarantee. Skipped if every
                        // target was pending-gated above: nobody is awaiting
                        // an ack, so no `Inflight` entry is needed.
                        if !send_targets.is_empty() {
                            // Inflight merge fix: same rationale as
                            // `forward_frames` — a blind `insert` here would
                            // replace an entry a concurrent mesh relay of
                            // this exact hash already created, dropping its
                            // pending peers. Merge instead.
                            match inflight.lock().await.entry(hash) {
                                std::collections::hash_map::Entry::Occupied(mut e) => {
                                    let inf = e.get_mut();
                                    inf.pending_peers.extend(send_targets);
                                    inf.frames = frames;
                                    inf.last_sent = Instant::now();
                                }
                                std::collections::hash_map::Entry::Vacant(v) => {
                                    v.insert(Inflight {
                                        frames,
                                        attempts: 0,
                                        last_sent: Instant::now(),
                                        first_sent: Instant::now(),
                                        pending_peers: send_targets.into_iter().collect(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Action::AckItem { hash } => {
                // FluxMesh 2C-b: acks are sent by the recv loop straight to the
                // source peer (the only place the source peer_id is known), so
                // the FSM-emitted AckItem is a no-op here. Kept as a variant so
                // the core FSM contract stays unchanged.
                let _ = hash;
            }
            Action::DuplicateDropped => {
                // DIR-P1-09: content-hash dedup suppressed this event (an
                // echo of our own local copy, or a peer retransmit already
                // applied). See `App::handle`'s `suppress_action` branches.
                metrics.lock().await.on_dedup_drop();
            }
            Action::ResyncApplySuppressed => {
                // resync-1 apply-suppression fix (DEFECT 1): a ResyncPull
                // response's WriteClipboard was dropped by `App::handle`.
                // History/vault/relay/ack already happened normally.
                metrics.lock().await.on_resync_apply_suppressed();
            }
            // FIX1: already handled by the caller BEFORE this `actions` vec
            // reached `dispatch` — see
            // `purge_dropped_pending_from_outbox_stage`'s call sites. It has
            // to run before `Action::EmitState` below publishes the new
            // (pending-item-shrunk) state, so it can't wait until this loop
            // reaches it here.
            #[allow(clippy::match_same_arms)] // empty body, but for an unrelated reason than the arm below
            Action::PendingDropped { .. } => {}
            Action::WriteClipboard { kind, payload, sensitive } => {
                // DIR-P1-09: this is the "item apply" chokepoint — a
                // logical inbound item accepted and written to the local
                // OS clipboard, regardless of text/image kind.
                metrics.lock().await.on_item_received();
                // Mark the hash before writing so the watcher's next
                // poll skips this exact payload — otherwise we'd read
                // back our own write, fire a LocalClipboardChange, and
                // ping-pong the same item back to the peer. The hash is
                // taken over the clipboard's *canonical* form (trimmed
                // UTF-8 for text, RGBA pixels for images) so it matches
                // what the watcher computes on read-back — a re-encoded
                // PNG would hash differently.
                if matches!(kind, Kind::Image) {
                    #[cfg(not(target_os = "android"))]
                    if let Some((w, h, rgba)) = decode_png_to_rgba(&payload) {
                        let hash = image_rgba_hash(w, h, &rgba);
                        {
                            let mut g = last_written_hashes.lock().await;
                            g.push_back(hash);
                            if g.len() > 10 {
                                g.pop_front();
                            }
                        }
                        // DIR-P3-02(b): stash the bytes under their hex hash so
                        // the tray's `fetch_item` IPC op (history thumbnails +
                        // image re-copy) can serve them on demand — the same
                        // bounded `IMAGE_CACHE` Android already relies on for
                        // its own `fetch_item` path. Mirrors the Android branch
                        // below: a sensitive image is never cached.
                        if sensitive {
                            tracing::debug!(
                                "WriteClipboard: sensitive image — skipping IMAGE_CACHE"
                            );
                        } else {
                            cache_image(hex::encode(hash), payload.clone());
                        }
                        tokio::task::spawn_blocking(move || match arboard::Clipboard::new() {
                            Ok(mut cb) => {
                                let img = arboard::ImageData {
                                    width: w as usize,
                                    height: h as usize,
                                    bytes: std::borrow::Cow::Owned(rgba),
                                };
                                if let Err(e) = cb.set_image(img) {
                                    tracing::warn!(error = %e, "clipboard set_image failed");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "clipboard init failed");
                            }
                        });
                    } else {
                        tracing::warn!("WriteClipboard: PNG decode failed");
                    }
                    #[cfg(target_os = "android")]
                    {
                        // Android can't put raw bytes on the OS
                        // clipboard, so the daemon stashes the PNG under
                        // its hex hash; the client pulls it via the
                        // `fetch_item` IPC op once the matching history
                        // row appears. The hash is recomputed off the
                        // decoded RGBA so it matches `HistoryItem::hash`
                        // (sender-side `image_rgba_hash`, stable across
                        // the PNG round-trip).
                        //
                        // L1 fix: a `sensitive` image is never cached — the
                        // whole point of firewall/history sensitivity is
                        // that the bytes never linger in memory past the
                        // immediate apply, and `IMAGE_CACHE` is a
                        // process-wide store that survives a security wipe
                        // otherwise (it has its own explicit clear now, but
                        // "never write it" is strictly stronger). The
                        // client-side MainActivity still receives the
                        // decoded bytes for the immediate OS-clipboard
                        // paste via its own path; only the persistent,
                        // re-fetchable cache is skipped here.
                        if sensitive {
                            tracing::debug!(
                                "WriteClipboard(android): sensitive image — skipping IMAGE_CACHE"
                            );
                        } else if let Some((w, h, rgba)) = decode_png_to_rgba(&payload) {
                            let hash = image_rgba_hash(w, h, &rgba);
                            cache_image(hex::encode(hash), payload);
                        } else {
                            tracing::warn!("WriteClipboard(android): PNG decode failed");
                        }
                    }
                } else {
                    let text = String::from_utf8_lossy(&payload).to_string();
                    let hash = clipboard_dedup_hash(&text);
                    {
                        let mut g = last_written_hashes.lock().await;
                        g.push_back(hash);
                        if g.len() > 10 {
                            g.pop_front();
                        }
                    }
                    #[cfg(not(target_os = "android"))]
                    tokio::task::spawn_blocking(move || match arboard::Clipboard::new() {
                        Ok(mut cb) => {
                            if let Err(e) = cb.set_text(text) {
                                tracing::warn!(error = %e, "clipboard set_text failed");
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "clipboard init failed"),
                    });
                    #[cfg(target_os = "android")]
                    {
                        // Android writes the OS clipboard from
                        // `MainActivity`; the daemon just records the
                        // hash for dedup symmetry with desktop.
                        let _ = text;
                    }
                }
            }
            Action::OpenSession => {
                // Both sides fire OpenSession on the Handshaking → Linked
                // transition. Take advantage of that to swap friendly
                // names: the Noise handshake only carries static pubkeys,
                // so without this the responder shows the TOFU placeholder
                // ("New Peer") instead of the peer's real device name.
                let name = app.config().peer_name_self.clone();
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Hello(fluxsync_proto::Hello {
                        name,
                        platform: self_platform().to_string(),
                        caps: SUPPORTED_CAPS.iter().map(|c| (*c).to_string()).collect(),
                    }),
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    if let Err(e) = transport.send_encrypted(&bytes).await {
                        tracing::warn!(error = %e, "send hello failed");
                    }
                }
            }
            Action::CloseSession => {
                // [FIX] Handshake Ghosting: inform peer before dropping session
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Bye,
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted(&bytes).await;
                }
                transport.drop_session().await;
            }
            Action::SendBattery { level, charging } => {
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::BatteryStatus(fluxsync_proto::BatteryStatus {
                        lamport: 0,
                        level,
                        charging,
                    }),
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted(&bytes).await;
                }
            }
            Action::DropPeer => {
                // [FIX] Handshake Ghosting: inform peer before dropping session
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Bye,
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted(&bytes).await;
                }

                // M-DAEMON-18: DropPeer tears down the live SESSION only — it
                // must NEVER wipe the trust store. GhostTimeout (peer offline
                // 10 min) reaches here and would otherwise erase every paired
                // device. Intentional unpair/revoke removes the specific peer
                // from `trusted` at its own call site (IPC Unpair, Revoke,
                // PairConfirm-reject) *before* dispatching the FSM actions.
                tracing::info!("DropPeer: dropping live session (trust store untouched)");
                transport.drop_session().await;
            }
            Action::SendHandshake { .. } => {
                metrics.lock().await.on_handshake_start();
            }
            Action::StartDiscovery | Action::StopDiscovery | Action::BurstReplay => {
                // FSM-emitted but driven by discovery / pair-accept paths
                // directly in v0.1.1. v0.1.2 may wire these explicitly.
            }
        }
    }
}

/// Bump the FSM out of `Idle` if it's still there. Pairing operations
/// call this so that when the responder fires `HandshakeOk`, the FSM is
/// already in `Discovering`/`Handshaking` and the
/// `(Handshaking → Linked)` transition can fire — without it,
/// `(Idle, HandshakeOk)` is a no-op (see `fsm.rs::transition`) and the
/// Noise tunnel comes up but the FSM never reaches the `Linked` phase
/// where clipboard SendItem/WriteClipboard actions are emitted.
#[allow(clippy::too_many_arguments)]
async fn ensure_online(
    app: &mut App,
    wall: &Arc<dyn WallClock + Send + Sync>,
    transport: &Arc<Transport>,
    trusted: &TrustedSet,
    keystore_dir: Option<&std::path::PathBuf>,
    state_watch_tx: &watch::Sender<State>,
    logs_bcast_tx: &broadcast::Sender<LogEntry>,
    log_tail: &Arc<LogTail>,
    last_written_hashes: &Arc<Mutex<VecDeque<[u8; 32]>>>,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
    peer_meta: &PeerMetaMap,
    outbox: &SharedOutbox,
    pending_pairs: &PendingSet,
    seq_store: &mut Option<SeqStore>,
) {
    if app.snapshot().on {
        return;
    }
    let actions = app.handle(Event::ToggleOn, &**wall);
    dispatch(
        actions,
        app,
        transport,
        trusted,
        keystore_dir,
        state_watch_tx,
        logs_bcast_tx,
        log_tail,
        last_written_hashes,
        metrics,
        inflight,
        peer_meta,
        outbox,
        pending_pairs,
        seq_store,
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────
// IPC command dispatch
// ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_driver_cmd(
    cmd: DriverCmd,
    app: &mut App,
    wall: &Arc<dyn WallClock + Send + Sync>,
    identity: &Identity,
    trusted: &TrustedSet,
    pairing_window: &PairingWindow,
    transport: &Arc<Transport>,
    pending_initiator_tx: &Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: &mpsc::Sender<Event>,
    state_watch_tx: &watch::Sender<State>,
    logs_bcast_tx: &broadcast::Sender<LogEntry>,
    log_tail: &Arc<LogTail>,
    last_written_hashes: &Arc<Mutex<VecDeque<[u8; 32]>>>,
    keystore_dir: Option<&std::path::PathBuf>,
    udp_bind: &str,
    udp_port: u16,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
    peer_meta: &PeerMetaMap,
    pending_pairs: &PendingSet,
    pin_advert: &PinAdvertisement,
    disc_cache: &DiscoveryCache,
    backoff: &BackoffMap,
    mdns_ctx: &MdnsCtx,
    shutdown: &CancellationToken,
    outbox: &SharedOutbox,
    outbox_stage: &PendingOutboxStage,
    seq_store: &mut Option<SeqStore>,
    deferred_sas_confirm: &DeferredSasConfirm,
    cleared_tombstone: &ClearedTombstone,
) {
    let DriverCmd::Run { op, reply, req_id } = cmd else {
        return;
    };
    let resp = match op {
        CmdOp::Status => {
            let m = metrics.lock().await.snapshot();
            app.set_metrics(Some(m));
            // FluxMesh Phase 3: enrich with the live mesh peer list, same as
            // the watch-published snapshot (a direct Status poll bypasses it).
            let mut snap = app.snapshot().clone();
            let primary = transport.cached_peer_id().await;
            snap.peers = build_peers(transport, peer_meta, primary).await;
            CmdResponse::ok(req_id, Some(CmdData::State(Box::new(snap))))
        }
        CmdOp::Reconnect {} => {
            tracing::info!("IPC: manual reconnect requested");
            // Capture the primary's peer_id BEFORE dropping the session —
            // `drop_session` clears the session but not `last_peer_id`, so
            // this is really just for clarity/ordering symmetry with the
            // other teardown paths (heartbeat timeout, Bye, Revoke).
            let peer_id = transport.cached_peer_id().await;
            transport.drop_session().await;
            if let Some(peer_id) = peer_id {
                let _ = event_tx.try_send(Event::PeerLost { peer_id });
            }
            CmdResponse::ok(req_id, Some(CmdData::Pong))
        }
        CmdOp::SetFavorite { hash, favorite } => {
            tracing::info!(%hash, favorite, "IPC: set-favorite");
            let actions = app.handle(Event::SetFavorite { hash, favorite }, &**wall);
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::ClearHistory { include_favorites } => {
            tracing::info!(include_favorites, "IPC: clear-history");
            // Snapshot the hashes about to be dropped BEFORE mutating state,
            // so the outbox/image-cache purge below matches exactly what
            // leaves `State.history`.
            let cleared_hex: Vec<String> = app
                .snapshot()
                .history
                .iter()
                .filter(|h| include_favorites || !h.favorite)
                .map(|h| h.hash.clone())
                .collect();
            let cleared_bytes: Vec<[u8; 32]> =
                cleared_hex.iter().filter_map(|h| decode_hex32(h).ok()).collect();
            // Purge the resync outbox first: a cleared item must not come
            // back into history via a later pull/resync.
            outbox.lock().await.remove_many(&cleared_bytes);
            // H2 fix: also tombstone the cleared hashes so a PEER that still
            // holds one in its own outbox (ClearHistory is local-only, never
            // propagated) can't resurrect it via its next ResyncOffer.
            mark_cleared(cleared_tombstone, &cleared_bytes).await;
            purge_cached_images(&cleared_hex);
            let actions = app.handle(Event::ClearHistory { include_favorites }, &**wall);
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::SetFirewall { policy } => {
            tracing::info!(enabled = policy.enabled, "IPC: set-firewall");
            app.set_firewall(policy);
            // Persist so the policy survives a daemon restart (best-effort: a
            // write failure logs but never fails the command).
            if let Some(dir) = keystore_dir {
                if let Err(e) = crate::keystore::save_firewall(dir, app.firewall()) {
                    tracing::warn!(error = %e, "failed to persist firewall policy");
                }
            }
            // Push the updated policy to every state subscriber.
            dispatch(
                vec![Action::EmitState],
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::ResolvePending { hash, allow } => {
            tracing::info!(%hash, allow, "IPC: resolve-pending");
            let actions = app.handle(Event::ResolvePending { hash: hash.clone(), allow }, &**wall);
            // Outbox admission gate fix: a staged inbound item (see
            // `PendingOutboxStage`) is only admitted now if `App::handle`
            // actually re-emitted its held `WriteClipboard` — not merely
            // because the caller passed `allow: true`. A denied item, an
            // unknown/already-resolved hash, or an OUTBOUND approval
            // (`SendItem` instead) must never promote anything, and either
            // way the staged entry (if any) must not survive this call.
            let admitted_inbound =
                allow && actions.iter().any(|a| matches!(a, Action::WriteClipboard { .. }));
            if let Ok(bytes) = decode_hex32(&hash) {
                match outbox_stage.lock().await.remove(&bytes) {
                    Some(entry) if admitted_inbound => {
                        outbox.lock().await.insert(bytes, entry);
                    }
                    _ => {}
                }
            }
            // An approved OUTBOUND item re-emits SendItem; route it through the
            // same SAS gate as a normal push so an unconfirmed peer can't be fed
            // the held secret.
            let actions = gate_outbound(actions, transport, pending_pairs).await;
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Push { text } => {
            use fluxsync_core::Clock;
            tracing::info!(len = text.len(), "IPC: push requested from local");
            let text = text.trim().to_string();
            if text.len() > MAX_PAYLOAD {
                // Reject early so the caller learns the paste was too big,
                // instead of dispatch silently truncating the bytes mid-wire
                // (the receiver would otherwise get a corrupted partial item).
                CmdResponse::err(
                    req_id,
                    format!(
                        "clipboard text too large: {} bytes (max {} bytes)",
                        text.len(),
                        MAX_PAYLOAD
                    ),
                )
            } else if !text.is_empty() {
                let kind = kind_of(&text);
                let sensitive = fluxsync_core::is_sensitive(&text);
                // Canon hash so CRLF/LF copies dedup (see clipboard_dedup_hash).
                let hash = clipboard_dedup_hash(&text);
                let lamport = app.clock.tick();
                let actions = app.handle(
                    Event::LocalClipboardChange {
                        hash,
                        kind,
                        payload: text.as_bytes().to_vec(),
                        preview: text,
                        sensitive,
                        lamport,
                    },
                    &**wall,
                );
                tracing::debug!(?actions, "LocalClipboardChange results");
                let actions = gate_outbound(actions, transport, pending_pairs).await;
                dispatch(
                    actions,
                    app,
                    transport,
                    trusted,
                    keystore_dir,
                    state_watch_tx,
                    logs_bcast_tx,
                    log_tail,
                    last_written_hashes,
                    metrics,
                    inflight,
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
                )
                .await;
                CmdResponse::ok(req_id, None)
            } else {
                CmdResponse::ok(req_id, None)
            }
        }
        CmdOp::PushImage { data, sensitive } => {
            use fluxsync_core::Clock;
            tracing::info!(
                b64_len = data.len(),
                sensitive,
                "IPC: push_image requested from local"
            );
            match B64.decode(data.as_bytes()) {
                Ok(png) if png.len() > MAX_PAYLOAD => CmdResponse::err(
                    req_id,
                    format!(
                        "push_image: image too large ({} bytes > {MAX_PAYLOAD} cap)",
                        png.len()
                    ),
                ),
                Ok(png) => match decode_png_to_rgba(&png) {
                    Some((w, h, rgba)) => {
                        let hash = image_rgba_hash(w, h, &rgba);
                        let preview = preview_label(Kind::Image, &png);
                        let lamport = app.clock.tick();
                        let actions = app.handle(
                            Event::LocalClipboardChange {
                                hash,
                                kind: Kind::Image,
                                payload: png,
                                preview,
                                // DIR-P2-05: the caller (fluxctl `--sensitive`,
                                // or the mobile FFI) decides — there is no
                                // image-content classifier, so this is the
                                // only place an image can be marked sensitive.
                                sensitive,
                                lamport,
                            },
                            &**wall,
                        );
                        let actions = gate_outbound(actions, transport, pending_pairs).await;
                        dispatch(
                            actions,
                            app,
                            transport,
                            trusted,
                            keystore_dir,
                            state_watch_tx,
                            logs_bcast_tx,
                            log_tail,
                            last_written_hashes,
                            metrics,
                            inflight,
                            peer_meta,
                            outbox,
                            pending_pairs,
                            seq_store,
                        )
                        .await;
                        CmdResponse::ok(req_id, None)
                    }
                    None => CmdResponse::err(req_id, "push_image: PNG decode failed"),
                },
                Err(e) => CmdResponse::err(req_id, format!("push_image: base64: {e}")),
            }
        }
        CmdOp::FetchItem { hash } => match lookup_cached_image(&hash) {
            Some(png) => CmdResponse::ok(
                req_id,
                Some(CmdData::ItemBytes {
                    bytes: B64.encode(&png),
                }),
            ),
            None => CmdResponse::err(req_id, "fetch_item: payload not cached"),
        },
        CmdOp::Pull => {
            let last = app.snapshot().history.first().cloned();
            CmdResponse::ok(req_id, Some(CmdData::Pull(last)))
        }
        CmdOp::Tail { n } => {
            let entries = log_tail.snapshot(n);
            CmdResponse::ok(req_id, Some(CmdData::Tail(entries)))
        }
        CmdOp::Peers => {
            let addr = transport.current_peer_addr().await;
            let peer = peer_entry(app.snapshot(), addr);
            CmdResponse::ok(req_id, Some(CmdData::Peers(peer.into_iter().collect())))
        }
        // H2: enumerate the persisted trust store. The `Peers` op above
        // only reflects the live session; this one reflects every entry
        // a malicious or unaware caller has managed to land in
        // `peers.json` via `pair from-uri` / `pair accept`. Render this
        // in the CLI so a silent extra-peer trust is immediately
        // visible to the user.
        CmdOp::TrustList {} => {
            let g = trusted.lock().await;
            let entries: Vec<crate::cmd::TrustedEntry> = g
                .iter()
                .map(|(pid, p)| crate::cmd::TrustedEntry {
                    peer_id_hex: hex::encode(pid),
                    static_pub_hex: hex::encode(p.static_pub),
                    name: p.name.clone(),
                })
                .collect();
            CmdResponse::ok(req_id, Some(CmdData::TrustList(entries)))
        }
        CmdOp::SetThreshold { value } => match app.state.set_threshold(value) {
            Ok(()) => {
                let actions = app.handle(
                    Event::BatteryChangedSelf {
                        level: app.snapshot().battery_level,
                        charging: app.snapshot().charging,
                    },
                    &**wall,
                );
                dispatch(
                    actions,
                    app,
                    transport,
                    trusted,
                    keystore_dir,
                    state_watch_tx,
                    logs_bcast_tx,
                    log_tail,
                    last_written_hashes,
                    metrics,
                    inflight,
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
                )
                .await;
                CmdResponse::ok(req_id, None)
            }
            Err(e) => CmdResponse::err(req_id, e.to_string()),
        },
        CmdOp::SetDeviceName { name } => match app.set_device_name(&name) {
            Ok(()) => {
                let resolved = app.config().peer_name_self.clone();
                tracing::info!(name = %resolved, "IPC: set-device-name");
                // Best-effort: a write failure logs but never fails the
                // command — the rename is already live in memory (and will
                // ship in the next `Msg::Hello`) even if the disk write
                // doesn't survive a restart.
                if let Some(dir) = keystore_dir {
                    if let Err(e) = crate::keystore::save_device_name(dir, &resolved) {
                        tracing::warn!(error = %e, "failed to persist device name");
                    }
                }
                dispatch(
                    vec![Action::EmitState],
                    app,
                    transport,
                    trusted,
                    keystore_dir,
                    state_watch_tx,
                    logs_bcast_tx,
                    log_tail,
                    last_written_hashes,
                    metrics,
                    inflight,
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
                )
                .await;
                CmdResponse::ok(req_id, None)
            }
            Err(e) => CmdResponse::err(req_id, e.to_string()),
        },
        CmdOp::SetChargeOverride { value } => {
            app.set_charge_override(value);
            // Re-evaluate status with current battery so the new
            // charge_override takes effect immediately (and the EmitState
            // it triggers pushes the updated value to subscribers).
            let actions = app.handle(
                Event::BatteryChangedSelf {
                    level: app.snapshot().battery_level,
                    charging: app.snapshot().charging,
                },
                &**wall,
            );
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        // M-TRAY-03: actually terminate. The tray's `restart_stale_daemon`
        // sends `shutdown` then waits for the socket to close before it
        // respawns the up-to-date binary; a no-op left the stale daemon
        // running forever. Cancelling the token breaks every loop; the ok
        // reply below still flushes (sent at the tail of this fn) before
        // `run()` returns and the process exits.
        CmdOp::Shutdown {} => {
            tracing::info!("Shutdown requested via IPC; cancelling daemon");
            shutdown.cancel();
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Unpair {} => {
            tracing::info!("Manual unpair requested via IPC");
            // Tell the live peer to drop us from its trust store, otherwise
            // it auto-reconnects through the next TOFU window and re-pairs
            // without a QR scan. Best-effort: if the session is down the
            // peer keeps a stale entry, which only it can clean up.
            let revoke = Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::Revoke,
            };
            if let Ok(bytes) = fluxsync_proto::encode(&revoke) {
                let _ = transport.send_encrypted(&bytes).await;
            }
            // VULN-001 variant V1: snapshot+retry+rollback. Without this,
            // a disk failure during unpair would clear live trust while
            // peers.json still trusts every peer; a daemon restart would
            // silently re-trust them.
            let snapshot = trusted.lock().await.clone();
            trusted.lock().await.clear();
            // DIR-P2-04a: the mDNS discovery cache holds every seen peer's
            // pubkey, name, addrs, and pairing PIN. Purge it unconditionally
            // on unpair — even if the disk persist below fails and trust is
            // rolled back, losing stale discovery data is harmless (mDNS
            // re-announces), never a regression from the pre-unpair state.
            disc_cache.lock().await.clear();
            // DIR-P1-02: same rationale — a stale backoff timer for a
            // now-untrusted peer must not survive to throttle a future
            // re-pair of that same peer-id.
            backoff.lock().await.clear();
            if let Some(dir) = keystore_dir {
                if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                    *trusted.lock().await = snapshot;
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; unpair rolled back, retry once disk recovers"
                        ),
                    );
                }
            }
            let actions = app.handle(Event::ManualUnpair, &**wall);
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Toggle { on } => {
            let ev = if on {
                Event::ToggleOn
            } else {
                Event::ToggleOff
            };
            let actions = app.handle(ev, &**wall);
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::SetSelfBattery { level, charging } => {
            let actions = app.handle(Event::BatteryChangedSelf { level, charging }, &**wall);
            dispatch(
                actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::Revoke { peer_id } => {
            let Ok(bytes) = hex::decode(&peer_id) else {
                return reply_err(reply, req_id, "bad hex peer_id");
            };
            let arr: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => return reply_err(reply, req_id, "expected 32-byte peer_id"),
            };
            // C1: surgical removal of a single peer. The previous flow
            // went through `Event::ManualUnpair` → `Action::DropPeer`
            // which `trusted.clear()`s the entire trust store, so
            // revoking one peer wiped every other paired device. We
            // now (a) remove only the target slot from the in-memory
            // set, (b) persist the new set under the disk lock, and
            // (c) tear down the live session **only if** the revoked
            // peer is the one currently linked. Other peers stay
            // trusted and reachable.
            //
            // VULN-001 variant V2 still applies: revoke must succeed on
            // disk before we acknowledge, otherwise a daemon restart
            // would re-trust the peer we just promised to drop.
            let removed_trusted = trusted.lock().await.remove(&arr);
            // DIR-P2-04a: purge this peer's mDNS discovery-cache entry
            // (pubkey, name, addrs, pairing PIN) so a revoked peer isn't
            // still resolvable via a stale cache hit (e.g. PairFromPin).
            disc_cache.lock().await.remove(&arr);
            // DIR-P1-02: same rationale — drop the revoked peer's backoff
            // timer too.
            backoff.lock().await.remove(&arr);
            if let Some(dir) = keystore_dir {
                if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                    if let Some(p) = removed_trusted {
                        trusted.lock().await.insert(arr, p);
                    }
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; revoke rolled back, retry once disk recovers"
                        ),
                    );
                }
            }
            // FluxMesh robustness slice 4: per-peer unpair must work for a
            // SECONDARY too. Signal the target so it drops us from its own
            // trust + tears down, then drop our side. `drop_session_for` keys
            // by peer, so a revoked secondary no longer stays linked and
            // syncing — the old code only tore down the primary, leaving a
            // revoked secondary live. Finally delist it from the mesh.
            if transport.has_session_for(arr).await {
                if let Ok(b) = fluxsync_proto::encode(&Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Revoke,
                }) {
                    let _ = transport.send_encrypted_to(arr, &b).await;
                }
            }
            // Bug #16 fix: a revoke is permanent — this peer can never
            // legitimately reconnect, so unlike the transient Bye/
            // ghost-timeout teardowns, nothing depends on the `extra` stub
            // surviving. `purge_peer` drops the session AND removes the
            // whole `PeerConn` entry so repeated pair/revoke churn can't
            // grow `extra` unboundedly.
            transport.purge_peer(arr).await;
            if peer_meta.lock().await.remove(&arr).is_some() {
                let _ = event_tx.try_send(Event::MeshPeersChanged);
            }
            // FIX1 (P0 parked-payload leak): drop this peer's Ask-parked
            // pending items (both directions) whether it was the primary or
            // a secondary — nobody is left to deliver an inbound item to,
            // or to receive an outbound one. Unlike `Event::PeerLost` (a
            // transient disconnect, which must NOT drop pending — see its
            // doc comment), a revoke is permanent, so this always runs,
            // independent of the primary-failover branch below.
            let mut revoke_actions = app.handle(Event::PeerRevoked { peer_id: arr }, &**wall);
            purge_dropped_pending_from_outbox_stage(&revoke_actions, outbox_stage).await;
            purge_peer_from_inflight(arr, inflight).await;
            // If the revoked peer was the primary, rebind State: fail over to a
            // live secondary if one exists, else walk Linked → Discovering
            // (CloseSession touches only the session, not the trust store).
            let active = app.snapshot().peer_id;
            if active == arr && !try_primary_failover(transport, event_tx, peer_meta).await {
                revoke_actions.extend(app.handle(Event::PeerLost { peer_id: arr }, &**wall));
            }
            dispatch(
                revoke_actions,
                app,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        // FS-052: list peers that landed in `trusted` under the TOFU
        // window but have not yet been verbally confirmed.
        CmdOp::PairPending {} => {
            let now = Instant::now();
            let entries: Vec<crate::cmd::PendingPairEntry> = {
                let mut g = pending_pairs.lock().await;
                // Expire stale entries before answering so callers never
                // see a pair the daemon would refuse to confirm anyway.
                g.retain(|_, p| p.expires_at > now);
                g.iter()
                    .map(|(peer_id, p)| crate::cmd::PendingPairEntry {
                        peer_id: hex::encode(peer_id),
                        name: p.name.clone(),
                        sas_words: p.sas_words.to_vec(),
                        addr: Some(p.from.to_string()),
                        expires_in_ms: Some(
                            p.expires_at
                                .saturating_duration_since(now)
                                .as_millis()
                                .min(u128::from(u64::MAX)) as u64,
                        ),
                    })
                    .collect()
            };
            CmdResponse::ok(req_id, Some(CmdData::PendingPairs(entries)))
        }

        // FS-052: resolve a pending pair. Accept = drop from the pending
        // map (peer keeps its trusted slot). Reject = revoke, same path
        // as `CmdOp::Revoke`, so an attacker that raced into the trusted
        // set is purged from `peers.json` and the live session is torn
        // down.
        CmdOp::PairConfirm { peer_id, accept } => {
            let Ok(bytes) = hex::decode(&peer_id) else {
                return reply_err(reply, req_id, "bad hex peer_id");
            };
            let arr: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => return reply_err(reply, req_id, "expected 32-byte peer_id"),
            };
            let removed_pending = pending_pairs.lock().await.remove(&arr);
            if removed_pending.is_none() {
                return reply_err(reply, req_id, "no pending pair with that peer_id");
            }
            if accept {
                // FS-052 wire mutual confirm: tell the peer our human said
                // yes — but only if we know it understands `Msg::PairConfirm`.
                // Caps unknown (Hello not arrived yet) → defer the send to
                // the `Msg::Hello` handler; known-legacy → nothing to send,
                // and the peer counts as confirmed (the Hello handler
                // already fired `SasPeerConfirmed` when its caps arrived).
                let (hello_seen, supports_sas) = {
                    let meta = peer_meta.lock().await;
                    meta.get(&arr).map_or((false, false), |m| {
                        (m.hello_seen, m.caps.iter().any(|c| c == "sas-confirm"))
                    })
                };
                if hello_seen {
                    if supports_sas {
                        let frame = Frame {
                            version: PROTOCOL_VERSION,
                            msg: Msg::PairConfirm(fluxsync_proto::PairConfirm { accept: true }),
                        };
                        if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                            if let Err(e) = transport.send_encrypted_to(arr, &bytes).await {
                                tracing::warn!(
                                    peer = ?&arr[..6],
                                    error = %e,
                                    "sas-confirm: PairConfirm(accept) send failed"
                                );
                            }
                        }
                    } else {
                        // Legacy peer: defensively count it as confirmed in
                        // case its Hello landed before the pending insert and
                        // the Hello handler's legacy path never fired.
                        let actions =
                            app.handle(Event::SasPeerConfirmed { peer_id: arr }, &**wall);
                        dispatch(
                            actions,
                            app,
                            transport,
                            trusted,
                            keystore_dir,
                            state_watch_tx,
                            logs_bcast_tx,
                            log_tail,
                            last_written_hashes,
                            metrics,
                            inflight,
                            peer_meta,
                            outbox,
                            pending_pairs,
                            seq_store,
                        )
                        .await;
                    }
                } else {
                    deferred_sas_confirm.lock().await.insert(arr);
                }
                let actions = app.handle(Event::SasLocalConfirmed { peer_id: arr }, &**wall);
                dispatch(
                    actions,
                    app,
                    transport,
                    trusted,
                    keystore_dir,
                    state_watch_tx,
                    logs_bcast_tx,
                    log_tail,
                    last_written_hashes,
                    metrics,
                    inflight,
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
                )
                .await;
            } else {
                // FS-052 wire mutual confirm: best-effort tell the peer our
                // human said NO while the session is still alive — the
                // peer-scoped teardown below sends Bye and drops it. A
                // legacy peer fails to decode the unknown variant and just
                // logs a warn; the Bye that follows still cleans it up.
                deferred_sas_confirm.lock().await.remove(&arr);
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::PairConfirm(fluxsync_proto::PairConfirm { accept: false }),
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted_to(arr, &bytes).await;
                }
                let removed_trusted = trusted.lock().await.remove(&arr);
                // DIR-P2-04a: same rationale as `CmdOp::Revoke` — per the
                // comment above, this rejection IS a revoke, so purge the
                // peer's discovery-cache entry too.
                disc_cache.lock().await.remove(&arr);
                // DIR-P1-02: same rationale — purge its backoff timer too.
                backoff.lock().await.remove(&arr);
                if let Some(dir) = keystore_dir {
                    if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                        // VULN-001 fix: roll back the in-memory removal
                        // so on-disk and in-memory state stay consistent.
                        // Otherwise a restart would re-trust the peer we
                        // just told the user we revoked.
                        if let Some(p) = removed_trusted {
                            trusted.lock().await.insert(arr, p);
                        }
                        if let Some(p) = removed_pending {
                            pending_pairs.lock().await.insert(arr, p);
                        }
                        return reply_err(
                            reply,
                            req_id,
                            &format!(
                                "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; reject rolled back, retry once disk recovers"
                            ),
                        );
                    }
                }
                // Peer-scoped teardown, mirroring `CmdOp::Revoke`: the
                // previous flow fired `Event::ManualUnpair`, whose FSM
                // actions (`CloseSession`/`DropPeer`) are unit/primary-only
                // (`send_encrypted` + `drop_session`, both hit `self.conn`).
                // Rejecting a SECONDARY's SAS was therefore sending Bye to
                // the PRIMARY and tearing down the primary's healthy
                // session, while the rejected secondary — which only ever
                // received the `PairConfirm{accept:false}` sent above, never
                // a session drop — stayed fully linked.
                if transport.has_session_for(arr).await {
                    if let Ok(b) = fluxsync_proto::encode(&Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::Bye,
                    }) {
                        let _ = transport.send_encrypted_to(arr, &b).await;
                    }
                }
                // Bug #16 fix: a local reject revokes trust permanently,
                // same rationale as `CmdOp::Revoke` — purge the `extra`
                // stub too instead of leaving it to leak.
                transport.purge_peer(arr).await;
                if peer_meta.lock().await.remove(&arr).is_some() {
                    let _ = event_tx.try_send(Event::MeshPeersChanged);
                }
                let mut reject_actions = app.handle(Event::PeerRevoked { peer_id: arr }, &**wall);
                purge_dropped_pending_from_outbox_stage(&reject_actions, outbox_stage).await;
                purge_peer_from_inflight(arr, inflight).await;
                // If the rejected peer was the primary, rebind State the
                // same way `CmdOp::Revoke` does: fail over to a live
                // secondary if one exists, else walk Linked → Discovering.
                let active = app.snapshot().peer_id;
                if active == arr && !try_primary_failover(transport, event_tx, peer_meta).await {
                    reject_actions.extend(app.handle(Event::PeerLost { peer_id: arr }, &**wall));
                }
                dispatch(
                    reject_actions,
                    app,
                    transport,
                    trusted,
                    keystore_dir,
                    state_watch_tx,
                    logs_bcast_tx,
                    log_tail,
                    last_written_hashes,
                    metrics,
                    inflight,
                    peer_meta,
                    outbox,
                    pending_pairs,
                    seq_store,
                )
                .await;
            }
            CmdResponse::ok(req_id, None)
        }

        CmdOp::PairShow {} => {
            // Re-pairing while already paired is allowed: FS-052 gates any
            // peer that TOFU-joins through this window behind the SAS verify
            // (pending entry + reaper revoke), so an attacker handshaking in
            // is no better off than during a first pair. Without this, a
            // device whose peer was reset or unreachable for a long time
            // could never re-pair (the old `already_paired` refusal).
            let static_pub = identity.public_key();
            let peer_id = identity.peer_id();
            let pubkey_b32 = base32::encode(BASE32_ALPHA, &static_pub);
            let words = fingerprint(&static_pub);
            let words_vec: Vec<String> = words.iter().map(|s| (*s).to_string()).collect();
            let addr_hint = local_lan_addr(udp_bind, udp_port);
            // Optional Tailscale path: if this host has a tailnet address,
            // fold it into the SAME uri (`a=lan,tailnet`) so a single QR
            // works on the LAN and across a tailnet — the initiator tries
            // each hint in order. Pure routing probe, no Tailscale
            // dependency — see tailnet_local_addr.
            let tailnet_addr_hint = tailnet_local_addr(udp_port);
            let addr_hints = match &tailnet_addr_hint {
                Some(t) => format!("{addr_hint},{t}"),
                None => addr_hint.clone(),
            };
            let uri = build_pair_uri(&pubkey_b32, &addr_hints, &words_vec);
            // Open the TOFU window so the peer that scans this QR is
            // accepted on first handshake even though we don't know its
            // pubkey yet. Kept short (see `handshake::PAIRING_WINDOW`) so
            // a stale QR or a drive-by LAN handshake can't be exploited.
            *pairing_window.lock().await = Some(Instant::now() + handshake::PAIRING_WINDOW);
            tracing::info!("pairing window opened (90s)");
            // PR2: generate a fresh PIN, advertise it on mDNS, and
            // spawn a rotation watchdog if one is not already running.
            // The watchdog regenerates the PIN every PAIRING_WINDOW
            // while the trusted set is still empty, then clears the
            // TXT when the user pairs or the window times out.
            let pin = gen_pair_pin();
            let expires_at = Instant::now() + handshake::PAIRING_WINDOW;
            let was_active = pin_advert
                .lock()
                .await
                .replace(PinAd {
                    pin: pin.clone(),
                    expires_at,
                })
                .is_some();
            if let Some(ctx) = mdns_ctx.lock().await.as_ref() {
                if let Err(e) = discovery::republish_with_pin(
                    &ctx.daemon,
                    &ctx.instance_name,
                    &ctx.peer_id_hex,
                    &ctx.static_pub_hex,
                    ctx.bind_ip,
                    ctx.udp_port,
                    Some(&pin),
                ) {
                    tracing::warn!(error = %e, "mDNS republish_with_pin failed");
                }
            }
            if !was_active {
                spawn_pin_watchdog(pin_advert.clone(), mdns_ctx.clone(), pairing_window.clone());
            }
            // Showing the QR is implicit "I want to sync" — bump the
            // FSM out of Idle so when the responder fires HandshakeOk
            // the (Handshaking → Linked) transition can fire. Without
            // this, (Idle, HandshakeOk) is a no-op and clipboard sync
            // stays dead even though the Noise tunnel is up.
            ensure_online(
                app,
                wall,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            // PR2: surface the PIN + epoch-ms expiry to the UI so the
            // pair window can render the 6-digit code + countdown.
            let pin_expires_at_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis() as u64 + handshake::PAIRING_WINDOW.as_millis() as u64);
            CmdResponse::ok(
                req_id,
                Some(CmdData::PairInfo {
                    peer_id_hex: hex::encode(peer_id),
                    pubkey_b32,
                    fingerprint_words: words_vec,
                    addr_hint,
                    uri,
                    pin: Some(pin),
                    pin_expires_at_ms,
                    tailnet_addr_hint,
                }),
            )
        }
        CmdOp::PairFromUri { uri, name } => {
            let parsed = match parse_pair_uri(&uri) {
                Ok(p) => p,
                Err(e) => return reply_err(reply, req_id, &format!("bad pair uri: {e}")),
            };
            let Some(bytes) = base32::decode(BASE32_ALPHA, &parsed.pubkey_b32) else {
                return reply_err(reply, req_id, "bad base32 pubkey in uri");
            };
            let static_pub: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => return reply_err(reply, req_id, "expected 32-byte pubkey"),
            };
            // H1: reject all-zero + known low-order Curve25519 points
            // before they reach `trusted`. A degenerate pubkey would
            // pin Noise IK to predictable DH output; rejecting here is
            // cheaper than a SAS-time failure and avoids ever writing
            // such an entry to disk.
            if let Err(e) = fluxsync_crypto::validate_peer_pubkey(&static_pub) {
                return reply_err(reply, req_id, &format!("bad pubkey in uri: {e}"));
            }
            let peer_id = handshake::peer_id_for(&static_pub);
            // H3: cap the trust store so an attacker that lures the user
            // into repeated `pair from-uri` runs cannot indefinitely
            // grow peers.json. 64 distinct devices is well past any
            // realistic personal/family setup; raise via config later if
            // a real fleet use case shows up. The check is "len before
            // insert" so re-pairing the same peer (same peer_id) stays
            // legal — `upsert` just refreshes the existing slot.
            {
                let g = trusted.lock().await;
                if !g.contains_key(&peer_id) && g.len() >= MAX_PERSISTED_PEERS {
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "trust store full ({MAX_PERSISTED_PEERS} peers); revoke an existing peer first"
                        ),
                    );
                }
            }
            // Same reconnect-not-fresh-pair rule as PairAccept/PairFromPin:
            // rescanning an already-trusted peer's QR (no fresh pending pair
            // in flight for it) is a silent reconnect, not a re-verification.
            // Without this, re-scanning a known peer engaged the SAS gate on
            // the scanning side only — the responder's already-trusted branch
            // (handshake.rs) never inserts a pending entry or fires
            // `SasPairingStarted`, so the scanner's `PairConfirm` would land
            // on the responder's silent-ignore branch and the scanner would
            // stick at `sas_phase = "local_confirmed"` until the 90s pending
            // reaper fired `SasReset` AND revoked the peer's trust. A genuine
            // fresh pair (peer not yet trusted, or a still-open pending from
            // an in-progress verification) still engages the gate below.
            let already_confirmed = trusted.lock().await.contains_key(&peer_id)
                && !pending_pairs.lock().await.contains_key(&peer_id);
            trusted.lock().await.insert(
                peer_id,
                TrustedPeer {
                    static_pub,
                    name: name.clone(),
                },
            );

            // Persist the new peer to disk immediately.
            // VULN-001 variant V3: if disk write fails, in-mem trust would
            // silently vanish on next restart. Roll back the insert and
            // surface the failure so the user knows the pairing is not
            // durable. F-001/F-002 hardening: upsert under the
            // `peers_disk_lock` so a concurrent reaper revoke cannot race
            // against the load, and propagate parse errors instead of
            // silently overwriting a corrupt `peers.json`.
            if let Some(dir) = keystore_dir {
                if let Err(e) = upsert_peer_persist(
                    dir,
                    transport,
                    crate::keystore::StoredPeer {
                        peer_id_hex: hex::encode(peer_id),
                        static_pub_hex: hex::encode(static_pub),
                        name: name.clone(),
                        last_addr: None,
                    },
                )
                .await
                {
                    trusted.lock().await.remove(&peer_id);
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; pair rolled back, retry once disk recovers"
                        ),
                    );
                }
            }

            // Scanning a peer's QR is implicit "I want to sync". Bump
            // the FSM into Discovering before we send msg1 so the
            // (Handshaking → Linked) chain can fire when msg2 arrives.
            ensure_online(
                app,
                wall,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            // URI carries one or more address hints; if any parsed, kick
            // off the initiator immediately (it tries each in order, LAN
            // before tailnet). If none, the trust has been recorded and
            // discovery (or a later pair-accept --addr) can drive it.
            if parsed.addrs.is_empty() {
                tracing::warn!("pair uri carried no usable addr; deferring to discovery");
            } else {
                start_initiator(
                    identity.clone(),
                    static_pub,
                    parsed.addrs,
                    peer_id,
                    name,
                    transport.clone(),
                    pending_initiator_tx.clone(),
                    event_tx.clone(),
                    // None on an already-trusted, not-pending peer → silent
                    // reconnect, same as PairAccept/PairFromPin. Otherwise
                    // Some so the SAS gate engages and the initiator's verify
                    // screen gets its 6 words.
                    if already_confirmed {
                        None
                    } else {
                        Some(pending_pairs.clone())
                    },
                    backoff.clone(),
                    trusted.clone(),
                    keystore_dir.cloned(),
                )
                .await;
            }
            CmdResponse::ok(
                req_id,
                Some(CmdData::PairResult { already_paired: already_confirmed }),
            )
        }
        CmdOp::PairAccept {
            pubkey_b32,
            name,
            addr,
        } => {
            let Some(bytes) = base32::decode(BASE32_ALPHA, &pubkey_b32) else {
                return reply_err(reply, req_id, "bad base32 pubkey");
            };
            let static_pub: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => return reply_err(reply, req_id, "expected 32-byte pubkey"),
            };
            // H1: same validation as PairFromUri. PairAccept is the
            // manual `--addr` path; just as scriptable, just as risky.
            if let Err(e) = fluxsync_crypto::validate_peer_pubkey(&static_pub) {
                return reply_err(reply, req_id, &format!("bad pubkey: {e}"));
            }
            let peer_id = handshake::peer_id_for(&static_pub);
            // H3: trust-store cap. Same rationale as PairFromUri.
            {
                let g = trusted.lock().await;
                if !g.contains_key(&peer_id) && g.len() >= MAX_PERSISTED_PEERS {
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "trust store full ({MAX_PERSISTED_PEERS} peers); revoke an existing peer first"
                        ),
                    );
                }
            }
            // Same reconnect-not-fresh-pair rule as PairFromUri.
            let already_confirmed = trusted.lock().await.contains_key(&peer_id)
                && !pending_pairs.lock().await.contains_key(&peer_id);
            trusted.lock().await.insert(
                peer_id,
                TrustedPeer {
                    static_pub,
                    name: name.clone(),
                },
            );

            // Persist the new peer to disk immediately.
            // VULN-001 variant V4: same shape as PairFromUri — rollback
            // in-mem insert + reply_err on persist failure so the caller
            // knows the trust is not durable. F-001/F-002 hardening: see
            // PairFromUri above for the lock + parse-error rationale.
            if let Some(dir) = keystore_dir {
                if let Err(e) = upsert_peer_persist(
                    dir,
                    transport,
                    crate::keystore::StoredPeer {
                        peer_id_hex: hex::encode(peer_id),
                        static_pub_hex: hex::encode(static_pub),
                        name: name.clone(),
                        last_addr: None,
                    },
                )
                .await
                {
                    trusted.lock().await.remove(&peer_id);
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; pair rolled back, retry once disk recovers"
                        ),
                    );
                }
            }

            // Same intent as PairFromUri: caller wants the link live.
            ensure_online(
                app,
                wall,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;

            // If addr supplied, kick off the initiator immediately
            // (skips mDNS discovery — useful for tests + for first-pair).
            if let Some(addr_str) = addr {
                match addr_str.parse::<SocketAddr>() {
                    Ok(parsed) => {
                        start_initiator(
                            identity.clone(),
                            static_pub,
                            vec![parsed],
                            peer_id,
                            name,
                            transport.clone(),
                            pending_initiator_tx.clone(),
                            event_tx.clone(),
                            if already_confirmed {
                                None
                            } else {
                                Some(pending_pairs.clone())
                            },
                            backoff.clone(),
                            trusted.clone(),
                            keystore_dir.cloned(),
                        )
                        .await;
                    }
                    Err(_) => return reply_err(reply, req_id, "bad addr"),
                }
            }
            CmdResponse::ok(req_id, None)
        }
        // PR2: PIN-method pair. Look up the discovery cache for a
        // peer whose mDNS `pair_pin` TXT matches, then take the same
        // path as `PairFromUri`: trust + persist + start_initiator.
        // The UI is expected to follow up with `PairPending` +
        // `PairConfirm` for verify-words gating — without that the
        // pair lands in `pending_pairs` and the reaper revokes it
        // after `PAIRING_WINDOW`.
        CmdOp::PairFromPin { pin, name } => {
            if pin.len() != 6 || !pin.bytes().all(|b| b.is_ascii_digit()) {
                return reply_err(reply, req_id, "bad pin format (6 digits)");
            }
            let target = {
                let cache = disc_cache.lock().await;
                let now = Instant::now();
                cache
                    .values()
                    .filter(|e| now.duration_since(e.last_seen) < DISCOVERY_CACHE_TTL)
                    .find(|e| e.pair_pin.as_deref() == Some(pin.as_str()))
                    .cloned()
            };
            let Some(target) = target else {
                return reply_err(reply, req_id, "no_peer_with_pin");
            };
            let static_pub = target.static_pub;
            // H1: even the PIN-method path needs to validate the
            // discovered peer's static pubkey. mDNS is unauthenticated;
            // an attacker controlling the LAN could advertise a
            // degenerate pubkey on a guessed PIN.
            if let Err(e) = fluxsync_crypto::validate_peer_pubkey(&static_pub) {
                return reply_err(reply, req_id, &format!("bad pubkey from discovery: {e}"));
            }
            let peer_id = handshake::peer_id_for(&static_pub);
            // H3: trust-store cap.
            {
                let g = trusted.lock().await;
                if !g.contains_key(&peer_id) && g.len() >= MAX_PERSISTED_PEERS {
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "trust store full ({MAX_PERSISTED_PEERS} peers); revoke an existing peer first"
                        ),
                    );
                }
            }
            // Same reconnect-not-fresh-pair rule as PairFromUri.
            let already_confirmed = trusted.lock().await.contains_key(&peer_id)
                && !pending_pairs.lock().await.contains_key(&peer_id);
            trusted.lock().await.insert(
                peer_id,
                TrustedPeer {
                    static_pub,
                    name: name.clone(),
                },
            );
            // Mirror PairFromUri's persist-or-rollback (VULN-001 V3 /
            // F-001 hardening). PIN-method pair has identical durability
            // requirements: on disk failure, drop the in-mem trust.
            if let Some(dir) = keystore_dir {
                if let Err(e) = upsert_peer_persist(
                    dir,
                    transport,
                    crate::keystore::StoredPeer {
                        peer_id_hex: hex::encode(peer_id),
                        static_pub_hex: hex::encode(static_pub),
                        name: name.clone(),
                        last_addr: None,
                    },
                )
                .await
                {
                    trusted.lock().await.remove(&peer_id);
                    return reply_err(
                        reply,
                        req_id,
                        &format!(
                            "persist failed after {PEERS_PERSIST_ATTEMPTS} attempts: {e}; pair rolled back, retry once disk recovers"
                        ),
                    );
                }
            }
            ensure_online(
                app,
                wall,
                transport,
                trusted,
                keystore_dir,
                state_watch_tx,
                logs_bcast_tx,
                log_tail,
                last_written_hashes,
                metrics,
                inflight,
                peer_meta,
                outbox,
                pending_pairs,
                seq_store,
            )
            .await;
            start_initiator(
                identity.clone(),
                static_pub,
                vec![target.addr],
                peer_id,
                name,
                transport.clone(),
                pending_initiator_tx.clone(),
                event_tx.clone(),
                if already_confirmed {
                    None
                } else {
                    Some(pending_pairs.clone())
                },
                backoff.clone(),
                trusted.clone(),
                keystore_dir.cloned(),
            )
            .await;
            CmdResponse::ok(
                req_id,
                Some(CmdData::PairResult { already_paired: already_confirmed }),
            )
        }
    };
    let _ = reply.send(resp);
}

fn reply_err(reply: oneshot::Sender<CmdResponse>, id: u64, msg: &str) {
    let _ = reply.send(CmdResponse::err(id, msg));
}

fn peer_entry(state: &State, addr: Option<SocketAddr>) -> Option<PeerEntry> {
    if state.peer_name.is_empty() {
        return None;
    }
    Some(PeerEntry {
        peer_id: String::from("paired"),
        name: state.peer_name.clone(),
        addr: addr.map(|a| a.to_string()).unwrap_or_default(),
        link_latency_ms: state.link_latency_ms,
        battery: state.peer_battery,
        charging: state.peer_charging,
        linked: state.status != fluxsync_core::Status::Inactive,
    })
}

// ─────────────────────────────────────────────────────────────────
// Transport receive loop — type-byte dispatch
// ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn transport_recv_loop(
    transport: Arc<Transport>,
    identity: Identity,
    trusted: TrustedSet,
    pairing_window: PairingWindow,
    pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: mpsc::Sender<Event>,
    shutdown: CancellationToken,
    keystore_dir: Option<PathBuf>,
    metrics: Arc<Mutex<MetricsTracker>>,
    inflight: InflightMap,
    pending_pairs: PendingSet,
    mesh_seen: MeshSeen,
    peer_meta: PeerMetaMap,
    disc_cache: DiscoveryCache,
    backoff: BackoffMap,
    lan_only_handshakes: bool,
    outbox: SharedOutbox,
    pending_pulls: PendingPulls,
    outbox_stage: PendingOutboxStage,
    state_rx: watch::Receiver<State>,
    deferred_sas_confirm: DeferredSasConfirm,
    echo_ack_sent: EchoAckSent,
    cleared_tombstone: ClearedTombstone,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // FS-058: per-source-IP handshake limiter. Local-mutable; recv loop is
    // single-task so no Arc<Mutex<>> needed.
    let mut handshake_limiter = HandshakeRateLimiter::new();
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(5));
    let mut retransmit_interval = tokio::time::interval(RETRANSMIT_INTERVAL);
    let mut nak_interval = tokio::time::interval(NAK_INTERVAL);
    // M-DAEMON-17: last peer address we persisted to peers.json. Used to
    // persist a roam ONLY when the address actually changes — otherwise every
    // encrypted frame (heartbeat each 5 s + every clipboard item) would
    // tmp+fsync+rename peers.json continuously, burning disk/SSD for nothing.
    let mut last_persisted_addr: Option<std::net::SocketAddr> = None;

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = retransmit_interval.tick() => {
                // Re-send any clipboard item a peer hasn't acked yet, to the
                // peers still pending. Frames whose item exceeds MAX_RETRANSMIT
                // are dropped.
                let mut to_send: Vec<([u8; 32], Vec<u8>)> = Vec::new();
                {
                    let mut map = inflight.lock().await;
                    let mut done: Vec<[u8; 32]> = Vec::new();
                    for (hash, item) in map.iter_mut() {
                        // Age backstop first: NAK resends keep `last_sent`
                        // fresh, so the `continue` below would otherwise
                        // shield a never-converging item from ever being
                        // dropped.
                        if item.first_sent.elapsed() > INFLIGHT_MAX_AGE {
                            tracing::warn!(
                                item = ?&hash[..6],
                                "item dropped: exceeded max age (transfer never converged)"
                            );
                            done.push(*hash);
                            continue;
                        }
                        if item.last_sent.elapsed() < RETRANSMIT_INTERVAL {
                            continue;
                        }
                        if item.attempts >= MAX_RETRANSMIT {
                            tracing::warn!(
                                item = ?&hash[..6],
                                "item dropped: peer never acked after max retransmits"
                            );
                            done.push(*hash);
                            continue;
                        }
                        item.attempts += 1;
                        item.last_sent = Instant::now();
                        tracing::debug!(
                            item = ?&hash[..6],
                            attempt = item.attempts,
                            pending = item.pending_peers.len(),
                            "retransmitting unacked item"
                        );
                        for peer in &item.pending_peers {
                            for f in &item.frames {
                                to_send.push((*peer, f.clone()));
                            }
                        }
                    }
                    for h in done {
                        map.remove(&h);
                    }
                }
                for (peer, bytes) in &to_send {
                    let _ = transport.send_encrypted_to(*peer, bytes).await;
                }
            }
            _ = nak_interval.tick() => {
                // Selective NAK: for every chunked transfer still in
                // reassembly, tell the ACTUAL SENDER (`Reassembly::source`,
                // never assumed to be the primary link) exactly which chunk
                // indices (and the header) are still missing so it resends
                // only those — whole-item retransmit can't converge under
                // steady UDP loss.
                let pending = {
                    let map = reassembly.lock().await;
                    build_pending_naks(&map)
                };
                for (source, nak) in pending {
                    let frame = Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::Nak(nak),
                    };
                    if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                        let _ = transport.send_encrypted_to(source, &bytes).await;
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                let mut map = reassembly.lock().await;
                map.retain(|hash, r| {
                    let total_age = r.first_seen.elapsed();
                    let idle_age = r.last_update.elapsed();
                    let keep = total_age < Duration::from_secs(60) && idle_age < Duration::from_secs(5);
                    if !keep {
                        tracing::warn!(
                            item = ?&hash[..6],
                            chunks = ?r.chunks.iter().filter(|x| x.is_some()).count(),
                            total = ?r.chunks.len(),
                            "Reassembly timeout: dropping incomplete item (data loss due to packet loss)"
                        );
                    }
                    keep
                });
            }
            res = transport.recv(&mut buf) => {
                let frame = match res {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(error = %e, "transport recv error");
                        continue;
                    }
                };
                // H2 (Phase 3 audit): uniform `lan_only` filter applied
                // to EVERY frame, not just `HandshakeInit`. The UDP
                // socket binds 0.0.0.0 by default so multi-NIC users
                // get LAN reachability without configuration, but that
                // also exposes the Noise / replay-window state to WAN
                // probes. We drop non-local sources here, before any
                // decrypt or Noise step touches them.
                if lan_only_handshakes && !crate::config::is_local_ip(frame.from().ip()) {
                    tracing::warn!(
                        src = %frame.from(),
                        kind = frame.kind_label(),
                        "frame dropped: non-local source (lan_only)"
                    );
                    continue;
                }
                match frame {
                    RecvFrame::HandshakeInit { from, msg } => {
                        // FS-059: refuse handshakes from public-internet
                        // sources by default. LAN clipboard sync has no
                        // legitimate WAN peer; a routable IP here is
                        // almost certainly a scanner.
                        // (The blanket LAN filter above already covers
                        // this; the explicit check is retained as a
                        // defense-in-depth assertion in case someone
                        // later moves the filter or flips its scope.)
                        if lan_only_handshakes && !crate::config::is_local_ip(from.ip()) {
                            tracing::warn!(
                                src = %from,
                                "HandshakeInit dropped: non-local source"
                            );
                            continue;
                        }
                        // FS-058: per-source-IP rate-limit. Drop excess
                        // HandshakeInit datagrams BEFORE spawning the
                        // responder so neither the Noise step nor the
                        // PendingSet/trusted map are exposed to the flood.
                        if !handshake_limiter.check(from.ip()) {
                            tracing::warn!(
                                src = %from,
                                "HandshakeInit dropped: source rate-limited"
                            );
                            continue;
                        }
                        // FluxMesh 2C-b: no global "session active → reject"
                        // gate any more — that blocked a SECOND device from
                        // ever pairing. Per-peer admission is enforced in the
                        // responder via `try_install_session`'s CAS: a
                        // re-handshake from the SAME peer (e.g. Android's ~15s
                        // mDNS rediscovery) finds that peer's session already
                        // present and is dropped without replacing it (the
                        // Noise session is never destroyed), while a DIFFERENT
                        // peer is routed to its own connection slot. The
                        // FS-058 per-source rate-limit above still bounds how
                        // often a responder is spawned.
                        let id = identity.clone();
                        let tr = transport.clone();
                        let trusted = trusted.clone();
                        let window = pairing_window.clone();
                        let evt = event_tx.clone();
                        let kd = keystore_dir.clone();
                        let pending = pending_pairs.clone();
                        let responder_metrics = metrics.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handshake::run_responder(id, msg, from, tr, trusted, window, evt, kd, pending).await {
                                tracing::warn!(error = %e, "responder failed");
                                // DIR-P1-09: counted here (not inside
                                // `handshake::run_responder`) because
                                // `MetricsTracker` lives in `fluxsyncd`, while
                                // `handshake` only returns an error type —
                                // keeps the metrics dependency at the one
                                // call site instead of threading it through
                                // every handshake helper.
                                responder_metrics.lock().await.on_handshake_fail();
                            }
                        });
                    }
                    RecvFrame::HandshakeResp { msg, .. } => {
                        let g = pending_initiator_tx.lock().await;
                        if let Some(tx) = g.as_ref() {
                            let _ = tx.send(msg);
                            // On a fast/loopback link the peer's post-handshake
                            // traffic (its own `Msg::Hello`, sent the instant
                            // ITS side reaches Linked) can already be sitting
                            // in this socket's recv buffer right behind this
                            // `HandshakeResp` datagram. Forwarding to
                            // `run_initiator` above only wakes that task; it
                            // does not run it. Without yielding here, this
                            // loop can read the very next datagram (that
                            // Hello) and fail it with "encrypted frame but no
                            // session" before `run_initiator` ever gets
                            // scheduled to call `try_install_session`. Since
                            // `Msg::Hello` is sent exactly once per session
                            // establishment (resync-1 caps ride on it, never
                            // retried), losing that race silently and
                            // permanently drops resync-1 negotiation for the
                            // whole session. A single cooperative yield here
                            // gives `run_initiator` a real chance to finish
                            // installing the session first.
                            tokio::task::yield_now().await;
                        } else {
                            tracing::debug!("HandshakeResp with no pending initiator");
                        }
                    }
                    RecvFrame::Encrypted { from, peer_id, plaintext } => {
                        // ROAMING persistence (M-DAEMON-17): only when the peer
                        // address actually changed since the last write — not on
                        // every frame. `peer_addr` updates on roam; comparing
                        // against `last_persisted_addr` collapses the steady-state
                        // heartbeat/clipboard stream to zero disk writes.
                        //
                        // last_addr persistence + redial: this is
                        // the "peer address change" surface the transport exposes
                        // — use the single-entry atomic upsert (`persist_last_addr`)
                        // so this peer's `last_addr` is updated in place. The
                        // previous implementation called `save_current_peers`
                        // here, which rebuilds every `StoredPeer` purely from the
                        // in-memory `TrustedPeer` (no address field) and so
                        // unconditionally wrote `last_addr: None` for every
                        // trusted peer on every roam — silently erasing the very
                        // redial hint this call site exists to persist.
                        if last_persisted_addr != Some(from) {
                            if let Some(dir) = &keystore_dir {
                                let current_p = transport.current_peer_addr().await;
                                if current_p == Some(from) {
                                    persist_last_addr(Some(dir), &transport, &trusted, peer_id, from)
                                        .await;
                                    last_persisted_addr = Some(from);
                                }
                            }
                        }

                        match fluxsync_proto::decode(&plaintext) {
                            Ok(f) => dispatch_inbound_frame(f, peer_id, &mesh_seen, &event_tx, &transport, &reassembly, &metrics, &inflight, &pending_pairs, &trusted, &disc_cache, &backoff, &peer_meta, keystore_dir.as_ref(), &outbox, &pending_pulls, &outbox_stage, &state_rx, &deferred_sas_confirm, &echo_ack_sent, &cleared_tombstone).await,
                            Err(e) => tracing::warn!(error = %e, "decode encrypted"),
                        }
                    }
                    RecvFrame::Other { type_byte, .. } => {
                        tracing::debug!(type_byte, "unknown wire type byte");
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Clipboard watcher (read side)
// ─────────────────────────────────────────────────────────────────

/// Dedup hash over the *trimmed* clipboard text, so the write side and
/// the watcher (which trims before hashing) agree — see FS-026.
fn clipboard_dedup_hash(text: &str) -> [u8; 32] {
    // CRLF-canonicalize (not just trim) so a Windows `\r\n` copy and a
    // Unix `\n` copy of the same text — or an app that LF-normalizes the
    // clipboard on read-back — dedup against each other instead of
    // ping-ponging. Mirrors the core's inbound hashing (app.rs).
    DedupRing::hash(fluxsync_core::canon_text(text).as_bytes()).into_bytes()
}

/// Build the history label for a clipboard payload. Text-like kinds show
/// the (lossy) UTF-8 text; images show a byte-size descriptor since their
/// payload is binary PNG.
fn preview_label(kind: Kind, payload: &[u8]) -> String {
    match kind {
        Kind::Image => format!("Image, {} KB", payload.len().div_ceil(1024)),
        _ => String::from_utf8_lossy(payload).to_string(),
    }
}

/// State the FluxVault persister carries between writes: where + how to
/// encrypt, plus a cache so a re-persist preserves each entry's original
/// `created_ms` (and favorite flag) instead of re-stamping it `now`.
struct VaultCtx {
    dir: PathBuf,
    key: zeroize::Zeroizing<[u8; 32]>,
    /// The history list as last persisted — change detection.
    last: Vec<HistoryItem>,
    /// The entries as last persisted — source of stable `created_ms`.
    entries: Vec<VaultEntry>,
}

impl VaultCtx {
    /// Map the current in-memory history (newest-first) to vault entries,
    /// carrying each entry's original `created_ms` forward (matched on the
    /// stable hash+lamport key, so toggling `favorite` doesn't reset its TTL)
    /// and stamping freshly-seen items with `now`. Favorited entries that
    /// scrolled out of the in-memory window are re-appended so they survive in
    /// the vault (favorites are exempt from the cap + TTL).
    fn rebuild(&self, history: &[HistoryItem], now: u64) -> Vec<VaultEntry> {
        let stable = |a: &HistoryItem, b: &HistoryItem| a.hash == b.hash && a.lamport == b.lamport;
        let mut out: Vec<VaultEntry> = history
            .iter()
            .map(|item| {
                let created_ms = self
                    .entries
                    .iter()
                    .find(|e| stable(&e.item, item))
                    .map_or(now, |prev| prev.created_ms);
                VaultEntry {
                    item: item.clone(),
                    created_ms,
                }
            })
            .collect();
        for e in &self.entries {
            if e.item.favorite && !history.iter().any(|h| stable(h, &e.item)) {
                out.push(e.clone());
            }
        }
        out
    }
}

/// One persist attempt: mirror a security wipe to disk if `wipe_gen`
/// advanced past `*last_wipe_gen`, then save `history` if it differs from
/// what's already persisted (`ctx.last`). Factored out of
/// `run_vault_persister` so the exact same logic can also run once more,
/// synchronously, during a graceful shutdown — see the final flush at the
/// end of that function.
async fn persist_history_change(
    ctx: &mut VaultCtx,
    last_wipe_gen: &mut u64,
    history: Vec<HistoryItem>,
    wipe_gen: u64,
    disc_cache: &DiscoveryCache,
    backoff: &BackoffMap,
) {
    // A security wipe (untrusted-peer, ghost-timeout, peer-swap) cleared
    // the in-memory history for safety; mirror it on disk. Delete the
    // encrypted vault and forget cached favorites so a pinned secret can't
    // be re-appended by rebuild() and the file can't outlive the wipe.
    //
    // FIX3: this is now belt-and-braces. The main event loop (see the
    // `vault_wipe_gen` before/after check around `Some(event) =
    // event_rx.recv()` in `run()`) already performs this exact disk clear
    // SYNCHRONOUSLY, inline, before the wiping event's new state is even
    // published to subscribers — this async path only re-runs the same
    // (idempotent) clear as a backstop. CORRECTION to a previous version of
    // this comment: a crash landing in the gap between the in-memory wipe
    // and either clear reaching disk is NOT auto-healed on the next boot —
    // boot only loads+restores whatever `history.enc` exists (see `run()`'s
    // vault rehydrate, well before `initial_wipe_gen` is even seeded) and
    // never re-wipes it, so a stray file from that gap survives until some
    // later, unrelated wipe trigger clears it. Residual, low-severity (the
    // user's own secret, on the user's own device), and now far less likely
    // to matter thanks to the synchronous path above.
    if wipe_gen != *last_wipe_gen {
        ctx.entries.clear();
        // DIR-P2-04a: a security wipe means this peer relationship is no
        // longer trusted; the mDNS discovery cache still holds its
        // pubkey, name, addrs, and pairing PIN from before the wipe.
        // Purge it too — eagerly, since an in-memory clear cannot fail,
        // rather than gating it on the disk clear below.
        disc_cache.lock().await.clear();
        // DIR-P1-02: same rationale — drop every peer's backoff timer.
        backoff.lock().await.clear();
        let dir = ctx.dir.clone();
        match tokio::task::spawn_blocking(move || history_store::clear(&dir)).await {
            // Only advance past this generation once the file is actually
            // gone; on failure keep last_wipe_gen so the next state publish
            // re-attempts the clear instead of permanently losing the wipe.
            Ok(Ok(())) => *last_wipe_gen = wipe_gen,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "vault security wipe failed; will retry on next change");
            }
            Err(e) => {
                tracing::warn!(error = %e, "vault security wipe task join failed; will retry on next change");
            }
        }
        // Force the post-wipe history (empty, or freshly-started for a
        // peer-swap) to be re-persisted below instead of short-circuiting.
        ctx.last = Vec::new();
    }
    if history == ctx.last {
        return;
    }
    let now = now_ms();
    let entries = ctx.rebuild(&history, now);
    let dir = ctx.dir.clone();
    let key = *ctx.key;
    let to_save = entries.clone();
    let saved = tokio::task::spawn_blocking(move || {
        history_store::save(
            &dir,
            &key,
            &to_save,
            now,
            history_store::DEFAULT_TTL_SECS,
            history_store::DEFAULT_DISK_CAP,
        )
    })
    .await;
    match saved {
        Ok(Ok(())) => {
            ctx.entries = entries;
            ctx.last = history;
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "vault persist failed"),
        Err(e) => tracing::warn!(error = %e, "vault persist task join failed"),
    }
}

/// Persist clipboard history whenever it changes. Wakes on every state
/// publish, skips when the history list is unchanged, and writes the
/// encrypted vault off-thread (`spawn_blocking`) so the fsync never stalls
/// a runtime worker.
///
/// DEFECT 2 fix (resync-1 "every launch" loop): this task used to be a bare
/// detached `tokio::spawn`, not tracked in `run()`'s `JoinSet`, so a
/// graceful shutdown could return — and the process could exit — before the
/// LAST history change (e.g. a resync-1 delivery landing right after Hello)
/// had actually reached disk. The next boot's vault load would then miss
/// that item, `missing_resync_hashes` would call it missing again, and the
/// daemon would re-`ResyncPull` it on every subsequent relaunch forever.
/// Now this task is spawned into the tracked `JoinSet` and also selects on
/// `shutdown`, so `run()`'s `while tasks.join_next().await.is_some() {}`
/// genuinely waits for the final flush below before the caller can exit.
async fn run_vault_persister(
    mut ctx: VaultCtx,
    mut rx: watch::Receiver<State>,
    initial_wipe_gen: u64,
    disc_cache: DiscoveryCache,
    backoff: BackoffMap,
    shutdown: CancellationToken,
) {
    // Baseline is seeded from the CONSTRUCTION snapshot, not a late
    // `rx.borrow()`: a security wipe that lands between `subscribe()` and the
    // first poll would otherwise be adopted as the baseline, so `rx.changed()`
    // would never observe it and the disk clear would be skipped while
    // ctx.entries still holds the favorite (which rebuild() would resurrect).
    let mut last_wipe_gen = initial_wipe_gen;
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            changed = rx.changed() => {
                if changed.is_err() {
                    // All senders dropped — the driver already tore down
                    // without going through the shutdown token (e.g. a test
                    // harness that just drops its `watch::Sender`). Nothing
                    // left to observe; exit exactly like the old `while
                    // rx.changed().await.is_ok()` loop did, with no extra
                    // final-flush attempt (there is no fresher state to read).
                    return;
                }
            }
        }
        let (history, wipe_gen) = {
            let snap = rx.borrow_and_update();
            (snap.history.clone(), snap.vault_wipe_gen)
        };
        persist_history_change(
            &mut ctx,
            &mut last_wipe_gen,
            history,
            wipe_gen,
            &disc_cache,
            &backoff,
        )
        .await;
    }
    // Final flush: `shutdown` fired. The daemon may have published one more
    // history change in the same instant as the cancellation, with no
    // guarantee this task's last loop iteration observed it before
    // `shutdown.cancelled()` won the `tokio::select!` race — `rx.changed()`
    // is edge-triggered, not level-triggered, so a change that arrives and
    // is immediately followed by cancellation can otherwise be lost. Read
    // the CURRENT state directly (`borrow`, not `changed`) and persist it if
    // it differs from what's already on disk.
    let (history, wipe_gen) = {
        let snap = rx.borrow();
        (snap.history.clone(), snap.vault_wipe_gen)
    };
    persist_history_change(
        &mut ctx,
        &mut last_wipe_gen,
        history,
        wipe_gen,
        &disc_cache,
        &backoff,
    )
    .await;
}

/// Dedup hash over an image's raw RGBA pixels (prefixed with its
/// dimensions). Hashing the decoded pixels — not the PNG bytes — keeps the
/// hash stable across a PNG encode/decode round-trip, so a write followed
/// by the watcher's read-back is recognised as our own and not echoed back
/// to the peer.
fn image_rgba_hash(width: u32, height: u32, rgba: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + rgba.len());
    buf.extend_from_slice(&width.to_le_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(rgba);
    DedupRing::hash(&buf).into_bytes()
}

/// Process-global cache of recently-received image payloads, keyed by hex
/// content hash. The daemon never puts binary in the state JSON; every
/// client pulls an inbound image's PNG bytes on demand via the `fetch_item`
/// IPC op, which reads this map (Android needs it to apply the bytes at all;
/// desktop uses it for tray history thumbnails + image re-copy, in addition
/// to writing straight to the OS clipboard). Bounded to the last few images
/// so a 16 MiB cap can't grow memory without limit.
type ImageCache = std::sync::Mutex<VecDeque<(String, Vec<u8>)>>;
static IMAGE_CACHE: std::sync::OnceLock<ImageCache> = std::sync::OnceLock::new();

/// Max image payloads retained in [`IMAGE_CACHE`]. 4 × 16 MiB worst case.
const IMAGE_CACHE_CAP: usize = 4;

fn image_cache() -> &'static ImageCache {
    IMAGE_CACHE.get_or_init(|| std::sync::Mutex::new(VecDeque::with_capacity(IMAGE_CACHE_CAP)))
}

/// Store an inbound image's PNG bytes under its hex hash. No-op if the
/// hash is already cached. Cross-platform: both Android (which has no other
/// way to apply the bytes) and desktop (tray thumbnails/re-copy via
/// `fetch_item`, alongside its direct OS-clipboard write) populate this.
fn cache_image(hash_hex: String, png: Vec<u8>) {
    if let Ok(mut g) = image_cache().lock() {
        if g.iter().any(|(h, _)| *h == hash_hex) {
            return;
        }
        g.push_back((hash_hex, png));
        while g.len() > IMAGE_CACHE_CAP {
            g.pop_front();
        }
    }
}

/// Look up a cached image's PNG bytes by hex hash. `None` if evicted or
/// never received.
fn lookup_cached_image(hash_hex: &str) -> Option<Vec<u8>> {
    let g = image_cache().lock().ok()?;
    g.iter()
        .find(|(h, _)| h == hash_hex)
        .map(|(_, png)| png.clone())
}

/// "Clear clipboard history": drop every cached image payload whose hex hash
/// is in `hashes_hex` so a cleared image can't still be fetched via
/// `FetchItem` after the history entry that pointed at it is gone.
fn purge_cached_images(hashes_hex: &[String]) {
    if let Ok(mut g) = image_cache().lock() {
        g.retain(|(h, _)| !hashes_hex.iter().any(|c| c == h));
    }
}

/// Decode PNG bytes to `(width, height, rgba)`. `None` on any decode error.
fn decode_png_to_rgba(png: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let img = image::load_from_memory_with_format(png, image::ImageFormat::Png).ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = (rgba.width(), rgba.height());
    Some((w, h, rgba.into_raw()))
}

/// Encode RGBA pixels to PNG bytes. `None` on failure (e.g. the buffer
/// length doesn't match `width * height * 4`).
#[cfg(not(target_os = "android"))]
fn encode_png(width: u32, height: u32, rgba: Vec<u8>) -> Option<Vec<u8>> {
    let img = image::RgbaImage::from_raw(width, height, rgba)?;
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut out, image::ImageFormat::Png)
        .ok()?;
    Some(out.into_inner())
}

/// Polls the OS clipboard every 200ms and forwards new payloads through
/// the same `DriverCmd::Run { op: Push }` path the IPC `push` op uses.
/// Routing through the cmd channel (instead of firing
/// `Event::LocalClipboardChange` directly) lets us reuse the existing
/// lamport allocation, dedup, and SendItem dispatch — the watcher only
/// has to detect "the OS clipboard changed."
///
/// Dedup happens twice:
///   * `last_seen_hash` filters consecutive polls of the same payload.
///   * `last_written_hashes` (shared with `Action::WriteClipboard`)
///     filters out the immediate read-back of a payload we just wrote
///     ourselves after receiving it from the peer — without it, every
///     inbound item would ping-pong back to the sender.
///
/// Gated on `transport.session.is_some()` so we don't spam the FSM
/// before pairing completes.
///
/// Compiled out on Android — `arboard` doesn't ship an Android backend
/// and the platform forbids background clipboard reads anyway. The
/// Android `MainActivity` does the equivalent work in its
/// `ClipboardManager.OnPrimaryClipChangedListener`.
#[cfg(not(target_os = "android"))]
async fn clipboard_watcher_loop(
    transport: Arc<Transport>,
    cmd_tx: mpsc::UnboundedSender<DriverCmd>,
    last_written_hashes: Arc<Mutex<VecDeque<[u8; 32]>>>,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut last_seen_hash: Option<[u8; 32]> = None;
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    let mut last_session_est = 0u64;
    loop {
        // FS-048: while unpaired there is nothing to poll. Sleep on the
        // session-install pulse instead of waking every 200ms only to
        // observe `session.is_none()` and `continue`.
        if !transport.has_session().await {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                () = transport.session_notify.notified() => {}
            }
            continue;
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let est = transport.session_established_at();
                let session_active = transport.has_session().await;

                if !session_active {
                    continue;
                }

                // [REMEDIATION] Session Seeding: If this is a fresh session, seed last_seen_hash
                // with the current OS clipboard to avoid blasting disconnected-state copies to the peer.
                if est != last_session_est {
                    last_session_est = est;
                    // Image-first, mirroring the poll below: a clipboard
                    // holding image/png means an image was copied, even
                    // when text/html is attached alongside.
                    let img_res = tokio::task::spawn_blocking(|| {
                        arboard::Clipboard::new().and_then(|mut cb| cb.get_image())
                    })
                    .await;
                    if let Ok(Ok(img)) = img_res {
                        last_seen_hash = Some(image_rgba_hash(
                            img.width as u32,
                            img.height as u32,
                            &img.bytes,
                        ));
                        tracing::debug!("Clipboard watcher seeded (image) for new session");
                    } else {
                        let text_res = tokio::task::spawn_blocking(|| {
                            arboard::Clipboard::new().and_then(|mut cb| cb.get_text())
                        })
                        .await;
                        if let Ok(Ok(raw_text)) = text_res {
                            last_seen_hash = Some(clipboard_dedup_hash(&raw_text));
                            tracing::debug!("Clipboard watcher seeded for new session");
                        }
                    }
                }
                // ── Image (takes priority) ───────────────────────────
                // image/png on the clipboard means the user copied an
                // image. Browsers attach text/html + text/x-moz-url
                // alongside it; probing text first would let that URL
                // shadow the image (FS: "sometimes it yields the URL"). So
                // probe the image first and, when present, skip text.
                let img_res = tokio::task::spawn_blocking(|| {
                    arboard::Clipboard::new().and_then(|mut cb| cb.get_image())
                })
                .await;
                if let Ok(Ok(img)) = img_res {
                    let w = img.width as u32;
                    let h = img.height as u32;
                    let rgba = img.bytes.into_owned();
                    let hash = image_rgba_hash(w, h, &rgba);
                    if last_seen_hash != Some(hash) {
                        let already = last_written_hashes.lock().await.contains(&hash);
                        last_seen_hash = Some(hash);
                        if !already {
                            match encode_png(w, h, rgba) {
                                Some(png) if png.len() <= MAX_PAYLOAD => {
                                    let preview = format!(
                                        "Image {w}×{h}, {} KB",
                                        png.len().div_ceil(1024)
                                    );
                                    if cmd_tx
                                        .send(DriverCmd::PushImage { hash, png, preview })
                                        .is_err()
                                    {
                                        tracing::error!("clipboard_watcher_loop: failed to send PushImage command");
                                        return Ok(());
                                    }
                                    tracing::debug!("clipboard_watcher_loop: PushImage command sent");
                                }
                                Some(png) => tracing::warn!(
                                    size = png.len(),
                                    "clipboard image exceeds 16 MiB cap; skipped"
                                ),
                                None => tracing::warn!("clipboard image PNG encode failed"),
                            }
                        }
                    }
                    // Had an image this tick — skip the text probe.
                    continue;
                }

                // ── Text (only when the clipboard holds no image) ────
                let text_res = tokio::task::spawn_blocking(|| {
                    arboard::Clipboard::new().and_then(|mut cb| cb.get_text())
                })
                .await;
                if let Ok(Ok(raw_text)) = text_res {
                    let text = raw_text.trim().to_string();
                    if !text.is_empty() {
                        let hash = clipboard_dedup_hash(&raw_text);
                        if last_seen_hash != Some(hash) {
                            let already =
                                last_written_hashes.lock().await.contains(&hash);
                            last_seen_hash = Some(hash);
                            if !already {
                                if text.len() > MAX_PAYLOAD {
                                    tracing::warn!(
                                        size = text.len(),
                                        "clipboard text exceeds 16 MiB cap; skipped"
                                    );
                                } else {
                                    let (reply_tx, _reply_rx) = oneshot::channel();
                                    if cmd_tx
                                        .send(DriverCmd::Run {
                                            op: CmdOp::Push { text },
                                            reply: reply_tx,
                                            req_id: 0,
                                        })
                                        .is_err()
                                    {
                                        tracing::error!("clipboard_watcher_loop: failed to send Push command");
                                        return Ok(());
                                    }
                                    tracing::debug!("clipboard_watcher_loop: Push command sent");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Heartbeat & Timeout loop
// ─────────────────────────────────────────────────────────────────

/// FluxMesh robustness slice 2: the primary peer's link just died. If a
/// secondary mesh session is still live, promote it into the primary slot and
/// rebind State onto it (via `Event::PrimaryFailover`) so the link stays
/// connected instead of dropping to Discovering. Returns true when it failed
/// over — the caller then SKIPS `Event::PeerLost`.
async fn try_primary_failover(
    transport: &Arc<Transport>,
    event_tx: &mpsc::Sender<Event>,
    peer_meta: &PeerMetaMap,
) -> bool {
    let Some(id) = transport.promote_secondary().await else {
        return false;
    };
    let (name, platform, caps) = match peer_meta.lock().await.get(&id) {
        Some(m) => (m.name.clone(), m.platform.clone(), m.caps.clone()),
        None => (String::new(), String::new(), Vec::new()),
    };
    tracing::warn!(
        peer = %hex::encode(id),
        "primary link lost; failing over to live secondary peer"
    );
    let _ = event_tx.try_send(Event::PrimaryFailover {
        peer_id: id,
        name,
        platform,
        caps,
    });
    let _ = event_tx.try_send(Event::MeshPeersChanged);
    true
}

#[allow(clippy::too_many_arguments)]
async fn heartbeat_loop(
    transport: Arc<Transport>,
    event_tx: mpsc::Sender<Event>,
    shutdown: CancellationToken,
    metrics: Arc<Mutex<MetricsTracker>>,
    backoff: BackoffMap,
    peer_meta: PeerMetaMap,
    self_batt_level: Arc<std::sync::atomic::AtomicU8>,
    self_batt_charging: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    // 3s interval + 3-miss threshold ⇒ an ungraceful disconnect (crash,
    // sleep, Wi-Fi drop — no Bye) surfaces in ~9s instead of the old ~30s,
    // matching the "3 missed = offline" contract documented in state.rs.
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    let mut missed_pings = 0;
    // FluxMesh robustness slice 1: per-secondary-peer missed-ping counters.
    // The primary's `missed_pings` lives above; each `extra` peer ghost-times
    // out on its own schedule so one silent secondary cannot stall another.
    let mut secondary_missed: std::collections::HashMap<[u8; 32], u32> =
        std::collections::HashMap::new();

    let ping_bytes = || {
        let frame = fluxsync_proto::Frame {
            version: fluxsync_proto::PROTOCOL_VERSION,
            msg: fluxsync_proto::Msg::Heartbeat(fluxsync_proto::Heartbeat {
                lamport: 0,
                rtt_hint: None,
            }),
        };
        fluxsync_proto::encode(&frame).ok()
    };

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let now = crate::transport::now_ms();
                let session_active = transport.has_session().await;

                if session_active {
                    // 1. Send Heartbeat (Ping) to the primary peer.
                    if let Some(bytes) = ping_bytes() {
                        tracing::debug!("Heartbeat: sending ping to peer");
                        metrics.lock().await.on_heartbeat_sent();
                        let _ = transport.send_encrypted(&bytes).await;
                    }

                    // 1b. Re-broadcast this device's current battery so the peer
                    // stays fresh even when the level is steady (no change event
                    // would fire otherwise). 255 = not read yet → skip.
                    let level = self_batt_level.load(std::sync::atomic::Ordering::Relaxed);
                    if level != 255 {
                        let charging = self_batt_charging.load(std::sync::atomic::Ordering::Relaxed);
                        let frame = fluxsync_proto::Frame {
                            version: fluxsync_proto::PROTOCOL_VERSION,
                            msg: fluxsync_proto::Msg::BatteryStatus(fluxsync_proto::BatteryStatus {
                                lamport: 0,
                                level,
                                charging,
                            }),
                        };
                        if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                            let _ = transport.send_encrypted(&bytes).await;
                        }
                    }

                    // 2. Check the primary's receive timeout.
                    let last_rx = transport.last_rx();

                    if now.saturating_sub(last_rx) > 3_000 {
                        missed_pings += 1;
                        metrics.lock().await.on_heartbeat_missed();
                        if missed_pings >= 3 {
                            tracing::warn!("Peer timed out (3 missed pings/~9s). Dropping link.");
                            metrics.lock().await.on_disconnect(DisconnectReason::HeartbeatTimeout);
                            // M6 fix: capture the dying peer + its uptime BEFORE
                            // any failover swaps `cached_peer_id`/
                            // `session_established_at` to a promoted secondary.
                            // Only a session that proved stable (>= MIN_STABLE)
                            // resets backoff; a fast flap keeps its escalation.
                            // Also doubles as the `Event::PeerLost` peer_id below:
                            // `install_session` always sets `last_peer_id`
                            // together with the primary session, and we only
                            // reach this branch when `session_active` was true,
                            // so `dead_peer` is guaranteed `Some` here.
                            let dead_peer = transport.cached_peer_id().await;
                            if let Some(dead_peer) = dead_peer {
                                let uptime = Duration::from_millis(
                                    now.saturating_sub(transport.session_established_at()),
                                );
                                backoff
                                    .lock()
                                    .await
                                    .entry(dead_peer)
                                    .or_insert_with(PeerBackoff::new)
                                    .on_session_ended(uptime);
                            }
                            transport.set_last_rx(now);
                            // FluxMesh robustness slice 2: rebind to a live
                            // secondary if one exists; only fall to Discovering
                            // when the whole mesh is gone.
                            if !try_primary_failover(&transport, &event_tx, &peer_meta).await {
                                if let Some(peer_id) = dead_peer {
                                    let _ = event_tx.try_send(Event::PeerLost { peer_id });
                                } else {
                                    tracing::error!(
                                        "heartbeat timeout with no cached primary peer_id; \
                                         skipping PeerLost (should be unreachable)"
                                    );
                                }
                            }
                            missed_pings = 0;
                        }
                    } else {
                        missed_pings = 0;
                    }
                } else {
                    // DISCOVERY PROBE: If no session but we have a last known peer IP,
                    // try a direct handshake poke.
                    if let Some(_addr) = transport.cached_peer_addr().await {
                         // We don't initiate here because we lack the peer's static_pub,
                         // but we can log that we are waiting for that specific IP.
                         // In a future PR, we could cache the static_pub too.
                    }
                }

                // FluxMesh robustness slice 1: secondary peers run their own
                // heartbeat + ghost-timeout, independent of the primary (which
                // may even be down). A silent secondary drops ONLY its own
                // session — it must NOT drive the single FSM's `PeerLost`; it
                // just refreshes the mesh peer list via `MeshPeersChanged`.
                let secondaries = transport.secondary_liveness().await;
                let live: std::collections::HashSet<[u8; 32]> =
                    secondaries.iter().map(|(id, _)| *id).collect();
                secondary_missed.retain(|id, _| live.contains(id));
                for (peer_id, last_rx) in secondaries {
                    if let Some(bytes) = ping_bytes() {
                        let _ = transport.send_encrypted_to(peer_id, &bytes).await;
                    }
                    if now.saturating_sub(last_rx) > 3_000 {
                        let missed = secondary_missed.entry(peer_id).or_insert(0);
                        *missed += 1;
                        if *missed >= 3 {
                            tracing::warn!(
                                peer = %hex::encode(peer_id),
                                "Secondary peer timed out (~9s). Dropping its session."
                            );
                            // M6 residual fix: a secondary's ghost-timeout is a
                            // teardown exactly like the primary's heartbeat
                            // timeout above, so it gets the same stability-gated
                            // backoff reset — computed from THIS peer's own
                            // established time (not the primary's), captured
                            // before `drop_session_for` below clears its session.
                            if let Some(established) =
                                transport.session_established_at_for(peer_id).await
                            {
                                let uptime = Duration::from_millis(now.saturating_sub(established));
                                backoff
                                    .lock()
                                    .await
                                    .entry(peer_id)
                                    .or_insert_with(PeerBackoff::new)
                                    .on_session_ended(uptime);
                            }
                            transport.drop_session_for(peer_id).await;
                            secondary_missed.remove(&peer_id);
                            // FIX1 (P0 parked-payload leak): a silently
                            // timed-out secondary is gone just as surely as
                            // an explicitly revoked one — drop its parked
                            // `Ask` items too (see `Event::PeerRevoked`'s
                            // doc comment). This loop has no `app`, so it
                            // routes through `event_tx` like
                            // `MeshPeersChanged` below already does.
                            let _ = event_tx.try_send(Event::PeerRevoked { peer_id });
                            let _ = event_tx.try_send(Event::MeshPeersChanged);
                        }
                    } else {
                        secondary_missed.remove(&peer_id);
                    }
                }
            }
        }
    }
}

/// DIR-P2-03: how often the rekey watchdog re-checks the primary session's
/// age/bytes against the rekey thresholds. Cheap (atomic loads plus an
/// occasional lock read) and rekeys are rare, so a short interval costs
/// nothing while keeping test-injected (small) thresholds responsive.
const REKEY_CHECK_INTERVAL: Duration = Duration::from_millis(500);

/// DIR-P2-03: automatic session rekey. Every [`REKEY_CHECK_INTERVAL`],
/// checks EVERY currently-linked session — the primary and every FluxMesh
/// `extra` secondary, via [`Transport::linked_peer_ids`] — for whether it
/// has crossed `max_age_ms` or `max_bytes` (see
/// [`crate::transport::rekey_due`]), each against its own established-at/
/// byte-count clock. For the first peer found due, checks whether this
/// daemon is the deterministic rekey initiator for that peer
/// ([`crate::transport::is_rekey_initiator`] — exactly one side of a pair
/// ever is). The other side does nothing: it just accepts the fresh
/// handshake the same way it already accepts any reconnect, via
/// `handshake::run_responder`'s generation-gated install (primary or
/// secondary — see the `secondary_generation` arm there).
///
/// FluxMesh fix: this used to read only the primary's clock and only ever
/// targeted `cached_peer_id()`, so a secondary session — however long-lived
/// — never rotated, violating the rekey policy for every mesh peer but the
/// primary. Iterating `linked_peer_ids()` and resolving each peer's own
/// clock via `session_established_at_for`/`session_bytes_for` (instead of
/// the primary-only `session_established_at`/`session_bytes`) extends the
/// same policy to all of them, uniformly.
///
/// Reuses the same `pending_initiator_tx` single-flight slot as ordinary
/// reconnects, now shared across every peer's rekey attempt too, so at most
/// one initiator handshake — for whichever due peer is checked first — runs
/// at a time; any other due peer simply retries on the next tick. A
/// rekey-triggered re-handshake is intentional, not a failure: on success it
/// feeds `PeerBackoff::on_session_ended` (gated on the old session's uptime,
/// M6) exactly like any other completed handshake; on failure it
/// deliberately does **not** call
/// `on_attempt_failed` — the peer did nothing wrong, so a transient rekey
/// hiccup must not penalize its future reconnect pacing. The next tick
/// simply retries (the age/bytes trigger stays true until a rekey
/// actually lands).
#[allow(clippy::too_many_arguments)]
async fn rekey_watchdog(
    identity: Identity,
    transport: Arc<Transport>,
    trusted: TrustedSet,
    pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: mpsc::Sender<Event>,
    backoff: BackoffMap,
    max_age_ms: u64,
    max_bytes: u64,
    keystore_dir: Option<PathBuf>,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut interval = tokio::time::interval(REKEY_CHECK_INTERVAL);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                // FluxMesh fix: check every currently-linked peer (primary +
                // every `extra` secondary), each against its OWN clock —
                // not just the primary. `pending_initiator_tx` stays a
                // single global slot, so at most one rekey handshake starts
                // per tick regardless of how many peers are due; the rest
                // are picked up on a later tick.
                for peer_id in transport.linked_peer_ids().await {
                    let Some(established_at) = transport.session_established_at_for(peer_id).await else {
                        continue;
                    };
                    let age_ms = now_ms().saturating_sub(established_at);
                    let bytes = transport.session_bytes_for(peer_id).await.unwrap_or(0);
                    if !rekey_due(age_ms, bytes, max_age_ms, max_bytes) {
                        continue;
                    }
                    if !is_rekey_initiator(identity.peer_id(), peer_id) {
                        // The peer is the deterministic initiator for this pair;
                        // we just wait to accept its handshake.
                        continue;
                    }

                    // Single-flight: never overlap with an organic reconnect
                    // or an earlier rekey attempt still finishing — shared
                    // across every peer, so once taken no other due peer can
                    // start either; stop scanning rather than looping
                    // through the rest for nothing.
                    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    {
                        let mut g = pending_initiator_tx.lock().await;
                        if g.is_some() {
                            break;
                        }
                        *g = Some(tx);
                    }

                    let Some(peer_addr) = transport.peer_addr_for(peer_id).await else {
                        *pending_initiator_tx.lock().await = None;
                        continue;
                    };
                    let static_pub = trusted.lock().await.get(&peer_id).map(|p| p.static_pub);
                    let Some(static_pub) = static_pub else {
                        *pending_initiator_tx.lock().await = None;
                        continue;
                    };
                    let Some(expected_generation) = transport.session_generation_for(peer_id).await else {
                        *pending_initiator_tx.lock().await = None;
                        continue;
                    };

                    tracing::info!(
                        peer = %hex::encode(&peer_id[..6]),
                        age_ms,
                        bytes,
                        "DIR-P2-03: starting planned session rekey"
                    );

                    let identity = identity.clone();
                    let transport = transport.clone();
                    let rekey_metrics = transport.metrics.clone();
                    let event_tx = event_tx.clone();
                    let backoff = backoff.clone();
                    let pending_initiator_tx = pending_initiator_tx.clone();
                    let trusted_for_rekey = trusted.clone();
                    let kd = keystore_dir.clone();
                    // M6 fix: gate the post-rekey backoff reset on the OLD
                    // session's uptime (already computed above as `age_ms`)
                    // instead of resetting unconditionally on every successful
                    // rekey — see `PeerBackoff::on_session_ended`.
                    let pre_rekey_uptime = Duration::from_millis(age_ms);
                    tokio::spawn(async move {
                        let result = handshake::run_rekey_initiator(
                            identity,
                            static_pub,
                            peer_addr,
                            transport,
                            rx,
                            event_tx,
                            peer_id,
                            expected_generation,
                            trusted_for_rekey,
                            kd,
                        )
                        .await;
                        match result {
                            Ok(()) => {
                                backoff
                                    .lock()
                                    .await
                                    .entry(peer_id)
                                    .or_insert_with(PeerBackoff::new)
                                    .on_session_ended(pre_rekey_uptime);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "DIR-P2-03: planned rekey attempt failed; will retry \
                                     (not counted against reconnect backoff)"
                                );
                                rekey_metrics.lock().await.on_handshake_fail();
                            }
                        }
                        *pending_initiator_tx.lock().await = None;
                    });
                    // Single-flight slot is now taken; stop scanning for
                    // more due peers this tick.
                    break;
                }
            }
        }
    }
}

/// Boot-time fallback trusted-peer choice, for the `Event::SetTrustedPeer`
/// UI hint `run()` sends right after reloading `peers.json`. `HashMap`
/// iteration order is randomized per process, so picking `.values().next()`
/// used to name a different trusted peer on every restart whenever more
/// than one is paired. Prefer the primary's own entry when its id is
/// already known at this point (e.g. the test harness's `test_pair` already
/// installed a session); otherwise fall back to the lowest peer id so the
/// choice is stable across restarts instead of iteration-order luck.
fn choose_boot_trusted_peer(
    trusted: &HashMap<[u8; 32], TrustedPeer>,
    primary_id: Option<[u8; 32]>,
) -> Option<TrustedPeer> {
    primary_id
        .and_then(|id| trusted.get(&id))
        .or_else(|| trusted.iter().min_by_key(|(id, _)| **id).map(|(_, p)| p))
        .cloned()
}

/// Load the trusted-peer set from `peers.json` (FS-039); malformed entries
/// are skipped with a warning. Also returns each entry's persisted
/// last-known remote address (`last_addr` redial), best-effort parsed —
/// missing or unparseable yields `None` rather than failing the whole boot.
fn load_trusted_peers(dir: &Path) -> Vec<([u8; 32], TrustedPeer, Option<SocketAddr>)> {
    let stored = match crate::keystore::load_peers(dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not read peers.json; starting with no trusted peers");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(stored.len());
    for p in stored {
        let static_pub = match decode_hex32(&p.static_pub_hex) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, peer = %p.peer_id_hex, "skipping peers.json entry: bad static_pub");
                continue;
            }
        };
        // H1 (defense-in-depth): a peers.json copied from a vulnerable
        // pre-fix daemon may already contain degenerate pubkeys. Filter
        // them at boot rather than panicking later inside Noise IK.
        if let Err(e) = fluxsync_crypto::validate_peer_pubkey(&static_pub) {
            tracing::warn!(
                error = %e,
                peer = %p.peer_id_hex,
                "skipping peers.json entry: invalid pubkey (zero or low-order)"
            );
            continue;
        }
        let peer_id = handshake::peer_id_for(&static_pub);
        let last_addr = p.last_addr.as_deref().and_then(|s| match s.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(error = %e, peer = %p.peer_id_hex, addr = %s, "skipping unparseable last_addr");
                None
            }
        });
        out.push((
            peer_id,
            TrustedPeer {
                static_pub,
                name: p.name,
            },
            last_addr,
        ));
    }
    // H3: enforce the cap at load too. If a malicious or pre-fix
    // peers.json has more than `MAX_PERSISTED_PEERS` entries, keep the
    // first N (load order = file order = insertion order under the
    // disk lock). This is conservative: it never silently *replaces*
    // a peer the user might still recognize, but it stops boot-time
    // memory blow-up.
    if out.len() > MAX_PERSISTED_PEERS {
        tracing::warn!(
            total = out.len(),
            cap = MAX_PERSISTED_PEERS,
            "peers.json exceeds cap; truncating tail. Revoke unwanted entries via `fluxctl revoke <peer-id>`."
        );
        out.truncate(MAX_PERSISTED_PEERS);
    }
    out
}

/// Persist the current trusted-peer set to `peers.json` (FS-039). Used by
/// callers that rewrite the WHOLE set from the in-memory `TrustedSet`
/// (Unpair, Revoke, `PairConfirm --reject`) rather than upserting one entry
/// (contrast [`upsert_peer_persist`], used by the pair-insert paths, and
/// [`persist_last_addr`], used on every completed handshake).
///
/// last_addr persistence: `TrustedPeer` carries no address
/// field, so a naive rebuild would silently overwrite every surviving
/// peer's `last_addr` with `None` on each of these operations. Preserve it
/// by reading the existing on-disk record for each peer_id that survives
/// the rewrite and carrying its `last_addr` forward; only a genuinely new
/// entry (not found on disk) gets `None`.
async fn save_current_peers(
    dir: &Path,
    trusted: &TrustedSet,
    _transport: &Transport,
) -> Result<()> {
    let existing_addrs: HashMap<String, Option<String>> = crate::keystore::load_peers(dir)
        .unwrap_or_default()
        .into_iter()
        .map(|p| (p.peer_id_hex, p.last_addr))
        .collect();
    let stored: Vec<crate::keystore::StoredPeer> = {
        let g = trusted.lock().await;
        g.iter()
            .map(|(peer_id, peer)| {
                let peer_id_hex = hex::encode(peer_id);
                let last_addr = existing_addrs.get(&peer_id_hex).cloned().flatten();
                crate::keystore::StoredPeer {
                    peer_id_hex,
                    static_pub_hex: hex::encode(peer.static_pub),
                    name: peer.name.clone(),
                    last_addr,
                }
            })
            .collect()
    };
    crate::keystore::save_peers(dir, &stored)
}

/// FS-052 / VULN-001 fix: persist `trusted` to `peers.json` with up to
/// `PEERS_PERSIST_ATTEMPTS` tries (exponential backoff 100/200/400 ms).
/// Used by paths whose security invariant depends on the on-disk state
/// matching the in-memory state — namely `PairConfirm --reject` and the
/// FS-052 strict pending-expiry revoke. Silently swallowing the write
/// would re-trust the attacker on next daemon restart.
pub(crate) async fn save_peers_with_retry(
    dir: &Path,
    trusted: &TrustedSet,
    transport: &Transport,
) -> Result<()> {
    // F-001 fix: serialize every peers.json write so a concurrent
    // pair-insert cannot read a stale snapshot and clobber this revoke.
    let _disk_guard = transport.peers_disk_lock.lock().await;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..PEERS_PERSIST_ATTEMPTS {
        match save_current_peers(dir, trusted, transport).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "save_peers failed; retrying");
                last_err = Some(e);
                if attempt + 1 < PEERS_PERSIST_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(100u64 << attempt)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("save_peers exhausted retries")))
}

/// Max attempts for [`save_peers_with_retry`]. Three is enough to ride
/// out a transient ENOSPC / EBUSY / fs-quota hiccup without making the
/// IPC reply hang forever on a broken disk.
const PEERS_PERSIST_ATTEMPTS: u32 = 3;

/// M-DAEMON-11: bounded capacity for the daemon's central `Event` channel.
/// One mono-task consumer drains it; 1024 is orders of magnitude above any
/// legitimate burst (chunk reassembly already caps concurrent inbound items at
/// 5), so it only ever fills under a hostile flood — at which point `try_send`
/// drops with a warning instead of growing memory without bound.
const EVENT_CHANNEL_CAP: usize = 1024;

/// M-DAEMON-11: bounded capacity for the mDNS `DiscoveryEvent` channel. A
/// dropped resolve under flood is harmless — mDNS re-announces, and the
/// downstream discovery cache is itself capped at 256.
const DISCOVERY_CHANNEL_CAP: usize = 256;

/// Atomic upsert of a single [`crate::keystore::StoredPeer`] into
/// `peers.json`: takes the disk lock, reads the on-disk list, upserts
/// `entry` by `peer_id_hex`, and persists with retry. Used by the
/// pair-insert paths (PairFromUri / PairAccept / TOFU) where the new
/// entry carries data (e.g. `last_addr`) that the in-memory
/// `TrustedSet` does not retain.
///
/// Replaces the old `save_peers_with_retry_stored` + inline
/// `load_peers().unwrap_or_default()` pattern. Two fixes folded in:
///
/// * **F-001** — the load/modify/save sequence runs entirely under
///   `transport.peers_disk_lock`, so a concurrent reaper revoke cannot
///   race against the load and have its write overwritten.
/// * **F-002** — `load_peers` parse failure now propagates instead of
///   being swallowed by `unwrap_or_default()` (which would silently
///   nuke every other trusted peer from disk).
pub(crate) async fn upsert_peer_persist(
    dir: &Path,
    transport: &Transport,
    entry: crate::keystore::StoredPeer,
) -> Result<()> {
    let _disk_guard = transport.peers_disk_lock.lock().await;
    let mut stored = crate::keystore::load_peers(dir).with_context(|| {
        format!(
            "read {}/peers.json before upsert; refusing to overwrite a corrupt file",
            dir.display()
        )
    })?;
    crate::keystore::upsert_peer(&mut stored, entry);
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..PEERS_PERSIST_ATTEMPTS {
        match crate::keystore::save_peers(dir, &stored) {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "upsert_peer_persist save failed; retrying");
                last_err = Some(e);
                if attempt + 1 < PEERS_PERSIST_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(100u64 << attempt)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("upsert_peer_persist exhausted retries")))
}

/// Persist `peer_id`'s current remote address into its on-disk `StoredPeer`
/// record (last_addr persistence + redial). This is the
/// single chokepoint called from every path that completes a Noise
/// handshake — fresh pairing (TOFU), an ordinary reconnect, and a planned
/// rekey, both initiator and responder roles (see
/// `handshake::run_initiator`, `handshake::run_rekey_initiator`, and
/// `handshake::run_responder`) — so `peers.json`'s `last_addr` always
/// reflects the most recently confirmed address. That, combined with
/// `run()`'s boot-time seed of `Transport` from `load_trusted_peers`, is
/// what lets a rebooted daemon redial an already-paired peer with zero
/// mDNS involvement.
///
/// No-op when `keystore_dir` is `None` (in-process test harnesses with no
/// on-disk persistence) or when `peer_id` is not (yet) in `trusted` — the
/// latter should not happen for a handshake that just completed, but a
/// stale invariant here must degrade to "skip the write", never panic.
/// L4 fix: rejects the source-IP-spoofable address classes (unspecified /
/// multicast / link-local) so a `last_addr` we persist or seed a boot-time
/// redial from can never be one a LAN attacker plants via a forged source
/// IP during the pairing window. Loopback is deliberately NOT rejected: a
/// 127.0.0.0/8 source cannot be spoofed onto a real interface (the kernel
/// drops inbound packets claiming a loopback source), redialing localhost is
/// harmless, and the in-process test harness relies on it.
fn is_redialable_addr(ip: std::net::IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

pub(crate) async fn persist_last_addr(
    keystore_dir: Option<&Path>,
    transport: &Transport,
    trusted: &TrustedSet,
    peer_id: [u8; 32],
    addr: SocketAddr,
) {
    let Some(dir) = keystore_dir else { return };
    if !is_redialable_addr(addr.ip()) {
        tracing::warn!(
            peer = %hex::encode(&peer_id[..6]),
            addr = %addr,
            "L4: refusing to persist a link-local/multicast/unspecified last_addr"
        );
        return;
    }
    let entry = { trusted.lock().await.get(&peer_id).cloned() };
    let Some(entry) = entry else {
        tracing::debug!(
            peer = %hex::encode(&peer_id[..6]),
            "persist_last_addr: peer not in trusted set yet; skipping"
        );
        return;
    };
    let stored = crate::keystore::StoredPeer {
        peer_id_hex: hex::encode(peer_id),
        static_pub_hex: hex::encode(entry.static_pub),
        name: entry.name,
        last_addr: Some(addr.to_string()),
    };
    if let Err(e) = upsert_peer_persist(dir, transport, stored).await {
        tracing::warn!(
            error = %e,
            peer = %hex::encode(&peer_id[..6]),
            "failed to persist last_addr after handshake"
        );
    }
}

/// Send an item Ack straight to the source peer. FluxMesh 2C-b: acks are a
/// transport concern routed to whoever sent the datagram (the only place the
/// source peer_id is known), not an FSM-emitted action.
async fn ack_source(transport: &Arc<Transport>, peer_id: [u8; 32], hash: [u8; 32]) {
    let frame = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Ack(fluxsync_proto::Ack { lamport: 0, hash }),
    };
    if let Ok(bytes) = fluxsync_proto::encode(&frame) {
        let _ = transport.send_encrypted_to(peer_id, &bytes).await;
    }
}

/// Relay a freshly-seen item to every linked peer except its `source` and
/// `origin`, tracking the relayed hash in `inflight` so retransmits cover a
/// dropped relay datagram (FluxMesh 2C-b mesh forwarding).
/// Encode a clipboard item into its wire frames: one `ClipboardItem` for a
/// small payload, or an empty-payload header followed by one `Chunk` per slice
/// for a large one. Shared by the outbound `SendItem` path and the chunked
/// relay (FluxMesh robustness slice 3), so a relayed image is re-chunked
/// identically and keeps the original `origin`/`event_seq`.
fn build_item_frames(
    lamport: u64,
    hash: [u8; 32],
    kind: Kind,
    payload: &[u8],
    sensitive: bool,
    origin: [u8; 32],
    event_seq: u64,
) -> Vec<Vec<u8>> {
    let mut frames: Vec<Vec<u8>> = Vec::new();
    if payload.len() <= MAX_CHUNK_DATA {
        let item = ClipboardItem {
            lamport,
            hash,
            kind,
            payload: payload.to_vec(),
            sensitive,
            wall_time_ms: 0,
            origin,
            event_seq,
        };
        if let Ok(bytes) = fluxsync_proto::encode(&Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ClipboardItem(item),
        }) {
            frames.push(bytes);
        } else {
            tracing::error!("build_item_frames: CBOR encode failed");
        }
    } else {
        // Large payload: a header frame (empty payload), then one per chunk.
        let header = ClipboardItem {
            lamport,
            hash,
            kind,
            payload: Vec::new(),
            sensitive,
            wall_time_ms: 0,
            origin,
            event_seq,
        };
        if let Ok(bytes) = fluxsync_proto::encode(&Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::ClipboardItem(header),
        }) {
            frames.push(bytes);
        }
        let chunks: Vec<_> = payload.chunks(MAX_CHUNK_DATA).collect();
        let total = chunks.len() as u16;
        for (idx, data) in chunks.into_iter().enumerate() {
            let chunk = fluxsync_proto::Chunk {
                item_id: hash,
                idx: idx as u16,
                total,
                data: data.to_vec(),
            };
            if let Ok(bytes) = fluxsync_proto::encode(&Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::Chunk(chunk),
            }) {
                frames.push(bytes);
            }
        }
    }
    frames
}

/// Fan one item's frames out to every linked peer except `source` and `origin`
/// (mesh relay), with the same burst-16/pause-2ms pacing as the outbound path
/// for multi-frame items, and arm the retransmit timer until each target acks.
async fn forward_frames(
    transport: &Arc<Transport>,
    inflight: &InflightMap,
    pending_pairs: &PendingSet,
    source: [u8; 32],
    origin: [u8; 32],
    hash: [u8; 32],
    frames: Vec<Vec<u8>>,
) {
    // FS-052 gate (mesh-relay hole fix): mirrors the per-target pending
    // filter `Action::SendItem` already applies. Without it, a confirmed
    // peer's plaintext clipboard was relayed to any linked-but-unconfirmed
    // TOFU secondary, bypassing the FS-052 confirmation gate entirely.
    let all_targets = transport.linked_peer_ids().await;
    let targets: Vec<[u8; 32]> = {
        let pending = pending_pairs.lock().await;
        all_targets
            .into_iter()
            .filter(|d| *d != source && *d != origin && !pending.contains_key(d))
            .collect()
    };
    if targets.is_empty() || frames.is_empty() {
        return;
    }
    let multi = frames.len() > 1;
    for peer in &targets {
        for (i, bytes) in frames.iter().enumerate() {
            let _ = transport.send_encrypted_to(*peer, bytes).await;
            if multi && (i + 1) % 16 == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }
    // Inflight merge fix (sibling of the ResyncPull-serve merge below): a
    // blind `insert` here would REPLACE any entry a concurrent relay or
    // local `Action::SendItem` already created for this same hash, silently
    // dropping whichever peers that entry was still awaiting an ack from —
    // they'd never get a retransmit, and the entry would clear on the NEW
    // peers' acks as if the old ones had been delivered. Merge instead.
    match inflight.lock().await.entry(hash) {
        std::collections::hash_map::Entry::Occupied(mut e) => {
            let inf = e.get_mut();
            inf.pending_peers.extend(targets);
            inf.frames = frames;
            inf.last_sent = Instant::now();
        }
        std::collections::hash_map::Entry::Vacant(v) => {
            v.insert(Inflight {
                frames,
                attempts: 0,
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                pending_peers: targets.into_iter().collect(),
            });
        }
    }
}

async fn forward_item(
    transport: &Arc<Transport>,
    inflight: &InflightMap,
    pending_pairs: &PendingSet,
    source: [u8; 32],
    origin: [u8; 32],
    hash: [u8; 32],
    frame_bytes: Vec<u8>,
) {
    forward_frames(
        transport,
        inflight,
        pending_pairs,
        source,
        origin,
        hash,
        vec![frame_bytes],
    )
    .await;
}

/// FluxMesh robustness slice 3: finish a reassembled chunked item. Acks the
/// source (always, so it stops retransmitting), then — only on first sight of
/// this `EventId` (mesh anti-loop) — re-chunks the full payload and relays it
/// across further hops, and delivers it locally. A chunked image now reaches
/// a third node B→C, not just direct neighbours.
#[allow(clippy::too_many_arguments)]
/// Namespace the reassembly map by the immediate source peer so concurrent
/// transfers of the same `item_id` from different mesh peers cannot share a
/// `Reassembly` slot vector. Without this, a paired-but-misbehaving peer could
/// send `Chunk{item_id=H, ..}` to overwrite a slot another peer is filling for
/// the same H, delivering a corrupted payload under an authentic hash. Keyed by
/// BLAKE3(source ‖ item_id); the content hash itself is still carried unchanged
/// into `complete_reassembled_item`.
fn reassembly_key(source: [u8; 32], item_id: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&source);
    buf[32..].copy_from_slice(&item_id);
    fluxsync_core::DedupRing::hash(&buf).into_bytes()
}

/// SE-14 defense in depth (daemon-side): confirm the wire `hash` a peer
/// claims for an item actually matches its payload before the frame is
/// trusted for outbox admission, mesh relay, or ack — otherwise a hostile
/// peer could squat a legitimate hash with different bytes, later served to
/// a third peer via resync. Mirrors each kind's real hashing convention:
/// text canonicalizes via `canon_text` before hashing for valid UTF-8 (same
/// as the sender's `clipboard_dedup_hash`, and the same rule core's own
/// SE-14 dedup recompute in `App::handle`'s `FrameReceivedClipboard` arm
/// uses), falling back to raw bytes for invalid UTF-8 exactly like it does.
/// Images hash the decoded RGBA pixels via `image_rgba_hash`, matching every
/// image sender path (`clipboard_watcher_loop`, `CmdOp::PushImage`) — this
/// is deliberately NOT core's internal dedup-ring hash for images, which
/// hashes the raw wire PNG bytes and was never meant to equal the sender's
/// claimed hash (see the SE-14 comment in `fluxsync-core/src/app.rs`: that
/// recompute exists so a hostile peer can't choose the dedup ring's slot,
/// not to validate what the sender claims). A payload that fails to decode
/// as PNG cannot be verified and is rejected fail-closed.
fn verify_content_hash(kind: Kind, payload: &[u8], claimed: [u8; 32]) -> bool {
    let computed = match kind {
        Kind::Image => match decode_png_to_rgba(payload) {
            Some((w, h, rgba)) => image_rgba_hash(w, h, &rgba),
            None => return false,
        },
        _ => match std::str::from_utf8(payload) {
            Ok(text) => DedupRing::hash(fluxsync_core::canon_text(text).as_bytes()).into_bytes(),
            Err(_) => DedupRing::hash(payload).into_bytes(),
        },
    };
    computed == claimed
}

#[allow(clippy::too_many_arguments)]
async fn complete_reassembled_item(
    transport: &Arc<Transport>,
    inflight: &InflightMap,
    mesh_seen: &MeshSeen,
    event_tx: &mpsc::Sender<Event>,
    source: [u8; 32],
    origin: [u8; 32],
    event_seq: u64,
    hash: [u8; 32],
    kind: Kind,
    sensitive: bool,
    lamport: u64,
    payload: Vec<u8>,
    outbox: &SharedOutbox,
    outbox_stage: &PendingOutboxStage,
    pending_pulls: &PendingPulls,
    state_rx: &watch::Receiver<State>,
    pending_pairs: &PendingSet,
) {
    // SE-14 defense in depth: reject a reassembled item whose claimed hash
    // doesn't match its payload BEFORE acking, relaying, or caching it —
    // see `verify_content_hash`.
    if !verify_content_hash(kind, &payload, hash) {
        tracing::warn!(
            peer = ?&source[..6],
            "SE-14: dropping reassembled item — wire hash does not match recomputed content hash"
        );
        return;
    }
    ack_source(transport, source, hash).await;
    let eid = EventId::new(DeviceId::from(origin), event_seq);
    if !mesh_seen.lock().await.observe(eid) {
        // Already seen this item on the mesh — don't re-apply or re-loop it.
        return;
    }
    // Resync-on-reconnect (resync-1): first sight of this item. Outbox
    // admission gate fix: `Event::FrameReceivedClipboard` (sent below) has
    // not been through the firewall yet, so we mirror its Pass/Ask/Block
    // decision here ourselves rather than inserting unconditionally — the
    // outbox must only ever hold items admitted to history (see
    // `crate::outbox`'s security invariant). Sensitive items are excluded
    // outright, matching the same invariant.
    let mut block_relay = false;
    if !sensitive {
        let decision = state_rx
            .borrow()
            .firewall
            .decide(kind, sensitive, Direction::Inbound);
        let staged = OutboxEntry {
            payload: payload.clone(),
            kind,
            origin,
            seq: event_seq,
            created: Instant::now(),
        };
        match decision {
            Decision::Pass => {
                outbox.lock().await.insert(hash, staged);
            }
            Decision::Defer => {
                // Parked under `Ask`: not admitted yet. Stage it so
                // `CmdOp::ResolvePending{allow: true}` can promote it later —
                // see `PendingOutboxStage`'s doc comment. First-wins, same as
                // `fluxsync_core::App::park_pending`'s own idempotent guard:
                // a blind `insert` here could let a SECOND peer offering the
                // identical hash silently overwrite the first peer's staged
                // entry, so `outbox_stage` and `pending_payloads` end up
                // crediting different peers for the same hash — corrupting
                // whichever gets purged on revoke.
                outbox_stage.lock().await.entry(hash).or_insert(staged);
            }
            Decision::Block => {
                // Firewall-enforcing relay: a Blocked item must not reach
                // other mesh peers either — only local admission was gated
                // before, so a Blocked item still relayed straight through.
                // Sensitive items are exempt (`block_relay` stays false when
                // `sensitive` is true above) — they're ephemeral and the
                // destination must still receive them.
                block_relay = true;
            }
        }
    }
    let frames = build_item_frames(lamport, hash, kind, &payload, sensitive, origin, event_seq);
    if !block_relay {
        forward_frames(transport, inflight, pending_pairs, source, origin, hash, frames).await;
    }
    let preview = preview_label(kind, &payload);
    // resync-1 apply-suppression fix: did WE ask `source` for this exact
    // hash via ResyncPull? If so this is a catch-up delivery, not a fresh
    // copy — history/vault/relay/ack still happen (above/below), but
    // `App::handle` must drop the `WriteClipboard` action for it.
    let resync = take_pending_pull(pending_pulls, source, hash).await;
    let _ = event_tx.try_send(Event::FrameReceivedClipboard {
        hash,
        kind,
        payload,
        preview,
        sensitive,
        lamport,
        resync,
        // FIX1: `source` is the direct sender of THIS hop (see `ack_source`
        // above, which acks the same peer) — not necessarily the item's
        // mesh `origin` for a forwarded/relayed item. That's the right peer
        // to tag a parked `Ask` item with: it's who we'd need to hear from
        // again, and whose revoke should drop this item.
        peer_id: source,
    });
}

/// resync-1: build a `ResyncOffer` from our own outbox's held hashes
/// (already newest-first per `Outbox::hashes`), hex-encoding each for the
/// wire. Factored out of the `Msg::Hello` handler so it's unit-testable
/// without a live `Outbox`/transport.
fn build_resync_offer(outbox_hashes: &[[u8; 32]]) -> ResyncOffer {
    ResyncOffer {
        hashes: outbox_hashes.iter().map(hex::encode).collect(),
    }
}

/// resync-1: which hashes a peer offered that we do not already hold,
/// preserving the offer's order and capped at `MAX_RESYNC_HASHES` (already
/// guaranteed by the codec on `offered`, but kept defensive here too since
/// this helper has no codec of its own to rely on). "Held" means present in
/// our clipboard history OR our own outbox. H2 fix: `cleared_hashes`
/// (hex-encoded, from `ClearedTombstone`) is a third exclusion — a hash we
/// deliberately cleared via `CmdOp::ClearHistory` must never be re-pulled
/// just because a peer's outbox still offers it.
fn missing_resync_hashes(
    offered: &[String],
    history_hashes: &[String],
    outbox_hashes: &[String],
    cleared_hashes: &[String],
    pending_pull_hashes: &[String],
) -> Vec<String> {
    offered
        .iter()
        .filter(|h| {
            !history_hashes.iter().any(|x| x == *h)
                && !outbox_hashes.iter().any(|x| x == *h)
                && !cleared_hashes.iter().any(|x| x == *h)
                // Bug #7: a hash we already have an outstanding ResyncPull
                // in flight for (to ANY peer) must not start a second one —
                // see `in_flight_pull_hashes`.
                && !pending_pull_hashes.iter().any(|x| x == *h)
        })
        .take(MAX_RESYNC_HASHES)
        .cloned()
        .collect()
}

/// resync-1 defense in depth: the codec already validates a `ResyncOffer` /
/// `ResyncPull`'s shape and bounds, but a message must also come from a
/// currently linked peer that negotiated the `resync-1` capability with US
/// specifically — not just any peer that happens to claim it.
async fn resync_authorized(
    transport: &Arc<Transport>,
    peer_meta: &PeerMetaMap,
    peer_id: [u8; 32],
) -> bool {
    if !transport.linked_peer_ids().await.contains(&peer_id) {
        return false;
    }
    peer_meta
        .lock()
        .await
        .get(&peer_id)
        .is_some_and(|m| m.caps.iter().any(|c| c == "resync-1"))
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_inbound_frame(
    frame: Frame,
    peer_id: [u8; 32],
    mesh_seen: &MeshSeen,
    event_tx: &mpsc::Sender<Event>,
    transport: &Arc<Transport>,
    reassembly: &Arc<Mutex<HashMap<[u8; 32], Reassembly>>>,
    metrics: &Arc<Mutex<MetricsTracker>>,
    inflight: &InflightMap,
    pending_pairs: &PendingSet,
    trusted: &TrustedSet,
    disc_cache: &DiscoveryCache,
    backoff: &BackoffMap,
    peer_meta: &PeerMetaMap,
    keystore_dir: Option<&std::path::PathBuf>,
    outbox: &SharedOutbox,
    pending_pulls: &PendingPulls,
    outbox_stage: &PendingOutboxStage,
    state_rx: &watch::Receiver<State>,
    deferred_sas_confirm: &DeferredSasConfirm,
    echo_ack_sent: &EchoAckSent,
    cleared_tombstone: &ClearedTombstone,
) {
    // FS-052 strict gate (VULN-002 fix): if the active session's peer
    // landed via TOFU and has not been verbally confirmed yet, drop all
    // data-bearing frames (`ClipboardItem`, `Chunk`) until the user runs
    // `fluxctl pair confirm --accept`. Hello / Heartbeat / Ack / Nak /
    // Bye keep flowing so the link stays diagnosable and the FSM still
    // reacts to peer disconnects — and `PairConfirm` MUST flow too, since
    // its whole purpose is to resolve exactly this pending window. Matches
    // the design intent stated in `docs/THREAT-MODEL.md` §3 row B-S: *"a
    // hard gate that blocks Msg::Item processing until the user runs
    // --accept"*.
    //
    // FS-052 egress hole fix: `ResyncOffer`/`ResyncPull` are also
    // data-bearing (resync-1 catch-up delivery) — without gating them here
    // too, an unconfirmed peer could still trade offers/pulls with us and
    // have cached clipboard content served straight to it, bypassing the
    // gate entirely.
    let blocks_until_confirmed = matches!(
        frame.msg,
        Msg::ClipboardItem(_) | Msg::Chunk(_) | Msg::ResyncOffer(_) | Msg::ResyncPull(_)
    );
    if blocks_until_confirmed {
        // Hardening: a peer must be BOTH currently trusted AND not still
        // pending confirmation to receive clipboard data. Checking only
        // `pending_pairs` used to leave a hole once the reaper expired a
        // peer: it removes the `pending_pairs` entry (and the `trusted`
        // entry) but a secondary's live `extra` session survives independent
        // of that sweep, so a not-trusted / not-pending peer must be
        // rejected fail-closed rather than falling through as "not pending,
        // so allowed".
        let still_pending = pending_pairs.lock().await.contains_key(&peer_id);
        let is_trusted = trusted.lock().await.contains_key(&peer_id);
        if still_pending || !is_trusted {
            tracing::warn!(
                peer = ?&peer_id[..6],
                "FS-052 gate: dropping clipboard frame — peer not yet verbally confirmed or no longer trusted"
            );
            return;
        }
    }
    match frame.msg {
        Msg::ClipboardItem(item) => {
            if item.payload.is_empty() {
                // Header for a chunked transfer
                let mut map = reassembly.lock().await;
                // Per-source namespacing: same item_id from different peers
                // must not collide in one Reassembly (see reassembly_key).
                let key = reassembly_key(peer_id, item.hash);
                // FS-058 V2: mirror the chunk-arm cap. A flood of headers
                // for new items must not grow `reassembly` unbounded —
                // evict the least-recently-updated entry first.
                if !map.contains_key(&key) && map.len() >= 5 {
                    let oldest = map
                        .iter()
                        .min_by_key(|(_, r)| r.last_update)
                        .map(|(k, _)| *k);
                    if let Some(k) = oldest {
                        map.remove(&k);
                    }
                }
                let r = map.entry(key).or_insert_with(|| Reassembly {
                    metadata: Some((item.lamport, item.kind, item.sensitive)),
                    origin: item.origin,
                    event_seq: item.event_seq,
                    chunks: Vec::new(),
                    last_update: Instant::now(),
                    first_seen: Instant::now(),
                    source: peer_id,
                    item_hash: item.hash,
                });
                r.metadata = Some((item.lamport, item.kind, item.sensitive));
                r.origin = item.origin;
                r.event_seq = item.event_seq;
                r.last_update = Instant::now();
                // A header datagram can arrive AFTER all its chunks (UDP
                // reorders freely). Check completion here too — not only in
                // the Chunk arm — or a late header strands a full payload.
                if let Some((lamport, kind, sensitive)) = r
                    .metadata
                    .filter(|_| !r.chunks.is_empty())
                    .filter(|_| r.chunks.iter().all(std::option::Option::is_some))
                {
                    let (origin, event_seq) = (r.origin, r.event_seq);
                    let mut full_payload = Vec::new();
                    for chunk in r.chunks.drain(..) {
                        full_payload.extend(chunk.unwrap());
                    }
                    map.remove(&key);
                    drop(map);

                    complete_reassembled_item(
                        transport, inflight, mesh_seen, event_tx, peer_id, origin, event_seq,
                        item.hash, kind, sensitive, lamport, full_payload, outbox, outbox_stage,
                        pending_pulls, state_rx, pending_pairs,
                    )
                    .await;
                }
            } else {
                // SE-14 defense in depth: reject a single-frame item whose
                // claimed hash doesn't match its payload BEFORE acking,
                // relaying, or caching it — see `verify_content_hash`.
                if !verify_content_hash(item.kind, &item.payload, item.hash) {
                    tracing::warn!(
                        peer = ?&peer_id[..6],
                        "SE-14: dropping ClipboardItem — wire hash does not match recomputed content hash"
                    );
                    return;
                }
                // FluxMesh 2C-b: ack the sender, then ingest by EventId for mesh
                // anti-loop. Forward + apply only on first sight here; a later
                // arrival of the same id via another path is dropped (the ack
                // still goes out so the sender stops retransmitting).
                ack_source(transport, peer_id, item.hash).await;
                let eid = EventId::new(DeviceId::from(item.origin), item.event_seq);
                let first_sight = mesh_seen.lock().await.observe(eid);
                if first_sight {
                    // Resync-on-reconnect (resync-1): keep a resend copy of
                    // this first-sight item too — most clipboard items are
                    // small enough to arrive as a single `ClipboardItem`
                    // frame and never touch `complete_reassembled_item`
                    // (that path only runs for chunked/reassembled items).
                    // Outbox admission gate fix: same Pass/Ask/Block mirror as
                    // `complete_reassembled_item` — see its doc comment.
                    let mut block_relay = false;
                    if !item.sensitive {
                        let decision =
                            state_rx
                                .borrow()
                                .firewall
                                .decide(item.kind, item.sensitive, Direction::Inbound);
                        let staged = OutboxEntry {
                            payload: item.payload.clone(),
                            kind: item.kind,
                            origin: item.origin,
                            seq: item.event_seq,
                            created: Instant::now(),
                        };
                        match decision {
                            Decision::Pass => {
                                outbox.lock().await.insert(item.hash, staged);
                            }
                            Decision::Defer => {
                                // First-wins — see the identical-hash-two-
                                // peers rationale in `complete_reassembled_item`.
                                outbox_stage.lock().await.entry(item.hash).or_insert(staged);
                            }
                            Decision::Block => {
                                // Firewall-enforcing relay: see the identical
                                // gate + rationale in `complete_reassembled_item`.
                                block_relay = true;
                            }
                        }
                    }
                    if !block_relay {
                        if let Ok(bytes) = fluxsync_proto::encode(&Frame {
                            version: PROTOCOL_VERSION,
                            msg: Msg::ClipboardItem(item.clone()),
                        }) {
                            forward_item(
                                transport, inflight, pending_pairs, peer_id, item.origin,
                                item.hash, bytes,
                            )
                            .await;
                        }
                    }
                    let preview = preview_label(item.kind, &item.payload);
                    // resync-1 apply-suppression fix: same check as
                    // `complete_reassembled_item` for the chunked path — see
                    // its doc comment.
                    let resync = take_pending_pull(pending_pulls, peer_id, item.hash).await;
                    let _ = event_tx.try_send(Event::FrameReceivedClipboard {
                        hash: item.hash,
                        kind: item.kind,
                        payload: item.payload,
                        preview,
                        sensitive: item.sensitive,
                        lamport: item.lamport,
                        resync,
                        // FIX1: `peer_id` here is the direct session peer
                        // this single-frame item arrived on (see the
                        // `ack_source`-equivalent handling above).
                        peer_id,
                    });
                }
            }
        }
        Msg::Chunk(c) => {
            // [REMEDIATION] DoS Protection: Limit chunk count and concurrent reassemblies.
            // Using MAX_CHUNKS (256) instead of magic 1000 for consistency.
            if c.total > fluxsync_proto::MAX_CHUNKS || c.total == 0 {
                tracing::warn!(total=%c.total, "Rejecting Chunk: invalid total (DoS protection)");
                return;
            }

            let mut map = reassembly.lock().await;
            // Per-source namespacing (see reassembly_key): a peer can only fill
            // its own item_id's slots, never overwrite another peer's transfer.
            let key = reassembly_key(peer_id, c.item_id);

            if !map.contains_key(&key) && map.len() >= 5 {
                let oldest = map
                    .iter()
                    .min_by_key(|(_, r)| r.last_update)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest {
                    map.remove(&k);
                }
            }

            let r = map.entry(key).or_insert_with(|| Reassembly {
                metadata: None,
                origin: [0u8; 32],
                event_seq: 0,
                chunks: vec![None; c.total as usize],
                last_update: Instant::now(),
                first_seen: Instant::now(),
                source: peer_id,
                item_hash: c.item_id,
            });

            r.last_update = Instant::now();
            if r.chunks.is_empty() {
                r.chunks = vec![None; c.total as usize];
            }

            if (c.idx as usize) < r.chunks.len() {
                r.chunks[c.idx as usize] = Some(c.data);
            }

            // Check if complete
            if let Some((lamport, kind, sensitive)) = r
                .metadata
                .filter(|_| r.chunks.iter().all(std::option::Option::is_some))
            {
                let (origin, event_seq) = (r.origin, r.event_seq);
                let mut full_payload = Vec::new();
                for chunk in r.chunks.drain(..) {
                    full_payload.extend(chunk.unwrap());
                }
                map.remove(&key);
                drop(map);

                complete_reassembled_item(
                    transport, inflight, mesh_seen, event_tx, peer_id, origin, event_seq,
                    c.item_id, kind, sensitive, lamport, full_payload, outbox, outbox_stage,
                    pending_pulls, state_rx, pending_pairs,
                )
                .await;
            }
        }
        Msg::BatteryStatus(b) => {
            // FluxMesh Phase 3: record every peer's battery in the mesh meta
            // map (drives the State `peers` list), republishing on change.
            {
                let mut meta = peer_meta.lock().await;
                let e = meta.entry(peer_id).or_insert_with(PeerMeta::new);
                if e.battery != b.level || e.charging != b.charging {
                    e.battery = b.level;
                    e.charging = b.charging;
                    let _ = event_tx.try_send(Event::MeshPeersChanged);
                }
            }
            // FluxMesh 2C-b: only the primary peer's battery drives the
            // single-peer State + the battery policy. A secondary mesh peer's
            // level must not overwrite the projected peer_battery or pause the
            // whole daemon.
            if transport.cached_peer_id().await == Some(peer_id) {
                let _ = event_tx.try_send(Event::BatteryChangedPeer {
                    level: b.level,
                    charging: b.charging,
                });
            }
        }
        Msg::Heartbeat(_) => {
            // Heartbeat Received (Ping) -> Send Ack (Pong)
            tracing::debug!("Heartbeat: received ping, sending ack");
            metrics.lock().await.on_heartbeat_received();
            let frame = fluxsync_proto::Frame {
                version: fluxsync_proto::PROTOCOL_VERSION,
                msg: fluxsync_proto::Msg::Ack(fluxsync_proto::Ack {
                    lamport: 0,
                    hash: [0u8; 32],
                }),
            };
            if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                let _ = transport.send_encrypted_to(peer_id, &bytes).await;
            }
        }
        Msg::Ack(ack) => {
            metrics.lock().await.on_ack_received();
            if ack.hash == [0u8; 32] {
                // Heartbeat pong — no item to clear.
                tracing::debug!("Heartbeat: received ack (pong)");
            } else {
                // FluxMesh 2C-b: clear this peer from the item's pending set;
                // the item is removed only once every targeted peer has acked.
                let mut map = inflight.lock().await;
                if let Some(item) = map.get_mut(&ack.hash) {
                    item.pending_peers.remove(&peer_id);
                    if item.pending_peers.is_empty() {
                        map.remove(&ack.hash);
                        tracing::debug!(item = ?&ack.hash[..6], "item fully acked; retransmit cleared");
                    }
                }
            }
        }
        Msg::Nak(nak) => {
            // Peer is missing chunks of an item we sent. Resend only the
            // frames it asked for. Layout in `Inflight.frames`:
            // frames[0] = header, frames[idx + 1] = chunk `idx`.
            let mut to_send: Vec<Vec<u8>> = Vec::new();
            {
                let map = inflight.lock().await;
                if let Some(item) = map.get(&nak.item_id) {
                    if nak.want_header {
                        if let Some(header) = item.frames.first() {
                            to_send.push(header.clone());
                        }
                    }
                    for idx in &nak.missing {
                        if let Some(frame) = item.frames.get(*idx as usize + 1) {
                            to_send.push(frame.clone());
                        }
                    }
                }
            }
            if !to_send.is_empty() {
                tracing::debug!(
                    item = ?&nak.item_id[..6],
                    frames = to_send.len(),
                    "NAK: resending missing frames"
                );
                for (i, bytes) in to_send.iter().enumerate() {
                    let _ = transport.send_encrypted_to(peer_id, bytes).await;
                    // Same burst-16/pause-2ms pacing as the initial send.
                    if (i + 1) % 16 == 0 {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
                // NAK is making progress — defer the whole-item retransmit
                // so it doesn't redundantly blast every frame again. The
                // INFLIGHT_MAX_AGE backstop still bounds total lifetime.
                if let Some(item) = inflight.lock().await.get_mut(&nak.item_id) {
                    item.last_sent = Instant::now();
                }
            }
        }
        Msg::Bye => {
            // Peer announced a clean disconnect: tear down THAT peer's session.
            let is_primary = transport.cached_peer_id().await == Some(peer_id);
            if is_primary {
                // M6 fix: a clean disconnect after a genuinely stable
                // session still resets backoff (so the next reconnect isn't
                // slow); a short-lived session keeps its escalation — same
                // policy as the heartbeat-timeout path.
                let uptime = Duration::from_millis(
                    now_ms().saturating_sub(transport.session_established_at()),
                );
                backoff
                    .lock()
                    .await
                    .entry(peer_id)
                    .or_insert_with(PeerBackoff::new)
                    .on_session_ended(uptime);
            } else if let Some(established) =
                transport.session_established_at_for(peer_id).await
            {
                // M6 residual fix: a secondary (FluxMesh `extra`) peer's clean
                // disconnect gets the same stability-gated backoff reset as
                // the primary above — computed from THIS peer's own
                // established time (the primary-only `session_established_at`
                // can't see a secondary), captured before `drop_session_for`
                // below clears its session.
                let uptime = Duration::from_millis(now_ms().saturating_sub(established));
                backoff
                    .lock()
                    .await
                    .entry(peer_id)
                    .or_insert_with(PeerBackoff::new)
                    .on_session_ended(uptime);
            }
            transport.drop_session_for(peer_id).await;
            // FluxMesh Phase 3: drop it from the mesh `peers` list too.
            if peer_meta.lock().await.remove(&peer_id).is_some() {
                let _ = event_tx.try_send(Event::MeshPeersChanged);
            }
            // Session torn down: clear the echo-ack loop guard so a fresh
            // session with this peer can echo-ack again if needed.
            echo_ack_sent.lock().await.remove(&peer_id);
            // Only the primary peer drives the single FSM's PeerLost (which
            // clears State + the primary session). A secondary mesh peer
            // leaving must not disturb the primary link (FluxMesh 2C-b).
            // Robustness slice 2: if the primary said Bye but a secondary is
            // still live, fail over to it instead of disconnecting.
            if is_primary && !try_primary_failover(transport, event_tx, peer_meta).await {
                let _ = event_tx.try_send(Event::PeerLost { peer_id });
            }
        }
        Msg::Revoke => {
            // Peer manually unpaired: remove it from our trust store so we
            // don't auto-reconnect into its next TOFU window. The frame
            // arrived over the established Noise session, so the sender is
            // authenticated (peer_id is whose session decrypted it) — only its
            // own entry is removed, never the rest.
            let removed = trusted.lock().await.remove(&peer_id);
            // DIR-P2-04a: the peer that just revoked us may still have a
            // stale entry in our mDNS discovery cache (pubkey, name, addrs,
            // pairing PIN) — drop it so a cache hit can't resurrect it.
            disc_cache.lock().await.remove(&peer_id);
            // DIR-P1-02: same rationale — drop its backoff timer too.
            backoff.lock().await.remove(&peer_id);
            if removed.is_some() {
                if let Some(dir) = keystore_dir {
                    if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                        tracing::error!("Revoke: failed to persist peer removal: {e}");
                    }
                }
                tracing::info!(peer = ?&peer_id[..6], "Revoke: peer unpaired us; trust entry removed");
            }
            // FS-052 wire mutual confirm: a Revoke mid-pairing removes the
            // pending entry here, so the reaper would never fire the
            // `SasReset` for it — reset the phase now instead of leaving a
            // stale "showing"/"local_confirmed" in State.
            if pending_pairs.lock().await.remove(&peer_id).is_some() {
                let _ = event_tx.try_send(Event::SasReset);
            }
            deferred_sas_confirm.lock().await.remove(&peer_id);
            echo_ack_sent.lock().await.remove(&peer_id);
            // Bug #16 fix: the peer just revoked US, a permanent teardown —
            // purge the `extra` stub too (same rationale as `CmdOp::Revoke`).
            transport.purge_peer(peer_id).await;
            // FluxMesh Phase 3: drop it from the mesh `peers` list too.
            if peer_meta.lock().await.remove(&peer_id).is_some() {
                let _ = event_tx.try_send(Event::MeshPeersChanged);
            }
            // Primary-only PeerLost, as for Bye — a secondary peer revoking us
            // tears down only its own link (FluxMesh 2C-b). Robustness slice 2:
            // fail over to a live secondary before declaring the link lost.
            if transport.cached_peer_id().await == Some(peer_id)
                && !try_primary_failover(transport, event_tx, peer_meta).await
            {
                let _ = event_tx.try_send(Event::PeerLost { peer_id });
            }
        }
        Msg::HandshakeInit(_) | Msg::HandshakeResp(_) => {
            // Handshake frames are driven by the handshake task, not here.
        }
        Msg::Hello(h) => {
            // DIR-P1-01: negotiate the working capability set as the
            // intersection of what the peer sent and what this build
            // understands. Anything neither side recognizes is silently
            // dropped — logged at DEBUG, never a reason to refuse the Hello
            // or tear down the session.
            let caps = negotiate_caps(&h.caps);
            for c in &h.caps {
                if !SUPPORTED_CAPS.contains(&c.as_str()) {
                    tracing::debug!(peer = ?&peer_id[..6], cap = %c, "ignoring unknown Hello capability");
                }
            }
            // FluxMesh Phase 3: record every peer's name/platform in the mesh
            // meta map (drives the State `peers` list), republishing on change.
            {
                let mut meta = peer_meta.lock().await;
                let e = meta.entry(peer_id).or_insert_with(PeerMeta::new);
                let mut changed = false;
                if e.name != h.name {
                    e.name.clone_from(&h.name);
                    changed = true;
                }
                if !h.platform.is_empty() && e.platform != h.platform {
                    e.platform.clone_from(&h.platform);
                    changed = true;
                }
                if e.caps != caps {
                    e.caps.clone_from(&caps);
                    changed = true;
                }
                // FS-052 wire mutual confirm: from here on, `caps` is real
                // negotiated data, not "Hello not seen yet".
                e.hello_seen = true;
                if changed {
                    let _ = event_tx.try_send(Event::MeshPeersChanged);
                }
            }
            // FS-052 wire mutual confirm: now that the peer's caps are known,
            // resolve the two Hello-dependent cases for a fresh-pair peer
            // (identified by a live `PendingPair` entry or a deferred local
            // accept — an already-confirmed reconnect has neither, so it
            // never enters the SAS states here).
            {
                let peer_supports_sas = caps.iter().any(|c| c == "sas-confirm");
                let has_pending = pending_pairs.lock().await.contains_key(&peer_id);
                let had_deferred = deferred_sas_confirm.lock().await.remove(&peer_id);
                // A deferred accept is only flushable while no NEW pending
                // pair exists for this peer: a live pending entry means a
                // fresh pairing (with fresh SAS words) superseded the earlier
                // confirm, so replaying it would confirm words the local
                // human never compared.
                let flush_deferred = had_deferred && !has_pending;
                let is_fresh_pair = had_deferred || has_pending;
                if is_fresh_pair {
                    if peer_supports_sas {
                        // The local user accepted before this Hello arrived —
                        // flush the deferred Msg::PairConfirm{accept:true} now.
                        if flush_deferred {
                            let frame = Frame {
                                version: PROTOCOL_VERSION,
                                msg: Msg::PairConfirm(fluxsync_proto::PairConfirm {
                                    accept: true,
                                }),
                            };
                            if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                                if let Err(e) =
                                    transport.send_encrypted_to(peer_id, &bytes).await
                                {
                                    tracing::warn!(
                                        peer = ?&peer_id[..6],
                                        error = %e,
                                        "sas-confirm: deferred PairConfirm send failed"
                                    );
                                }
                            }
                        }
                    } else {
                        // Legacy peer (no `sas-confirm` cap): treat it as
                        // having confirmed, so this build never waits forever
                        // on an old one. The app moves sas_phase to
                        // "confirmed" if the local user already confirmed,
                        // "peer_confirmed" otherwise.
                        tracing::info!(
                            peer = ?&peer_id[..6],
                            "sas-confirm: peer is a legacy build — treating as confirmed"
                        );
                        let _ = event_tx.try_send(Event::SasPeerConfirmed { peer_id });
                    }
                }
            }
            // verify-restart: this side holds a fresh TOFU pending for the
            // peer (its handshake just landed through our pairing window),
            // so OUR human is being shown 6 SAS words. If the peer trusted
            // us from a previous pairing, it reconnected SILENTLY (the
            // already-confirmed path never opens a verify screen) and its
            // human sees nothing — the verbal compare would be theater.
            // Announce the fresh pairing so a `verify-restart` peer re-opens
            // its own verify screen with the same words (derived on its side
            // from the shared Noise transcript hash). Guarded once per
            // session via `PeerMeta.verify_restart_sent` — Hello arrives
            // once per honest session, but a duplicate/malicious re-Hello
            // must not re-announce.
            {
                let has_pending = pending_pairs.lock().await.contains_key(&peer_id);
                let peer_supports_verify_restart =
                    caps.iter().any(|c| c == "verify-restart");
                if has_pending && peer_supports_verify_restart {
                    let first_announce = {
                        let mut meta = peer_meta.lock().await;
                        let e = meta.entry(peer_id).or_insert_with(PeerMeta::new);
                        if e.verify_restart_sent {
                            false
                        } else {
                            e.verify_restart_sent = true;
                            true
                        }
                    };
                    if first_announce {
                        tracing::info!(
                            peer = ?&peer_id[..6],
                            "verify-restart: announcing fresh pairing so the peer re-opens its verify screen"
                        );
                        let frame = Frame {
                            version: PROTOCOL_VERSION,
                            msg: Msg::PairVerifyStarted,
                        };
                        if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                            if let Err(e) = transport.send_encrypted_to(peer_id, &bytes).await {
                                tracing::warn!(
                                    peer = ?&peer_id[..6],
                                    error = %e,
                                    "verify-restart: PairVerifyStarted send failed"
                                );
                            }
                        }
                    }
                }
            }
            // resync-1: offer our outbox to this peer once negotiated. Hello
            // arrives exactly once per session establishment (rekey never
            // re-sends it), so this can't spam a peer with repeated offers.
            //
            // FS-052 egress hole fix: never offer cached clipboard content to
            // a peer that completed TOFU but hasn't been verbally confirmed
            // yet — the offer itself doesn't carry plaintext, but it starts a
            // ResyncPull round-trip that would otherwise hand one over.
            let is_pending = pending_pairs.lock().await.contains_key(&peer_id);
            if !is_pending && caps.iter().any(|c| c == "resync-1") {
                let hashes = outbox.lock().await.hashes();
                if !hashes.is_empty() {
                    let offer = build_resync_offer(&hashes);
                    tracing::info!(
                        peer = ?&peer_id[..6],
                        count = offer.hashes.len(),
                        "resync-1: sending ResyncOffer"
                    );
                    let frame = Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::ResyncOffer(offer),
                    };
                    if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                        let _ = transport.send_encrypted_to(peer_id, &bytes).await;
                    }
                }
            }
            // peer_id is whoever's session decrypted this Hello — always the
            // real id, no all-zero sentinel that would bypass the FSM
            // peer-mismatch check. FluxMesh 2C-b: only the primary peer's
            // identity is projected into the single-peer State DTO; secondary
            // mesh peers sync clipboard but are not shown (clients stay
            // single-peer-compatible).
            if transport.cached_peer_id().await == Some(peer_id) {
                let _ = event_tx.try_send(Event::PeerSeen {
                    peer_id,
                    name: h.name,
                });
                if !h.platform.is_empty() {
                    let _ = event_tx.try_send(Event::PeerPlatform {
                        platform: h.platform,
                    });
                }
                let _ = event_tx.try_send(Event::PeerCaps { caps });
            }
        }
        Msg::ResyncOffer(offer) => {
            if !resync_authorized(transport, peer_meta, peer_id).await {
                tracing::debug!(
                    peer = ?&peer_id[..6],
                    "resync-1: ignoring ResyncOffer (peer not linked or cap not negotiated)"
                );
                return;
            }
            let history_hashes: Vec<String> = state_rx
                .borrow()
                .history
                .iter()
                .map(|h| h.hash.clone())
                .collect();
            let outbox_hashes: Vec<String> =
                outbox.lock().await.hashes().iter().map(hex::encode).collect();
            // H2 fix: exclude anything we deliberately cleared via
            // `CmdOp::ClearHistory` — a peer's outbox is not told about a
            // local clear (by design), so without this a cleared item would
            // silently resurrect the moment that peer re-offers it.
            let cleared_hashes = cleared_hex_snapshot(cleared_tombstone).await;
            let pending_pull_hashes = in_flight_pull_hashes(pending_pulls).await;
            let missing = missing_resync_hashes(
                &offer.hashes,
                &history_hashes,
                &outbox_hashes,
                &cleared_hashes,
                &pending_pull_hashes,
            );
            if !missing.is_empty() {
                tracing::info!(
                    peer = ?&peer_id[..6],
                    count = missing.len(),
                    "resync-1: sending ResyncPull"
                );
                // resync-1 apply-suppression fix (DEFECT 1): remember every
                // hash we're about to ask this peer for, so when it comes
                // back as an ordinary ClipboardItem/Chunk we recognise it as
                // catch-up bookkeeping rather than a fresh copy — see
                // `PendingPulls` and `take_pending_pull`. Malformed hex (the
                // codec already bounds the string shape/count, but a corrupt
                // entry would still fail `decode_hex32`) is skipped rather
                // than tracked, matching `Msg::ResyncPull`'s own handling.
                {
                    let now = Instant::now();
                    let mut map = pending_pulls.lock().await;
                    let per_peer = map.entry(peer_id).or_default();
                    for hex_hash in &missing {
                        if let Ok(hash) = decode_hex32(hex_hash) {
                            per_peer.insert(hash, now);
                        }
                    }
                }
                let frame = Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::ResyncPull(ResyncPull { hashes: missing }),
                };
                if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                    let _ = transport.send_encrypted_to(peer_id, &bytes).await;
                }
            }
        }
        Msg::ResyncPull(pull) => {
            if !resync_authorized(transport, peer_meta, peer_id).await {
                tracing::debug!(
                    peer = ?&peer_id[..6],
                    "resync-1: ignoring ResyncPull (peer not linked or cap not negotiated)"
                );
                return;
            }
            tracing::info!(
                peer = ?&peer_id[..6],
                count = pull.hashes.len(),
                "resync-1: received ResyncPull"
            );
            let mut served = 0usize;
            for hex_hash in pull.hashes.iter().take(MAX_RESYNC_HASHES) {
                let Ok(hash) = decode_hex32(hex_hash) else {
                    tracing::debug!(peer = ?&peer_id[..6], "resync-1: malformed hash in ResyncPull, skipping");
                    continue;
                };
                let Some(entry) = outbox.lock().await.get(hash).cloned() else {
                    // Not (or no longer) held — silently skip, no error.
                    continue;
                };
                // Resync serve firewall gate: a policy tightened to Block
                // AFTER this item was admitted must not be bypassed just
                // because it still sits in the outbox cache — re-check the
                // LIVE firewall before serving it, same `decide()` call
                // `gate_outbound`/admission use elsewhere in this file.
                let decision = state_rx
                    .borrow()
                    .firewall
                    .decide(entry.kind, false, Direction::Outbound);
                if decision != Decision::Pass {
                    tracing::debug!(
                        peer = ?&peer_id[..6],
                        ?decision,
                        "resync-1: skipping cached entry — firewall no longer passes it"
                    );
                    continue;
                }
                // Lamport 0: `Entry` doesn't retain the original tick, and 0
                // is a safe no-op for the receiver's `LamportClock::observe`
                // (it only ever advances the clock forward via `max`).
                let frames =
                    build_item_frames(0, hash, entry.kind, &entry.payload, false, entry.origin, entry.seq);
                if frames.is_empty() {
                    continue;
                }
                let multi = frames.len() > 1;
                for (i, bytes) in frames.iter().enumerate() {
                    let _ = transport.send_encrypted_to(peer_id, bytes).await;
                    if multi && (i + 1) % 16 == 0 {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
                // Inflight merge fix: `inflight` is keyed by hash only. A
                // blind `insert` here would REPLACE any entry already
                // tracking OTHER peers still awaiting an ack for this same
                // hash (from a concurrent live `SendItem`/`forward_frames`
                // fan-out), silently dropping them from `pending_peers` so
                // they'd never get a retransmit. Merge instead: if an entry
                // exists, fold this peer into its `pending_peers` and refresh
                // the resend copy; only insert fresh when none exists.
                match inflight.lock().await.entry(hash) {
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        let inf = e.get_mut();
                        inf.pending_peers.insert(peer_id);
                        inf.frames = frames;
                        inf.last_sent = Instant::now();
                    }
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(Inflight {
                            frames,
                            attempts: 0,
                            last_sent: Instant::now(),
                            first_sent: Instant::now(),
                            pending_peers: std::iter::once(peer_id).collect(),
                        });
                    }
                }
                metrics.lock().await.on_item_resynced();
                served += 1;
            }
            if served > 0 {
                tracing::info!(
                    peer = ?&peer_id[..6],
                    count = served,
                    "resync-1: served ResyncPull"
                );
            }
        }
        Msg::PairConfirm(pc) => {
            // FS-052 wire mutual confirm (`sas-confirm` capability). The
            // frame arrived over the established Noise session, so the
            // sender is authenticated — it can only resolve its OWN pairing.
            if pc.accept {
                // Peer's human confirmed the 6 SAS words. If our own pending
                // entry still exists, give the local human one natural
                // refresh of the 90s window — the peer side is engaged, so
                // the local user deserves the full window to compare words
                // instead of whatever remained of the original one.
                let had_pending = {
                    let mut g = pending_pairs.lock().await;
                    if let Some(p) = g.get_mut(&peer_id) {
                        p.expires_at = Instant::now() + handshake::PAIRING_WINDOW;
                        true
                    } else {
                        false
                    }
                };
                // Only move sas_phase while a SAS flow is actually live —
                // our own pending entry, or the local user already confirmed
                // (pending removed, phase advanced). An accept landing on an
                // idle reconnect (e.g. a peer flushing a deferred confirm
                // from a long-finished pairing) must NOT drag an
                // already-trusted link back into the SAS states. L3 fix:
                // peer-scoped via `sas_peer`, not just "some SAS flow is
                // live somewhere" — otherwise a confirm from a DIFFERENT
                // peer than the one `sas_phase` is currently tracking would
                // wrongly count as live and stomp that other pairing's UI.
                let in_sas_flow = {
                    let s = state_rx.borrow();
                    s.sas_peer == Some(peer_id)
                        && matches!(
                            s.sas_phase.as_str(),
                            "showing" | "local_confirmed" | "peer_confirmed" | "confirmed"
                        )
                };
                if had_pending || in_sas_flow {
                    tracing::info!(
                        peer = ?&peer_id[..6],
                        "sas-confirm: peer confirmed the pairing"
                    );
                    let _ = event_tx.try_send(Event::SasPeerConfirmed { peer_id });
                } else {
                    // Asymmetric-trust echo-ack. This accept landed with no
                    // live SAS flow on our side (no pending entry, no active
                    // sas_phase for this peer) — ordinarily a stray/late
                    // confirm to ignore. But this is exactly what happens
                    // when the OTHER side revoked-and-reconnected while WE
                    // still trust it: `CmdOp::PairFromUri` on our reconnect
                    // took the silent-reconnect path (already-trusted,
                    // no pending pair), so we never opened a SAS flow at
                    // all — yet the peer's human just verbally confirmed
                    // the pairing on their end and is waiting on us. Left
                    // unanswered, their pending entry sits until the 90s
                    // reaper fires and revokes OUR trust, breaking a link
                    // that was never actually compromised.
                    //
                    // Security rationale: the frame decrypted under this
                    // peer_id (= BLAKE3(static_pub)) over the established
                    // Noise session, which only the holder of the matching
                    // private key could complete — our trust entry already
                    // pins that exact static key. So "sender authenticated
                    // + sender is in our trusted store" together stand in
                    // for a fresh human confirmation: a prior completed
                    // verification still holds because the key has not
                    // changed. The echo below asserts "already verified,
                    // key unchanged", not a new SAS comparison — it is only
                    // sent to peers that negotiated `sas-confirm` (so we
                    // know they understand the message), and at most once
                    // per peer per session (guarded by `echo_ack_sent`) so
                    // a malformed/hostile peer resending PairConfirm can't
                    // turn this into an unbounded ping-pong.
                    let is_trusted = trusted.lock().await.contains_key(&peer_id);
                    let supports_sas = peer_meta
                        .lock()
                        .await
                        .get(&peer_id)
                        .is_some_and(|m| m.caps.iter().any(|c| c == "sas-confirm"));
                    if is_trusted && supports_sas {
                        let newly_acked = echo_ack_sent.lock().await.insert(peer_id);
                        if newly_acked {
                            tracing::info!(
                                peer = ?&peer_id[..6],
                                "sas-confirm: echoing accept back to an already-trusted peer \
                                 with no live SAS flow on our side (asymmetric-trust reconnect)"
                            );
                            let frame = Frame {
                                version: PROTOCOL_VERSION,
                                msg: Msg::PairConfirm(fluxsync_proto::PairConfirm {
                                    accept: true,
                                }),
                            };
                            if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                                if let Err(e) =
                                    transport.send_encrypted_to(peer_id, &bytes).await
                                {
                                    tracing::warn!(
                                        peer = ?&peer_id[..6],
                                        error = %e,
                                        "sas-confirm: echo-ack send failed"
                                    );
                                }
                            }
                        } else {
                            tracing::debug!(
                                peer = ?&peer_id[..6],
                                "sas-confirm: already echoed an accept to this peer this \
                                 session; not repeating (loop guard)"
                            );
                        }
                    } else {
                        tracing::debug!(
                            peer = ?&peer_id[..6],
                            "sas-confirm: ignoring PairConfirm(accept) outside a SAS flow"
                        );
                    }
                }
            } else {
                // Peer's human explicitly rejected — same effect as a local
                // reject: purge pending + trust (+ discovery/backoff/deferred
                // residue), persist, and tear the session down.
                tracing::warn!(
                    peer = ?&peer_id[..6],
                    "sas-confirm: peer REJECTED the pairing; revoking trust"
                );
                // L3 fix: captured for the SAME peer-scoped guard the accept
                // branch uses below — trust/session teardown stays
                // unconditional (an authenticated peer's explicit reject
                // always revokes it, live SAS flow or not); only whether we
                // report it as THIS pairing's verdict is gated, so a
                // stray/already-trusted peer's reject can't stomp a
                // DIFFERENT, in-progress pairing's UI.
                let had_pending = pending_pairs.lock().await.remove(&peer_id).is_some();
                deferred_sas_confirm.lock().await.remove(&peer_id);
                echo_ack_sent.lock().await.remove(&peer_id);
                let removed = trusted.lock().await.remove(&peer_id);
                disc_cache.lock().await.remove(&peer_id);
                backoff.lock().await.remove(&peer_id);
                if removed.is_some() {
                    if let Some(dir) = keystore_dir {
                        if let Err(e) = save_peers_with_retry(dir, trusted, transport).await {
                            tracing::error!(
                                "sas-confirm: failed to persist peer removal after reject: {e}"
                            );
                        }
                    }
                }
                // Bug #16 fix: the peer just rejected the pairing, a
                // permanent teardown — purge the `extra` stub too (same
                // rationale as `CmdOp::Revoke`).
                transport.purge_peer(peer_id).await;
                if peer_meta.lock().await.remove(&peer_id).is_some() {
                    let _ = event_tx.try_send(Event::MeshPeersChanged);
                }
                // Surface "peer_rejected" BEFORE the PeerLost teardown so a
                // state subscriber never sees a disconnect with a stale
                // "showing"/"local_confirmed" phase in between. Same
                // peer-scoped guard as the accept branch (L3 fix).
                let in_sas_flow = {
                    let s = state_rx.borrow();
                    s.sas_peer == Some(peer_id)
                        && matches!(
                            s.sas_phase.as_str(),
                            "showing" | "local_confirmed" | "peer_confirmed" | "confirmed"
                        )
                };
                if had_pending || in_sas_flow {
                    let _ = event_tx.try_send(Event::SasPeerRejected { peer_id });
                } else {
                    tracing::debug!(
                        peer = ?&peer_id[..6],
                        "sas-confirm: reject outside a SAS flow — trust still revoked, \
                         but not reported as this pairing's verdict"
                    );
                }
                if transport.cached_peer_id().await == Some(peer_id)
                    && !try_primary_failover(transport, event_tx, peer_meta).await
                {
                    let _ = event_tx.try_send(Event::PeerLost { peer_id });
                }
            }
        }
        Msg::PairVerifyStarted => {
            // verify-restart: the peer just accepted us via a fresh TOFU —
            // its side holds a pending pair and is showing 6 SAS words —
            // while WE reconnected silently as already-trusted (e.g. the
            // peer was reset and we rescanned its QR). Re-open our own
            // verify screen so the human comparison is real on both ends:
            // derive the same 6 words from the shared Noise transcript hash
            // (identical on both sides of one handshake — see
            // `fingerprint_from_handshake_hash`) and insert a REAL pending
            // pair, which also re-arms the FS-052 clipboard gate for this
            // peer until our human confirms. Guards:
            //  * sender must be in our trusted store — the frame decrypted
            //    under its pinned static key, so an untrusted stranger can
            //    never conjure a verify screen;
            //  * no existing pending / live SAS flow for it — a fresh
            //    pairing of our own is already showing the right words, so
            //    a (duplicate or malicious) announcement must not reset it.
            let trusted_entry = trusted
                .lock()
                .await
                .get(&peer_id)
                .map(|p| (p.static_pub, p.name.clone()));
            let Some((static_pub, name)) = trusted_entry else {
                tracing::debug!(
                    peer = ?&peer_id[..6],
                    "verify-restart: ignoring PairVerifyStarted from untrusted peer"
                );
                return;
            };
            let already_pending = pending_pairs.lock().await.contains_key(&peer_id);
            let in_sas_flow = {
                let s = state_rx.borrow();
                s.sas_peer == Some(peer_id)
                    && matches!(
                        s.sas_phase.as_str(),
                        "showing" | "local_confirmed" | "peer_confirmed" | "confirmed"
                    )
            };
            if already_pending || in_sas_flow {
                tracing::debug!(
                    peer = ?&peer_id[..6],
                    "verify-restart: ignoring PairVerifyStarted — a SAS flow for this peer is already live"
                );
                return;
            }
            let Some(hash) = transport.session_handshake_hash_for(peer_id).await else {
                tracing::warn!(
                    peer = ?&peer_id[..6],
                    "verify-restart: no live session hash for PairVerifyStarted sender; ignoring"
                );
                return;
            };
            let sas_words: [String; 6] =
                fluxsync_crypto::fingerprint_from_handshake_hash(&hash)
                    .map(std::string::ToString::to_string);
            let from = transport.peer_addr_for(peer_id).await;
            {
                // Same FS-058 hygiene as `run_initiator`/`run_responder`'s
                // inserts: sweep expired entries, then hard-cap by evicting
                // the soonest-to-expire one.
                let mut pending_guard = pending_pairs.lock().await;
                let now = Instant::now();
                pending_guard.retain(|_, p| p.expires_at > now);
                if pending_guard.len() >= handshake::MAX_PENDING_PAIRS {
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
                    handshake::PendingPair {
                        static_pub,
                        name,
                        sas_words,
                        // Fall back to an unspecified addr if the transport
                        // has no live route entry (shouldn't happen for an
                        // authenticated sender) — `from` is display-only.
                        from: from.unwrap_or_else(|| {
                            SocketAddr::from(([0, 0, 0, 0], 0))
                        }),
                        expires_at: now + handshake::PAIRING_WINDOW,
                    },
                );
            }
            tracing::info!(
                peer = ?&peer_id[..6],
                "verify-restart: peer re-paired fresh; re-opening our verify screen"
            );
            let _ = event_tx.try_send(Event::SasPairingStarted { peer_id });
        }
    }
}

struct Reassembly {
    metadata: Option<(u64, Kind, bool)>,
    /// FluxMesh robustness slice 3: the header's EventId, kept so a completed
    /// chunked item can be anti-loop-gated and relayed across a third hop with
    /// the SAME identity (set in the header arm; meaningful once metadata Some).
    origin: [u8; 32],
    event_seq: u64,
    chunks: Vec<Option<Vec<u8>>>,
    last_update: Instant,
    first_seen: Instant,
    /// The direct sender of this hop's frames (namespaces `reassembly_key`
    /// alongside `item_hash`). A selective NAK must go back to whoever is
    /// actually retransmitting this transfer — the primary link otherwise —
    /// so this is never assumed to equal the mesh `origin` above.
    source: [u8; 32],
    /// The real wire content hash (`ClipboardItem.hash` / `Chunk.item_id`),
    /// as opposed to `reassembly_key(source, item_hash)` — the composite
    /// digest used only as this map's key. A `Nak` must carry THIS value:
    /// the sender's `inflight` is keyed by content hash and can never match
    /// the composite digest.
    item_hash: [u8; 32],
}

/// Selective NAK: for every chunked transfer still in `reassembly` with at
/// least one missing chunk (or an unseen header), build the `Nak` to ask for
/// exactly those pieces, paired with the peer that must receive it — the
/// transfer's direct sender (`Reassembly::source`), not assumed to be the
/// primary link. Factored out of `transport_recv_loop`'s `nak_interval` tick
/// so it's unit-testable without a live transport.
fn build_pending_naks(map: &HashMap<[u8; 32], Reassembly>) -> Vec<([u8; 32], fluxsync_proto::Nak)> {
    let mut naks = Vec::new();
    for r in map.values() {
        if r.chunks.is_empty() {
            // Only a header (or nothing) seen so far — total unknown,
            // nothing concrete to ask for.
            continue;
        }
        let missing: Vec<u16> = r
            .chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| c.is_none())
            .map(|(i, _)| i as u16)
            .take(NAK_MISSING_PER_FRAME)
            .collect();
        let want_header = r.metadata.is_none();
        if missing.is_empty() && !want_header {
            continue;
        }
        naks.push((
            r.source,
            fluxsync_proto::Nak {
                item_id: r.item_hash,
                want_header,
                missing,
            },
        ));
    }
    naks
}

/// An outbound clipboard item awaiting the peer's `Msg::Ack`. Frames are
/// stored already-encoded so the retransmit timer can re-send them
/// verbatim until the ack lands or `MAX_RETRANSMIT` attempts elapse.
/// This is the only delivery guarantee on the UDP path — without it a
/// dropped datagram silently loses the item.
struct Inflight {
    frames: Vec<Vec<u8>>,
    attempts: u8,
    last_sent: Instant,
    /// When the item was first queued. Selective-NAK resends keep
    /// `last_sent` perpetually fresh, which defers the `attempts`-based
    /// whole-item retransmit forever — so this is the backstop that
    /// drops an item that never converges. See `INFLIGHT_MAX_AGE`.
    first_sent: Instant,
    /// FluxMesh 2C-b: peers this item still awaits an Ack from. An item
    /// (locally copied or relayed) is fanned out to every linked peer; each
    /// peer's Ack removes it from this set, and the item is cleared only
    /// when the set empties. Retransmits go to whoever is still pending.
    pending_peers: HashSet<[u8; 32]>,
}

/// Map of clipboard items sent but not yet acked, keyed by item hash.
type InflightMap = Arc<Mutex<HashMap<[u8; 32], Inflight>>>;

/// Resync-on-reconnect (resync-1): shared resend buffer of recent
/// non-sensitive items, written on send/first-sight-receive and read to
/// build a `ResyncOffer` / serve a `ResyncPull`. See `crate::outbox`.
type SharedOutbox = Arc<Mutex<Outbox>>;

/// Resync-on-reconnect (resync-1) apply-suppression bug fix: hashes WE asked
/// a peer for via `ResyncPull`, keyed first by that peer's id then by content
/// hash, each with the instant we asked. When the matching `ClipboardItem`/
/// `Chunk` completes, this lets the receive path recognise "this is catch-up
/// bookkeeping I requested" — history/vault/relay/ack proceed as usual, but
/// the OS clipboard must not be silently overwritten with stale content on
/// the user's behalf (see `Event::FrameReceivedClipboard.resync` and
/// `App::handle`'s post-transition strip). Entries are consumed on arrival
/// (`take_pending_pull`) and lazily swept past `RESYNC_PULL_TIMEOUT` so a
/// pull that never gets served (peer dropped the item, e.g. it expired from
/// their outbox between offer and pull) doesn't wedge a stale entry forever.
/// Deliberately explicit tracking — never inferred from Lamport tick (0 on
/// resync sends) or item age, both of which a legitimate item can also have.
type PendingPulls = Arc<Mutex<HashMap<[u8; 32], HashMap<[u8; 32], Instant>>>>;

/// Outbox admission gate: `OutboxEntry`s staged for an inbound item the
/// firewall parked under `Ask`, keyed by content hash, awaiting
/// `CmdOp::ResolvePending`. Never touched for a `Pass` (inserted straight
/// into `SharedOutbox`) or a `Block` (dropped, nothing staged) — see
/// `complete_reassembled_item` / `dispatch_inbound_frame`. An entry here is
/// always resolved one way or another by the same `ResolvePending` that
/// resolves the matching `fluxsync_core::State.pending` row, so this never
/// outlives the user's decision; a security wipe additionally clears it
/// alongside `SharedOutbox` (see the `vault_wipe_gen` handling in `run()`).
///
/// `(origin, seq)` ordering note: an inbound item's `origin`/`event_seq` are
/// wire-carried, sender-assigned values (the origin device's own monotonic
/// counter) — they identify the ORIGINATING event, not this device's
/// admission of it, so they are captured unmodified at receive time and
/// preserved as-is through staging to promotion; there is nothing to
/// reassign at admission time. The outbound side is the mirror image and
/// needed no change: `next_local_event_id()` is only called inside
/// `dispatch`'s `Action::SendItem` arm, which for an `Ask`-deferred push
/// already only fires once `ResolvePending{allow: true}` re-emits it — i.e.
/// outbound seq allocation already happens at admission time, not at the
/// original (parked) push.
type PendingOutboxStage = Arc<Mutex<HashMap<[u8; 32], OutboxEntry>>>;

/// How long a `ResyncPull` we sent stays "pending" before we give up
/// expecting it and would treat a same-hash arrival as a fresh item instead.
const RESYNC_PULL_TIMEOUT: Duration = Duration::from_secs(60);

/// Consume a pending resync pull for `hash` from `peer_id`, if one is still
/// outstanding and fresh. Also lazily sweeps every other stale entry for that
/// peer (`RESYNC_PULL_TIMEOUT` old) so the bounded map never accumulates
/// pulls that were never served.
async fn take_pending_pull(pending_pulls: &PendingPulls, peer_id: [u8; 32], hash: [u8; 32]) -> bool {
    let mut map = pending_pulls.lock().await;
    let Some(per_peer) = map.get_mut(&peer_id) else {
        return false;
    };
    per_peer.retain(|_, asked_at| asked_at.elapsed() < RESYNC_PULL_TIMEOUT);
    let found = per_peer.remove(&hash).is_some();
    if per_peer.is_empty() {
        map.remove(&peer_id);
    }
    found
}

/// FluxMesh 2C-b: shared mesh anti-loop guard. Keyed on `EventId`
/// (origin + sequence), it records every item already relayed/applied at
/// this node so a fan-out that arrives via two paths is forwarded exactly
/// once and never loops. Independent of the per-`App` content-hash
/// `DedupRing` (which guards the OS-clipboard *apply*).
type MeshSeen = Arc<Mutex<SeenSet>>;

/// FluxMesh Phase 3: per-peer UI metadata (name/platform/battery) captured
/// from EVERY linked peer's Hello/Battery — including the secondaries the
/// single-peer State projection ignores. The `State.peers` list is rebuilt at
/// each `EmitState` by joining this with the live session set
/// (`linked_peer_ids`), so an entry here that lost its session never shows.
#[derive(Debug, Clone)]
struct PeerMeta {
    name: String,
    platform: String,
    /// DIR-P1-01: negotiated capability set for this peer (intersection of
    /// their `Hello.caps` with `SUPPORTED_CAPS`).
    caps: Vec<String>,
    battery: u8,
    charging: bool,
    /// FS-052 wire mutual confirm: true once this peer's `Msg::Hello` has
    /// been processed at least once, so `caps` (possibly empty) is known
    /// to be real negotiated data rather than "not seen yet". Lets
    /// `CmdOp::PairConfirm` tell "peer caps unknown, defer the wire send"
    /// apart from "peer caps known and empty/legacy".
    hello_seen: bool,
    /// verify-restart: true once this session has announced its fresh
    /// pending pair to the peer via `Msg::PairVerifyStarted`, so a repeated
    /// (or malicious duplicate) `Hello` can't re-send it. `PeerMeta` is
    /// dropped on session teardown (Bye/Revoke/reject), which is exactly
    /// the "once per session" lifetime the announcement needs.
    verify_restart_sent: bool,
}

impl PeerMeta {
    /// Battery defaults to the 255 "unknown" sentinel so a peer seen via Hello
    /// before its first `BatteryStatus` renders "—", not a fake 100%. 255 is
    /// also safe for the Critical check (255 <= 5 is false).
    fn new() -> Self {
        Self {
            name: String::new(),
            platform: String::new(),
            caps: Vec::new(),
            battery: 255,
            charging: false,
            hello_seen: false,
            verify_restart_sent: false,
        }
    }
}

type PeerMetaMap = Arc<Mutex<BTreeMap<[u8; 32], PeerMeta>>>;

/// Build the `State.peers` list from the live session set joined with the
/// captured per-peer metadata. Only peers with a live session appear, so a
/// torn-down link never lingers as a ghost. `primary` flags the peer the
/// single-peer `State.peer_*` fields project.
async fn build_peers(
    transport: &Transport,
    peer_meta: &PeerMetaMap,
    primary: Option<[u8; 32]>,
) -> Vec<PeerInfo> {
    let ids = transport.linked_peer_ids().await;
    let meta = peer_meta.lock().await;
    ids.into_iter()
        .map(|id| {
            let m = meta.get(&id);
            PeerInfo {
                peer_id: id,
                name: m.map(|m| m.name.clone()).unwrap_or_default(),
                platform: m.map(|m| m.platform.clone()).unwrap_or_default(),
                battery: m.map_or(255, |m| m.battery), // 255 = unknown → UI "—"
                charging: m.is_some_and(|m| m.charging),
                primary: Some(id) == primary,
                caps: m.map(|m| m.caps.clone()).unwrap_or_default(),
            }
        })
        .collect()
}

/// Wait this long for an ack before re-sending an inflight item.
const RETRANSMIT_INTERVAL: Duration = Duration::from_secs(2);
/// Drop the item after this many re-sends with no ack.
const MAX_RETRANSMIT: u8 = 6;
/// Absolute lifetime cap for an inflight item. Selective-NAK resends bump
/// `last_sent`, so the `attempts`/`MAX_RETRANSMIT` path can be deferred
/// indefinitely while a transfer slowly progresses; this is the hard
/// backstop that frees the buffer if it simply never converges.
const INFLIGHT_MAX_AGE: Duration = Duration::from_secs(90);
/// How often the receiver emits a selective NAK for an incomplete
/// chunked transfer still in reassembly.
const NAK_INTERVAL: Duration = Duration::from_millis(700);
/// Cap on chunk indices a single NAK asks for — kept under
/// `fluxsync_proto::MAX_NAK_MISSING` (512) so the encoded NAK fits one
/// datagram. Remaining gaps are picked up by the next NAK tick.
const NAK_MISSING_PER_FRAME: usize = 400;

// ─────────────────────────────────────────────────────────────────
// mDNS discovery dispatcher
// ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn discovery_dispatcher(
    mut rx: mpsc::Receiver<DiscoveryEvent>,
    identity: Identity,
    trusted: TrustedSet,
    transport: Arc<Transport>,
    pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: mpsc::Sender<Event>,
    disc_cache: DiscoveryCache,
    backoff: BackoffMap,
    // Item 4 (secondary redial): boot-time `peers.json` `last_addr` per
    // trusted peer id — the fallback candidate address for a SECONDARY
    // that has never held a session on `transport` this boot (so its
    // per-peer `roaming_history_snapshot_for` is still empty).
    persisted_peer_addrs: Arc<HashMap<[u8; 32], SocketAddr>>,
    keystore_dir: Option<PathBuf>,
    shutdown: CancellationToken,
) -> Result<()> {
    // DIR-P1-02: polled at the initial-backoff granularity (see
    // `backoff::INITIAL_BASE`), not the redial cadence itself — actual
    // dial pacing is governed by `PeerBackoff::ready` below. Checking
    // this often is cheap (in-memory lock reads only, no I/O unless a
    // dial is actually due) and matches the clipboard watcher's own
    // 200ms poll elsewhere in this file.
    //
    // last_addr redial: the first tick is deliberately delayed (rather
    // than firing immediately, `tokio::time::interval`'s default) so a
    // fresh boot gives any imminent EXPLICIT reconnect command (PairAccept
    // / PairFromUri / PairFromPin — e.g. a CLI-driven manual redial issued
    // right after the IPC socket comes up) first claim on the single
    // in-flight initiator slot (`pending_initiator_tx`), rather than
    // racing it. Purely a fairness/ordering nicety: if nothing else claims
    // the slot, this blind proactive redial still engages a few seconds
    // later, which is negligible against the reconnect timescales already
    // in play (heartbeat timeout alone is ~9s). Does not affect the
    // separate, event-driven `DiscoveryEvent::Resolved` redial path below,
    // which reacts immediately regardless of this timer.
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(2),
        Duration::from_millis(200),
    );
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                // PROACTIVE PROBE: If no session, try the last known peer
                let has_session = transport.has_session().await;
                if !has_session {
                    let addr_opt = transport.cached_peer_addr().await;
                    let id_opt = transport.cached_peer_id().await;

                    if let (Some(_addr), Some(id)) = (addr_opt, id_opt) {
                        let peer_opt = {
                            let g = trusted.lock().await;
                            g.get(&id).cloned()
                        };

                        if let Some(peer) = peer_opt {
                            // DIR-P1-02: this is the blind cache-redial path —
                            // no fresh mDNS advert triggered it, we're just
                            // retrying the last known address. Gate it on the
                            // peer's backoff timer so a dead/flapping peer
                            // doesn't get redialed every tick forever (that
                            // was the pre-backoff handshake-storm bug). A
                            // fresh `DiscoveryEvent::Resolved` below
                            // deliberately bypasses this gate — see the
                            // comment there.
                            let ready = {
                                let mut g = backoff.lock().await;
                                g.entry(id).or_insert_with(PeerBackoff::new).ready(Instant::now())
                            };
                            if !ready {
                                continue;
                            }
                            // Redial candidate set (last_addr persistence +
                            // redial): the transport's roaming history —
                            // seeded at boot from the persisted `last_addr`
                            // (see `run()`'s seed loop) and updated on every
                            // confirmed handshake/roam — UNION any
                            // still-fresh mDNS discovery-cache hint for this
                            // peer, deduplicated by address. When mDNS is
                            // disabled `disc_cache` simply stays empty, so
                            // this reduces to the roaming-history-only set.
                            let mut candidates = transport.roaming_history_snapshot().await;
                            {
                                let cache = disc_cache.lock().await;
                                if let Some(hint) = cache.get(&id) {
                                    if Instant::now().duration_since(hint.last_seen) < DISCOVERY_CACHE_TTL
                                        && !candidates.contains(&hint.addr)
                                    {
                                        candidates.push(hint.addr);
                                    }
                                }
                            }
                            for h_addr in candidates {
                                let id_clone = identity.clone();
                                let static_pub = peer.static_pub;
                                let peer_id_clone = id;
                                let peer_name = peer.name.clone();
                                let transport_clone = transport.clone();
                                let pending_tx = pending_initiator_tx.clone();
                                let event_tx_clone = event_tx.clone();
                                let backoff_clone = backoff.clone();
                                let trusted_clone = trusted.clone();
                                let kd = keystore_dir.clone();

                                // [REMEDIATION] Proactive Probe Tie-break: only one side initiates.
                                if id_clone.public_key() >= static_pub {
                                    tracing::debug!(peer = %hex::encode(&peer_id_clone[..4]), "proactive probe tie-break: peer initiates");
                                    continue;
                                }

                                tokio::spawn(async move {
                                    tracing::debug!(
                                        peer = %hex::encode(&peer_id_clone[..4]),
                                        addr = %h_addr,
                                        "proactive probe: trying known IP in parallel"
                                    );
                                    start_initiator(
                                        id_clone,
                                        static_pub,
                                        vec![h_addr],
                                        peer_id_clone,
                                        peer_name,
                                        transport_clone,
                                        pending_tx,
                                        event_tx_clone,
                                        None,
                                        backoff_clone,
                                        trusted_clone,
                                        kd,
                                    ).await;
                                });
                            }
                        }
                    }
                }

                // Item 4: also proactively redial known-trusted SECONDARIES
                // whose session is down. The probe above only ever retries
                // the PRIMARY (`cached_peer_id`) — a linked-but-since-dropped
                // secondary was otherwise stranded until mDNS happened to
                // rediscover it. Independent of the primary's own session
                // state (a secondary can need redialing whether or not the
                // primary is currently linked). Reuses the exact same
                // candidate-address union / backoff gate / tie-break /
                // `start_initiator` mechanics as the primary probe, just
                // per secondary id.
                let primary_id_now = transport.cached_peer_id().await;
                let secondary_candidates: Vec<(_, TrustedPeer)> = {
                    let g = trusted.lock().await;
                    g.iter()
                        .filter(|(id, _)| Some(**id) != primary_id_now)
                        .map(|(id, peer)| (*id, peer.clone()))
                        .collect()
                };
                for (id, peer) in secondary_candidates {
                    if transport.has_session_for(id).await {
                        continue;
                    }
                    let ready = {
                        let mut g = backoff.lock().await;
                        g.entry(id).or_insert_with(PeerBackoff::new).ready(Instant::now())
                    };
                    if !ready {
                        continue;
                    }
                    // Candidate set: this peer's own per-conn roaming
                    // history (populated once it has held ANY session on
                    // `transport` this boot, primary or `extra`) UNION the
                    // boot-time persisted `last_addr` (covers a secondary
                    // that has never connected yet this process) UNION a
                    // still-fresh mDNS discovery-cache hint.
                    let mut candidates = transport.roaming_history_snapshot_for(id).await;
                    if let Some(addr) = persisted_peer_addrs.get(&id) {
                        if !candidates.contains(addr) {
                            candidates.push(*addr);
                        }
                    }
                    {
                        let cache = disc_cache.lock().await;
                        if let Some(hint) = cache.get(&id) {
                            if Instant::now().duration_since(hint.last_seen) < DISCOVERY_CACHE_TTL
                                && !candidates.contains(&hint.addr)
                            {
                                candidates.push(hint.addr);
                            }
                        }
                    }
                    if candidates.is_empty() {
                        continue;
                    }
                    // Tie-break: only one side initiates (mirrors the
                    // primary probe above).
                    if identity.public_key() >= peer.static_pub {
                        tracing::debug!(peer = %hex::encode(&id[..4]), "proactive probe (secondary) tie-break: peer initiates");
                        continue;
                    }
                    for h_addr in candidates {
                        let id_clone = identity.clone();
                        let static_pub = peer.static_pub;
                        let peer_id_clone = id;
                        let peer_name = peer.name.clone();
                        let transport_clone = transport.clone();
                        let pending_tx = pending_initiator_tx.clone();
                        let event_tx_clone = event_tx.clone();
                        let backoff_clone = backoff.clone();
                        let trusted_clone = trusted.clone();
                        let kd = keystore_dir.clone();

                        tokio::spawn(async move {
                            tracing::debug!(
                                peer = %hex::encode(&peer_id_clone[..4]),
                                addr = %h_addr,
                                "proactive probe (secondary): trying known IP in parallel"
                            );
                            start_initiator(
                                id_clone,
                                static_pub,
                                vec![h_addr],
                                peer_id_clone,
                                peer_name,
                                transport_clone,
                                pending_tx,
                                event_tx_clone,
                                None,
                                backoff_clone,
                                trusted_clone,
                                kd,
                            ).await;
                        });
                    }
                }
            }
            Some(disc) = rx.recv() => {
                match disc {
                    DiscoveryEvent::Resolved { peer_id_hex, static_pub_hex, name, addrs, pair_pin } => {
                        let Ok(peer_id) = decode_hex32(&peer_id_hex) else { continue };
                        let Ok(static_pub) = decode_hex32(&static_pub_hex) else { continue };
                        if handshake::peer_id_for(&static_pub) != peer_id {
                            tracing::warn!("mDNS peer_id != BLAKE3(static_pub); ignoring");
                            continue;
                        }
                        // Best (highest-ranked) address for the reconnect
                        // cache; the initiator below gets the full ranked list.
                        let Some(best_addr) = addrs.first().copied() else { continue };
                        // PR2: feed the discovery cache before the trust
                        // gate so `PairFromPin` can resolve a not-yet-
                        // trusted peer. Cap to avoid unbounded growth from
                        // a hostile flood — old entries naturally age out
                        // via `DISCOVERY_CACHE_TTL`, but a burst could
                        // still wedge the map; 256 is far above the legit
                        // home-LAN peer count.
                        {
                            let mut cache = disc_cache.lock().await;
                            let now = Instant::now();
                            cache.retain(|_, e| now.duration_since(e.last_seen) < DISCOVERY_CACHE_TTL);
                            if cache.len() < 256 || cache.contains_key(&peer_id) {
                                cache.insert(peer_id, ResolvedPeer {
                                    static_pub,
                                    addr: best_addr,
                                    name: name.clone(),
                                    pair_pin: pair_pin.clone(),
                                    last_seen: now,
                                });
                            }
                        }
                        let trusted_match = {
                            let g = trusted.lock().await;
                            g.get(&peer_id).is_some_and(|t| t.static_pub == static_pub)
                        };
                        if !trusted_match {
                            // C-DAEMON-01: `peer_id == BLAKE3(static_pub)` is
                            // verified above, so a peer_id absent from the
                            // trust set is just an unknown device on the LAN —
                            // never a "cryptographic reset" of an existing
                            // pairing (impossible by construction: same id ⇒
                            // same key). Ignore it; do NOT touch trust. Firing
                            // UntrustedPeerSeen here let ANY stranger's mDNS
                            // advert remote-wipe the whole trust store.
                            tracing::debug!(peer = %peer_id_hex, "ignoring advertisement from untrusted/unknown peer");
                            continue;
                        }
                        // Skip if a session is already up to THIS peer.
                        // FluxMesh 2C-b: per-peer, so a daemon already linked to
                        // one device still initiates to other discovered peers.
                        if transport.has_session_for(peer_id).await {
                            continue;
                        }
                        // Tie-break: only the side with the lower static_pub
                        // bytes initiates from a discovery resolve. The other
                        // side waits for the inbound HandshakeInit. Without
                        // this, two daemons that resolve each other at the
                        // same time both initiate, both responders complete
                        // first, and each ends up with a session keyed for
                        // the *opposite* role — encrypts on one side cannot
                        // decrypt on the other.
                        if identity.public_key() >= static_pub {
                            tracing::debug!(
                                peer = %peer_id_hex,
                                "tie-break: peer initiates; waiting for HandshakeInit"
                            );
                            continue;
                        }
                        // DIR-P1-02: deliberately bypasses the backoff gate
                        // (contrast the "PROACTIVE PROBE" arm above). This
                        // fired because the peer *just* announced itself
                        // over mDNS, i.e. it is provably alive on the LAN
                        // right now — waiting out a stale backoff window
                        // here would only hurt reconnect latency for no
                        // storm-prevention benefit, since the trigger is a
                        // real signal, not a blind timer. The attempt still
                        // feeds `backoff` below so a failure here still
                        // paces the *next* blind redial correctly.
                        start_initiator(
                            identity.clone(),
                            static_pub,
                            addrs,
                            peer_id,
                            name,
                            transport.clone(),
                            pending_initiator_tx.clone(),
                            event_tx.clone(),
                            None,
                            backoff.clone(),
                            trusted.clone(),
                            keystore_dir.clone(),
                        ).await;
                    }
                    DiscoveryEvent::Removed { .. } => {
                        // mDNS removal is unreliable — TTL expiry, transient
                        // multicast loss, or an unrelated FluxSync device
                        // leaving the LAN all fire it. It must NOT tear down a
                        // healthy link: while an encrypted session is live,
                        // heartbeat timeout (~9s) is the sole authority on peer
                        // liveness. Only surface PeerLost when there is no
                        // session to lose (already discovering / never linked).
                        // The removed mDNS `fullname` isn't resolved to a
                        // peer_id here, so this targets the last-known
                        // primary (`cached_peer_id`, the same "primary"
                        // concept the Bye/Revoke handlers gate on) — the
                        // only peer this no-session state could be about.
                        // Never linked at all ⇒ no cached id ⇒ nothing to
                        // reset, so skip rather than invent one.
                        if !transport.has_session().await {
                            if let Some(peer_id) = transport.cached_peer_id().await {
                                let _ = event_tx.try_send(Event::PeerLost { peer_id });
                            }
                        }
                    }
                }
            }
            else => return Ok(()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_initiator(
    identity: Identity,
    static_pub: [u8; 32],
    addrs: Vec<SocketAddr>,
    peer_id: [u8; 32],
    name: String,
    transport: Arc<Transport>,
    pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    event_tx: mpsc::Sender<Event>,
    pending: Option<PendingSet>,
    backoff: BackoffMap,
    trusted: TrustedSet,
    keystore_dir: Option<PathBuf>,
) {
    if addrs.is_empty() {
        return;
    }
    // Single-flight: refuse to start a second initiator while one is
    // still waiting on its msg2. The pending slot doubles as the route
    // for HandshakeResp datagrams (transport_recv_loop), so two
    // overlapping initiators would steer the second peer's reply to
    // the first peer's session and corrupt both. Reserve the slot here
    // (under the lock, before spawning) with a placeholder; the loop
    // installs the real per-attempt channel before each handshake.
    {
        let mut g = pending_initiator_tx.lock().await;
        if g.is_some() {
            tracing::debug!("initiator already pending; skipping");
            return;
        }
        let (placeholder, _) = mpsc::unbounded_channel::<Vec<u8>>();
        *g = Some(placeholder);
    }
    tokio::spawn(async move {
        // Try each address hint in order (LAN first, then tailnet). A dead
        // hint fails fast via run_initiator's 5s msg2 timeout, then we
        // refresh the channel + pending slot and try the next. One QR with
        // `a=lan,tailnet` thus works on the LAN and across a tailnet.
        for (i, addr) in addrs.iter().enumerate() {
            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
            *pending_initiator_tx.lock().await = Some(tx);
            transport.set_peer_addr(*addr).await;
            let result = handshake::run_initiator(
                identity.clone(),
                static_pub,
                *addr,
                transport.clone(),
                rx,
                event_tx.clone(),
                peer_id,
                name.clone(),
                pending.clone(),
                trusted.clone(),
                keystore_dir.clone(),
            )
            .await;
            match result {
                Ok(()) => {
                    // M6 fix: do NOT reset backoff on a mere completed
                    // handshake — that proves nothing about link stability
                    // and previously let a connect-then-immediately-drop
                    // flap bypass backoff on every cycle. The reset now
                    // happens at actual teardown (heartbeat timeout /
                    // `Msg::Bye`) gated on `PeerBackoff::MIN_STABLE` uptime
                    // — see `heartbeat_loop` and `dispatch_inbound_frame`.
                    // Linked. Leave the slot cleared and stop trying hints.
                    *pending_initiator_tx.lock().await = None;
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, addr = %addr, attempt = i, "initiator attempt failed");
                    // DIR-P1-09: one failed hint = one failed handshake
                    // attempt, same accounting as the responder/rekey paths.
                    transport.metrics.lock().await.on_handshake_fail();
                }
            }
        }
        // All hints exhausted; clear the slot so the next discovery resolve
        // / PairAccept can retry.
        *pending_initiator_tx.lock().await = None;
        // DIR-P1-02: this whole call (every hint tried) is one logical
        // reconnect attempt — schedule the next allowed blind redial.
        // `OsRng` here is the real jitter source (tests inject a seeded
        // RNG directly against `PeerBackoff`, see backoff.rs).
        backoff
            .lock()
            .await
            .entry(peer_id)
            .or_insert_with(PeerBackoff::new)
            .on_attempt_failed(Instant::now(), &mut rand_core::OsRng);
    });
}

/// PR2: rotation watchdog for the advertised pairing PIN.
///
/// While `pin_advert` is `Some(_)`, sleeps until its `expires_at`,
/// then either:
///   * pairing_window has elapsed → clear PIN + republish the mDNS
///     record without a `pair_pin` TXT and exit (user did not pair in
///     time; stale PIN must not linger on the LAN).
///   * otherwise → generate a fresh PIN, republish the TXT, and loop.
///
/// Note the trusted set deliberately does NOT stop the rotation: with
/// re-pairing allowed while already paired, a non-empty trusted set
/// says nothing about whether the user is done with the window. The
/// window deadline (refreshed by each `PairShow` the UI issues while
/// its pair screen stays open) is the single source of truth.
///
/// Exactly one watchdog runs per `PairShow`-opened session — callers
/// guard the spawn behind `was_active` (the previous `pin_advert`
/// being `Some`). On termination the task clears `pin_advert` to
/// `None` so the next `PairShow` re-spawns cleanly.
fn spawn_pin_watchdog(
    pin_advert: PinAdvertisement,
    mdns_ctx: MdnsCtx,
    pairing_window: PairingWindow,
) {
    tokio::spawn(async move {
        loop {
            let sleep_until = match pin_advert.lock().await.as_ref() {
                Some(p) => p.expires_at,
                None => return,
            };
            let now = Instant::now();
            if sleep_until > now {
                tokio::time::sleep(sleep_until - now).await;
            }
            // After sleeping: decide whether to rotate or stop.
            let window_open = match *pairing_window.lock().await {
                Some(deadline) => deadline > Instant::now(),
                None => false,
            };
            if !window_open {
                // Window closed — strip the PIN from mDNS so a stale
                // code can't be used by a late scanner.
                *pin_advert.lock().await = None;
                if let Some(ctx) = mdns_ctx.lock().await.as_ref() {
                    if let Err(e) = discovery::republish_with_pin(
                        &ctx.daemon,
                        &ctx.instance_name,
                        &ctx.peer_id_hex,
                        &ctx.static_pub_hex,
                        ctx.bind_ip,
                        ctx.udp_port,
                        None,
                    ) {
                        tracing::warn!(error = %e, "mDNS republish (clear PIN) failed");
                    }
                }
                tracing::info!("pair PIN cleared");
                return;
            }
            // Rotate: fresh PIN, new expiry, re-publish TXT.
            let new_pin = gen_pair_pin();
            let new_expires = Instant::now() + handshake::PAIRING_WINDOW;
            *pin_advert.lock().await = Some(PinAd {
                pin: new_pin.clone(),
                expires_at: new_expires,
            });
            if let Some(ctx) = mdns_ctx.lock().await.as_ref() {
                if let Err(e) = discovery::republish_with_pin(
                    &ctx.daemon,
                    &ctx.instance_name,
                    &ctx.peer_id_hex,
                    &ctx.static_pub_hex,
                    ctx.bind_ip,
                    ctx.udp_port,
                    Some(&new_pin),
                ) {
                    tracing::warn!(error = %e, "mDNS republish (rotate PIN) failed");
                }
            }
            tracing::info!("pair PIN rotated");
        }
    });
}

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s)?;
    let arr: [u8; 32] = v.try_into().map_err(|_| anyhow!("hex not 32 bytes"))?;
    Ok(arr)
}

// ─────────────────────────────────────────────────────────────────
// Pair URI helpers
// ─────────────────────────────────────────────────────────────────

/// Best-guess `<ip>:<port>` the daemon is reachable at on the LAN.
///
/// If the daemon is bound to a specific address, that wins. Otherwise
/// the kernel's own routing table picks: open a UDP socket "to" a
/// public address — no packet leaves the box because UDP connect is
/// state-only — and read back the source IP the kernel chose. This is
/// the standard way to find the egress LAN IP without interface
/// enumeration.
fn local_lan_addr(udp_bind: &str, udp_port: u16) -> String {
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};

    fn pick_local() -> IpAddr {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("1.1.1.1:80").is_ok() {
                if let Ok(local) = sock.local_addr() {
                    return local.ip();
                }
            }
        }
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    let ip = match udp_bind.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) if v4.is_unspecified() => pick_local(),
        Ok(IpAddr::V6(v6)) if v6.is_unspecified() => pick_local(),
        Ok(other) => other,
        Err(_) => pick_local(),
    };
    format!("{ip}:{udp_port}")
}

/// Best-effort tailnet (Tailscale) socket address for this host, if any.
///
/// Tailscale assigns each node an address in the CGNAT range
/// `100.64.0.0/10`. We discover ours the same dependency-free way as
/// `local_lan_addr`: open a UDP socket "connected" to a target inside that
/// range (Tailscale's MagicDNS resolver, `100.100.100.100`) and read back
/// the source address the kernel picks. With no tailnet route the source IP
/// won't land in the CGNAT range, so we reject it and return `None`. No
/// Tailscale SDK or dependency — purely a routing probe, so Tailscale stays
/// 100% optional. (False positive only if the host itself sits behind ISP
/// CGNAT in the same range; harmless — it's a hint the user can verify.)
fn tailnet_local_addr(udp_port: u16) -> Option<String> {
    use std::net::{IpAddr, UdpSocket};
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("100.100.100.100:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if is_cgnat(v4) => Some(format!("{v4}:{udp_port}")),
        _ => None,
    }
}

/// True if `ip` is in the `100.64.0.0/10` CGNAT range Tailscale assigns.
fn is_cgnat(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// Render a `fluxsync://pair/<pubkey_b32>?a=<addr>&f=<w1.w2...>` URI.
fn build_pair_uri(pubkey_b32: &str, addr_hint: &str, fp_words: &[String]) -> String {
    format!(
        "fluxsync://pair/{pubkey_b32}?a={addr_hint}&f={}",
        fp_words.join(".")
    )
}

struct ParsedPairUri {
    pubkey_b32: String,
    /// Address hints from `a=` (comma-separated), parsed + validated, in
    /// order. Lets one URI/QR carry LAN + tailnet so the initiator can try
    /// each until one handshake succeeds.
    addrs: Vec<SocketAddr>,
    #[allow(dead_code)]
    fp_words: Vec<String>,
}

/// Parse a `fluxsync://pair/...` URI. Tolerant of missing/extra params:
/// only the pubkey segment is required. The fingerprint words are
/// returned for display-side comparison but the daemon does not enforce
/// them — the user does that visually.
fn parse_pair_uri(s: &str) -> Result<ParsedPairUri> {
    let rest = s
        .strip_prefix("fluxsync://pair/")
        .ok_or_else(|| anyhow!("scheme is not fluxsync://pair/"))?;
    let (pubkey_b32, query) = rest.split_once('?').unwrap_or((rest, ""));
    if pubkey_b32.is_empty() {
        return Err(anyhow!("missing pubkey segment"));
    }
    let mut addrs: Vec<SocketAddr> = Vec::new();
    let mut fp_words: Vec<String> = Vec::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        match k {
            // `a` may carry several comma-separated hints (LAN,tailnet).
            // Keep only the ones that parse; order is preserved so the
            // initiator tries LAN before tailnet.
            "a" => {
                addrs = v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse::<SocketAddr>().ok())
                    .collect();
            }
            "f" => fp_words = v.split('.').map(str::to_string).collect(),
            _ => {}
        }
    }
    Ok(ParsedPairUri {
        pubkey_b32: pubkey_b32.to_string(),
        addrs,
        fp_words,
    })
}

// ─────────────────────────────────────────────────────────────────
// IPC accept + per-client loop (unchanged from v0.1)
// ─────────────────────────────────────────────────────────────────

async fn ipc_accept_loop(
    server: IpcServer,
    cmd_tx: mpsc::UnboundedSender<DriverCmd>,
    state_rx: watch::Receiver<State>,
    logs_bcast_tx: broadcast::Sender<LogEntry>,
    log_tail: Arc<LogTail>,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut clients = JoinSet::new();
    // Bounds the number of concurrently-connected IPC clients so N local
    // processes can't each hold a up-to-64-MiB in-flight line and scale the
    // daemon's memory with connection count. Acquiring blocks (backpressure)
    // once the bound is hit rather than dropping the connection — this is a
    // local trusted socket, so a slow-to-accept client is preferable to a
    // rejected one.
    let accept_permits = Arc::new(Semaphore::new(32));
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            // Acquiring the permit and accepting the connection live in the
            // same arm so a shutdown mid-wait (whether blocked on the
            // semaphore or on the accept itself) still cancels promptly.
            accepted = async {
                let permit = accept_permits.clone().acquire_owned().await.expect("semaphore never closed");
                let conn = server.accept().await?;
                Ok::<_, std::io::Error>((permit, conn))
            } => {
                let (permit, conn) = match accepted {
                    Ok(pc) => pc,
                    Err(e) => { tracing::warn!(error = %e, "ipc accept"); continue; }
                };
                let cmd_tx = cmd_tx.clone();
                let state_rx = state_rx.clone();
                let logs_bcast_rx = logs_bcast_tx.subscribe();
                let log_tail = log_tail.clone();
                let client_shutdown = shutdown.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_ipc_client(conn, cmd_tx, state_rx, logs_bcast_rx, log_tail, client_shutdown).await {
                        tracing::debug!(error = %e, "ipc client end");
                    }
                });
            }
        }
    }
    while clients.join_next().await.is_some() {}
    Ok(())
}

/// Cap on a single IPC NDJSON line. The largest legitimate request is a
/// base64 image push (~4/3 of `MAX_PAYLOAD`); 64 MiB leaves headroom while
/// bounding a malicious/buggy local client that streams a newline-less line
/// (which would otherwise let `read_line` buffer unbounded → OOM the daemon).
const MAX_IPC_LINE: usize = 64 * 1024 * 1024;

/// Like `AsyncBufReadExt::read_line` but refuses to buffer more than `max`
/// bytes for one line. Reads via `fill_buf`/`consume` so accumulation is
/// bounded; returns `InvalidData` once the line would exceed the cap. Bytes
/// are decoded lossily once the whole line is collected, so multi-byte UTF-8
/// never splits across an internal buffer boundary.
async fn read_line_capped<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    out: &mut String,
    max: usize,
) -> std::io::Result<usize> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            break; // EOF
        }
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if bytes.len() + take > max {
            reader.consume(take);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IPC line exceeds max length",
            ));
        }
        bytes.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        if done {
            break;
        }
    }
    out.push_str(&String::from_utf8_lossy(&bytes));
    Ok(bytes.len())
}

async fn handle_ipc_client(
    conn: IpcConn,
    cmd_tx: mpsc::UnboundedSender<DriverCmd>,
    mut state_rx: watch::Receiver<State>,
    mut logs_bcast_rx: broadcast::Receiver<LogEntry>,
    _log_tail: Arc<LogTail>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (read_half, mut write_half) = conn.split();
    let mut reader = BufReader::new(read_half);

    let mut opening = String::new();
    read_line_capped(&mut reader, &mut opening, MAX_IPC_LINE).await?;
    let sub: Subscribe = serde_json::from_str(opening.trim())
        .map_err(|e| anyhow!("opening line not a Subscribe: {e}"))?;

    match sub.subscribe {
        Channel::Cmd => {
            let mut line = String::new();
            loop {
                line.clear();
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    res = read_line_capped(&mut reader, &mut line, MAX_IPC_LINE) => {
                        let n = res?;
                        if n == 0 { return Ok(()); }
                        let req: CmdRequest = match serde_json::from_str(line.trim()) {
                            Ok(r) => r,
                            Err(e) => {
                                let resp = CmdResponse::err(0, format!("bad json: {e}"));
                                write_json_line(&mut write_half, &resp).await?;
                                continue;
                            }
                        };
                        let (reply_tx, reply_rx) = oneshot::channel();
                        cmd_tx.send(DriverCmd::Run { op: req.op, reply: reply_tx, req_id: req.id })
                            .map_err(|_| anyhow!("driver gone"))?;
                        let resp = reply_rx.await.map_err(|_| anyhow!("driver dropped reply"))?;
                        write_json_line(&mut write_half, &resp).await?;
                    }
                }
            }
        }
        Channel::State => {
            let snap = state_rx.borrow().clone();
            write_json_line(&mut write_half, &snap).await?;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return Ok(()),
                    changed = state_rx.changed() => {
                        if changed.is_err() { return Ok(()); }
                        let snap = state_rx.borrow().clone();
                        write_json_line(&mut write_half, &snap).await?;
                    }
                }
            }
        }
        Channel::Logs => loop {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                entry = logs_bcast_rx.recv() => {
                    match entry {
                        Ok(e) => write_json_line(&mut write_half, &e).await?,
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            let warn = LogEntry { level: LogLevel::Warn, msg: String::from("(some log lines were dropped)") };
                            write_json_line(&mut write_half, &warn).await?;
                        }
                    }
                }
            }
        },
    }
}

async fn write_json_line<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: serde::Serialize,
{
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::load_trusted_peers;
    use crate::handshake;
    use crate::keystore::{save_peers, StoredPeer};

    /// FS-039: a peer persisted to `peers.json` must be back in the
    /// trusted set after a restart (i.e. via the boot reload path).
    #[test]
    fn fs039_trusted_peer_reloads_after_restart() {
        let dir = tempfile::tempdir().expect("create temp keystore dir");

        let static_pub = [0x42u8; 32];
        let peer_id = handshake::peer_id_for(&static_pub);
        save_peers(
            dir.path(),
            &[StoredPeer {
                peer_id_hex: hex::encode(peer_id),
                static_pub_hex: hex::encode(static_pub),
                name: "Galaxy S21".to_owned(),
                last_addr: Some("10.0.0.7:41889".to_owned()),
            }],
        )
        .expect("persist peer to peers.json");

        let loaded = load_trusted_peers(dir.path());

        assert_eq!(loaded.len(), 1, "the persisted peer must reload");
        let (id, peer, last_addr) = &loaded[0];
        assert_eq!(*id, peer_id, "peer_id must round-trip");
        assert_eq!(peer.static_pub, static_pub, "static_pub must round-trip");
        assert_eq!(peer.name, "Galaxy S21", "name must round-trip");
        assert_eq!(
            *last_addr,
            Some("10.0.0.7:41889".parse().unwrap()),
            "last_addr must parse and round-trip"
        );
    }

    /// Item 3: the boot-time `SetTrustedPeer` UI hint must be deterministic
    /// across restarts, not `HashMap`-iteration-order luck. Two cases: the
    /// primary's own entry wins when its id is already known, and otherwise
    /// the choice falls back to the lowest peer id — computed here
    /// independently of insertion order so the assertion cannot pass by
    /// coincidentally matching whatever order the map happens to iterate in.
    #[test]
    fn choose_boot_trusted_peer_is_deterministic() {
        use super::choose_boot_trusted_peer;
        use std::collections::HashMap;

        fn peer(name: &str) -> handshake::TrustedPeer {
            handshake::TrustedPeer { static_pub: [0u8; 32], name: name.to_string() }
        }

        // Scattered ids (not insertion-order-adjacent to the true min) so a
        // `HashMap`-iteration-order bug (`.values().next()`) is very unlikely
        // to coincidentally reproduce the correct answer.
        let ids: [[u8; 32]; 8] = [
            [0x90; 32], [0x20; 32], [0xF0; 32], [0x01; 32],
            [0x77; 32], [0xAA; 32], [0x55; 32], [0xC3; 32],
        ];
        let mut trusted = HashMap::new();
        for (i, id) in ids.iter().enumerate() {
            trusted.insert(*id, peer(&format!("peer-{i}")));
        }
        let true_min_id = *ids.iter().min().unwrap();
        let true_min_name = trusted[&true_min_id].name.clone();

        // ── Case 1: primary id known — its own entry must win, regardless
        //            of whether it's the min id. ──
        let primary_id = ids[5]; // [0xAA; 32] — not the min
        let chosen = choose_boot_trusted_peer(&trusted, Some(primary_id))
            .expect("primary's entry must be found");
        assert_eq!(
            chosen.name, trusted[&primary_id].name,
            "known primary id must win over the deterministic fallback"
        );

        // ── Case 2: no primary known — must fall back to the lowest peer
        //            id, deterministically. ──
        let chosen = choose_boot_trusted_peer(&trusted, None)
            .expect("fallback must find an entry");
        assert_eq!(
            chosen.name, true_min_name,
            "FIXED: no known primary must deterministically pick the lowest peer id, \
             not whatever HashMap iteration happens to yield first"
        );

        // ── Case 3: primary id given but NOT in the trusted set (stale) —
        //            must still fall back to the deterministic minimum. ──
        let chosen = choose_boot_trusted_peer(&trusted, Some([0xEEu8; 32]))
            .expect("fallback must still find an entry for an unknown primary id");
        assert_eq!(chosen.name, true_min_name);
    }

    /// L4: `persist_last_addr` must reject loopback/link-local/multicast/
    /// unspecified addresses outright (never even attempt the write),
    /// while a normal LAN address persists exactly as before.
    #[tokio::test]
    async fn l4_persist_last_addr_filters_bogus_address_classes() {
        use super::{is_redialable_addr, persist_last_addr};
        use crate::handshake::{TrustedPeer, TrustedSet};
        use crate::transport::Transport;
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        assert!(!is_redialable_addr("169.254.1.1".parse().unwrap()), "link-local must be rejected");
        assert!(!is_redialable_addr("224.0.0.1".parse().unwrap()), "multicast must be rejected");
        assert!(!is_redialable_addr("0.0.0.0".parse().unwrap()), "unspecified must be rejected");
        assert!(!is_redialable_addr("fe80::1".parse().unwrap()), "IPv6 link-local must be rejected");
        assert!(is_redialable_addr("192.168.1.42".parse().unwrap()), "a normal LAN address must pass");
        // Loopback is intentionally allowed: an off-host attacker cannot forge
        // a loopback source, and the in-process harness redials over it.
        assert!(is_redialable_addr("127.0.0.1".parse().unwrap()), "loopback must be allowed");
        assert!(is_redialable_addr("::1".parse().unwrap()), "IPv6 loopback must be allowed");

        let dir = tempfile::tempdir().expect("tempdir");
        let (transport, _port) =
            Transport::bind("127.0.0.1", 0).await.expect("bind transport");
        let peer_id = [0x11u8; 32];
        let trusted: TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(peer_id, TrustedPeer { static_pub: [0x22u8; 32], name: "peer".into() });

        // A link-local source (the LAN-spoofable class the fix targets)
        // must never be written to peers.json.
        persist_last_addr(
            Some(dir.path()),
            &transport,
            &trusted,
            peer_id,
            "169.254.1.1:9999".parse().unwrap(),
        )
        .await;
        assert!(
            crate::keystore::load_peers(dir.path()).expect("load peers").is_empty(),
            "L4: a link-local last_addr must never be persisted"
        );

        // A genuine LAN address persists exactly as before the fix.
        let lan_addr: std::net::SocketAddr = "192.168.1.42:9999".parse().unwrap();
        persist_last_addr(Some(dir.path()), &transport, &trusted, peer_id, lan_addr).await;
        let stored = crate::keystore::load_peers(dir.path()).expect("load peers");
        assert_eq!(stored.len(), 1, "a normal LAN address must persist");
        assert_eq!(stored[0].last_addr, Some(lan_addr.to_string()));
    }

    /// "Clear clipboard history": `CmdOp::ClearHistory` purges cleared
    /// hashes from `IMAGE_CACHE` so a cleared image can't still be fetched
    /// via `FetchItem` afterwards. Seeds the process-global cache directly
    /// through `image_cache()` (rather than going through a `WriteClipboard`
    /// action) to keep the test focused on `purge_cached_images` alone.
    #[test]
    fn clear_history_purges_cached_images_for_cleared_hashes() {
        use super::{image_cache, lookup_cached_image, purge_cached_images};

        let keep = "bb".repeat(32);
        let drop = "aa".repeat(32);
        {
            let mut g = image_cache().lock().expect("lock image cache");
            g.clear();
            g.push_back((drop.clone(), vec![1, 2, 3]));
            g.push_back((keep.clone(), vec![4, 5, 6]));
        }

        purge_cached_images(std::slice::from_ref(&drop));

        assert!(
            lookup_cached_image(&drop).is_none(),
            "cleared hash must be purged from IMAGE_CACHE"
        );
        assert!(
            lookup_cached_image(&keep).is_some(),
            "an untouched hash must survive the purge"
        );

        // Don't leak this process-global cache's state into other tests in
        // the same binary.
        image_cache().lock().expect("lock image cache").clear();
    }

    /// FS-026: the write side records `clipboard_dedup_hash(preview)` and
    /// the watcher looks up `clipboard_dedup_hash(raw_text)`. A payload that
    /// only differs by surrounding whitespace must hash equal, or a peer
    /// item with a trailing newline echoes straight back to the sender.
    #[test]
    fn fs026_clipboard_dedup_hash_is_trim_symmetric() {
        use super::clipboard_dedup_hash;
        assert_eq!(
            clipboard_dedup_hash("hello\n"),
            clipboard_dedup_hash("hello"),
            "trailing newline must not change the dedup hash",
        );
        assert_eq!(
            clipboard_dedup_hash("  hello  "),
            clipboard_dedup_hash("hello"),
            "surrounding spaces must not change the dedup hash",
        );
        assert_ne!(
            clipboard_dedup_hash("hello"),
            clipboard_dedup_hash("world"),
            "distinct payloads must still hash differently",
        );
    }

    /// C1: the dedup hash CRLF-canonicalizes, so the SAME text copied with
    /// Windows `\r\n` vs Unix `\n` line endings dedups instead of bouncing.
    #[test]
    fn c1_clipboard_dedup_hash_canonicalizes_crlf() {
        use super::clipboard_dedup_hash;
        assert_eq!(
            clipboard_dedup_hash("line1\r\nline2"),
            clipboard_dedup_hash("line1\nline2"),
            "CRLF and LF of the same text must hash equal",
        );
        assert_eq!(
            clipboard_dedup_hash("a\rb"),
            clipboard_dedup_hash("a\nb"),
            "lone CR must canonicalize to LF",
        );
    }

    /// C2: the vault persister mirrors a security wipe onto disk. When the
    /// published `State.vault_wipe_gen` increments, the persister must delete
    /// the encrypted vault AND forget its cached favorites — otherwise a
    /// previously-favorited secret is re-appended by `rebuild()` and the file
    /// outlives the in-memory wipe. This exercises the real persister glue
    /// end-to-end (the only line the integration test couldn't reach).
    #[tokio::test]
    async fn c2_persister_clears_disk_vault_and_favorites_on_wipe_gen_bump() {
        use super::{run_vault_persister, BackoffMap, DiscoveryCache, ResolvedPeer, VaultCtx};
        use crate::history_store;
        use fluxsync_core::{Config, HistoryItem, HistorySource, Kind, State};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        use tokio::sync::{watch, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let key = zeroize::Zeroizing::new([0x11u8; 32]);
        let now = 1_000_000u64;
        let ttl = history_store::DEFAULT_TTL_SECS;
        let disk_len = |d: &std::path::Path| {
            history_store::load(d, &key, now, ttl).map_or(0, |v| v.len())
        };

        let secret = HistoryItem {
            kind: Kind::Text,
            preview: "favorited secret".into(),
            time: "12:00".into(),
            source: HistorySource::Local,
            sensitive: false,
            lamport: 1,
            hash: "aa".repeat(32),
            favorite: true,
            resync: false,
            source_peer_id: None,
        };

        // Persister starts empty (ctx.last empty) so the baseline publish below
        // forces a save we can poll on — a deterministic sync point that proves
        // the loop captured wipe_gen=0 BEFORE we bump it (avoids a watch-init
        // race where borrow() reads the post-send value).
        let ctx = VaultCtx {
            dir: dir.path().to_path_buf(),
            key: key.clone(),
            last: Vec::new(),
            entries: Vec::new(),
        };

        // DIR-P2-04a: pre-seed the discovery cache (as a real mDNS resolve
        // would) so this test also proves the security-wipe path purges it,
        // not just the on-disk vault + cached favorites.
        let disc_cache: DiscoveryCache = Arc::new(Mutex::new(HashMap::new()));
        disc_cache.lock().await.insert(
            [0x77u8; 32],
            ResolvedPeer {
                static_pub: [0x88u8; 32],
                addr: "127.0.0.1:1".parse().unwrap(),
                name: "stale-peer".into(),
                pair_pin: Some("123456".into()),
                last_seen: Instant::now(),
            },
        );
        // DIR-P1-02: same rationale — pre-seed a backoff timer for the same
        // peer so this test also proves the security-wipe path purges it.
        let backoff: BackoffMap = Arc::new(Mutex::new(HashMap::new()));
        let mut pb = crate::backoff::PeerBackoff::new();
        pb.on_attempt_failed(Instant::now(), &mut rand_core::OsRng);
        backoff.lock().await.insert([0x77u8; 32], pb);

        // Channel init: empty, gen=0. Persister records last_wipe_gen=0.
        let (tx, rx) = watch::channel(State::initial(&Config::default()));
        // Never-cancelled token: this test ends the persister the old way
        // (dropping `tx` below), exercising that path still works unchanged.
        let shutdown = tokio_util::sync::CancellationToken::new();
        let persister = tokio::spawn(run_vault_persister(
            ctx,
            rx,
            0,
            disc_cache.clone(),
            backoff.clone(),
            shutdown,
        ));

        // Baseline: publish the favorited secret (gen still 0) → persister saves
        // it to disk and caches it as a favorite in ctx.entries.
        let mut base = State::initial(&Config::default());
        base.history = vec![secret.clone()];
        base.vault_wipe_gen = 0;
        tx.send(base).expect("publish baseline");
        let mut saved = false;
        for _ in 0..200 {
            if disk_len(dir.path()) == 1 {
                saved = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(saved, "baseline favorite must reach the on-disk vault first");

        // Security wipe with a NON-EMPTY post-wipe history (a peer-swap starts
        // a fresh, non-favorite item). This is what makes ctx.entries.clear()
        // load-bearing: with a non-empty history the persister does NOT
        // short-circuit on `history == ctx.last`, so it runs rebuild(). If
        // ctx.entries still held the favorited secret, rebuild()'s favorite
        // re-append loop would resurrect it onto disk — so this test fails iff
        // the cached favorites are not forgotten on the wipe.
        let fresh = HistoryItem {
            kind: Kind::Text,
            preview: "post-swap item".into(),
            time: "12:01".into(),
            source: HistorySource::Local,
            sensitive: false,
            lamport: 2,
            hash: "bb".repeat(32),
            favorite: false,
            resync: false,
            source_peer_id: None,
        };
        let mut wiped = State::initial(&Config::default());
        wiped.history = vec![fresh.clone()];
        wiped.vault_wipe_gen = 1;
        tx.send(wiped).expect("publish wipe");

        // Poll until the on-disk vault reflects the wipe: the fresh item is
        // persisted and the previously-favorited secret is GONE.
        let disk_previews = |d: &std::path::Path| -> Vec<String> {
            history_store::load(d, &key, now, ttl)
                .map(|v| v.into_iter().map(|e| e.item.preview).collect())
                .unwrap_or_default()
        };
        let mut cleared = false;
        for _ in 0..200 {
            let p = disk_previews(dir.path());
            if p.iter().any(|x| x == "post-swap item")
                && !p.iter().any(|x| x == "favorited secret")
            {
                cleared = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            cleared,
            "security wipe must drop the cached favorite: on-disk vault should hold only \
             the fresh post-swap item, never the previously-favorited secret. Got: {:?}",
            disk_previews(dir.path()),
        );
        assert!(
            disc_cache.lock().await.is_empty(),
            "security wipe must purge the mDNS discovery cache (DIR-P2-04a): a stale \
             pubkey/name/addrs/pairing PIN must not survive the wipe"
        );
        assert!(
            backoff.lock().await.is_empty(),
            "security wipe must purge per-peer reconnect backoff state (DIR-P1-02)"
        );

        drop(tx);
        let _ = persister.await;
    }

    /// FIX3: `sync_security_wipe_if_needed` (the driver's inline,
    /// synchronous belt for the vault persister's async braces) must, by
    /// the time it RETURNS — no polling needed — have both fully cleared
    /// the resync outbox (real + `Ask`-staged) and deleted `history.enc`
    /// from disk, exactly once per `vault_wipe_gen` advance. A call with no
    /// gen change must touch neither.
    #[tokio::test]
    async fn sync_security_wipe_if_needed_clears_outbox_and_disk_synchronously() {
        use super::{sync_security_wipe_if_needed, Outbox, OutboxEntry, PendingOutboxStage};
        use crate::history_store;
        use fluxsync_core::{App, Config, Event, HistoryItem, HistorySource, StubWallClock};
        use fluxsync_proto::Kind;
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Instant;
        use tokio::sync::Mutex;

        let dir = tempfile::tempdir().expect("tempdir");
        let key = [0x22u8; 32];
        // Seed a real on-disk vault, exactly like a running persister would
        // have already written before the wipe.
        let entry = history_store::VaultEntry {
            item: HistoryItem {
                kind: Kind::Text,
                preview: "pre-wipe secret".into(),
                time: "12:00".into(),
                source: HistorySource::Local,
                sensitive: false,
                lamport: 1,
                hash: "cc".repeat(32),
                favorite: false,
                resync: false,
                source_peer_id: None,
            },
            created_ms: 1_000,
        };
        history_store::save(
            dir.path(),
            &key,
            &[entry],
            1_000,
            history_store::DEFAULT_TTL_SECS,
            history_store::DEFAULT_DISK_CAP,
        )
        .expect("seed on-disk vault");
        assert!(
            dir.path().join("history.enc").exists(),
            "precondition: vault file must exist before the wipe"
        );

        let outbox = Arc::new(Mutex::new(Outbox::new()));
        outbox.lock().await.insert(
            [1u8; 32],
            OutboxEntry {
                payload: b"held item".to_vec(),
                kind: Kind::Text,
                origin: [9u8; 32],
                seq: 1,
                created: Instant::now(),
            },
        );
        let outbox_stage: PendingOutboxStage = Arc::new(Mutex::new(HashMap::new()));
        outbox_stage.lock().await.insert(
            [2u8; 32],
            OutboxEntry {
                payload: b"staged item".to_vec(),
                kind: Kind::Text,
                origin: [9u8; 32],
                seq: 2,
                created: Instant::now(),
            },
        );
        // Bug #9: an inflight entry (unrelated `sensitive` gating on the
        // outbox insert notwithstanding) must not survive a security wipe —
        // its plaintext frames would otherwise keep retransmitting.
        let inflight: super::InflightMap = Arc::new(Mutex::new(HashMap::new()));
        inflight.lock().await.insert(
            [3u8; 32],
            super::Inflight {
                frames: vec![vec![1, 2, 3]],
                attempts: 0,
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                pending_peers: std::iter::once([4u8; 32]).collect(),
            },
        );

        let mut app = App::new(Config::default());
        let wall = StubWallClock::new("12:00", 1_000);
        let mut last_wipe_gen = app.snapshot().vault_wipe_gen;
        let dir_buf = dir.path().to_path_buf();

        // No gen change yet: must be a complete no-op.
        let wiped = sync_security_wipe_if_needed(
            &app,
            &mut last_wipe_gen,
            &outbox,
            &outbox_stage,
            &inflight,
            Some(&dir_buf),
        )
        .await;
        assert!(!wiped, "must not fire when vault_wipe_gen hasn't advanced");
        assert!(
            outbox.lock().await.get([1u8; 32]).is_some(),
            "an unrelated call must not touch the outbox"
        );
        assert!(
            dir.path().join("history.enc").exists(),
            "an unrelated call must not touch disk"
        );
        assert!(
            inflight.lock().await.get(&[3u8; 32]).is_some(),
            "an unrelated call must not touch inflight"
        );

        // Bump vault_wipe_gen. `ClearHistory` is the simplest reliable way to
        // do this in a unit test; this test only exercises the driver's
        // REACTION to the bump, not which fluxsync_core events cause one —
        // that is fluxsync_core::app's own test coverage (and
        // regression_vault_security_wipe.rs's TEST 1 for the real security
        // triggers specifically).
        app.handle(Event::ClearHistory { include_favorites: true }, &wall);
        assert_eq!(app.snapshot().vault_wipe_gen, 1);

        let wiped = sync_security_wipe_if_needed(
            &app,
            &mut last_wipe_gen,
            &outbox,
            &outbox_stage,
            &inflight,
            Some(&dir_buf),
        )
        .await;
        assert!(wiped, "must fire once vault_wipe_gen advances");
        assert_eq!(last_wipe_gen, 1, "must record the new generation");
        assert!(
            outbox.lock().await.is_empty(),
            "the real outbox must be fully cleared"
        );
        assert!(
            outbox_stage.lock().await.is_empty(),
            "Ask-staged entries must be fully cleared too"
        );
        assert!(
            !dir.path().join("history.enc").exists(),
            "history.enc must already be gone from disk by the time this call \
             returns — no polling/sleep needed, proving the clear is synchronous"
        );
        assert!(
            inflight.lock().await.is_empty(),
            "FIXED (bug #9): inflight must be fully cleared by a security wipe too"
        );

        // A second call at the same (already-recorded) generation must be a
        // no-op again — it must not re-run the disk clear or error out on an
        // already-missing file.
        let wiped_again = sync_security_wipe_if_needed(
            &app,
            &mut last_wipe_gen,
            &outbox,
            &outbox_stage,
            &inflight,
            Some(&dir_buf),
        )
        .await;
        assert!(!wiped_again, "must not re-fire for a generation already handled");
    }

    /// L1 fix: `sync_security_wipe_if_needed` must also empty `IMAGE_CACHE`
    /// (`WriteClipboard`'s image stash) — otherwise a wiped peer's cached
    /// image bytes stay fetchable via `CmdOp::FetchItem` after the rest of
    /// the vault is already gone. Seeds the process-global cache directly,
    /// same as `clear_history_purges_cached_images_for_cleared_hashes`.
    #[tokio::test]
    async fn sync_security_wipe_if_needed_clears_image_cache() {
        use super::{image_cache, lookup_cached_image, sync_security_wipe_if_needed, Outbox, PendingOutboxStage};
        use fluxsync_core::{App, Config, Event, StubWallClock};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let stashed = "dd".repeat(32);
        {
            let mut g = image_cache().lock().expect("lock image cache");
            g.clear();
            g.push_back((stashed.clone(), vec![7, 8, 9]));
        }

        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let outbox_stage: PendingOutboxStage = Arc::new(Mutex::new(HashMap::new()));
        let inflight: super::InflightMap = Arc::new(Mutex::new(HashMap::new()));

        let mut app = App::new(Config::default());
        let wall = StubWallClock::new("12:00", 1_000);
        let mut last_wipe_gen = app.snapshot().vault_wipe_gen;

        // Bump vault_wipe_gen the same way the outbox/disk test does.
        app.handle(Event::ClearHistory { include_favorites: true }, &wall);
        assert_eq!(app.snapshot().vault_wipe_gen, 1);

        let wiped = sync_security_wipe_if_needed(
            &app,
            &mut last_wipe_gen,
            &outbox,
            &outbox_stage,
            &inflight,
            None,
        )
        .await;
        assert!(wiped, "must fire once vault_wipe_gen advances");
        assert!(
            lookup_cached_image(&stashed).is_none(),
            "a security wipe must purge IMAGE_CACHE, not just the outbox/disk vault"
        );

        // Don't leak this process-global cache's state into other tests in
        // the same binary.
        image_cache().lock().expect("lock image cache").clear();
    }

    /// DIR-P3-02(b) (desktop `FetchItem`): `WriteClipboard`'s image handler
    /// now populates `IMAGE_CACHE` on every target, not just Android — this
    /// is what lets the tray's `fetch_item` (`CmdOp::FetchItem` ->
    /// `lookup_cached_image`) serve history thumbnails/re-copy on
    /// macOS/Linux/Windows. Proves all three invariants through the real
    /// `dispatch` path (not a direct cache seed, unlike the two tests
    /// above): a non-sensitive image is fetchable byte-for-byte, a sensitive
    /// one never enters the cache at all (mirrors the Android sensitivity
    /// gate), and a security wipe purges whatever was cached before it.
    #[tokio::test]
    async fn write_clipboard_populates_desktop_image_cache_gated_by_sensitivity_and_wipe() {
        use super::{
            dispatch, encode_png, image_cache, image_rgba_hash, lookup_cached_image,
            sync_security_wipe_if_needed, Outbox, PendingOutboxStage,
        };
        use crate::transport::Transport;
        use fluxsync_core::{Action, App, Config, Event, StubWallClock};
        use fluxsync_proto::Kind;
        use std::collections::{BTreeMap, HashMap, VecDeque};
        use std::sync::Arc;
        use tokio::sync::{broadcast, watch, Mutex};

        // Other tests in this binary share the process-global cache.
        image_cache().lock().expect("lock image cache").clear();

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);

        let mut app = App::new(Config::default());
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        let (state_watch_tx, _state_watch_rx) =
            watch::channel(fluxsync_core::State::initial(&Config::default()));
        let (logs_bcast_tx, _logs_rx) = broadcast::channel(16);
        let log_tail = Arc::new(super::LogTail::new());
        let last_written_hashes = Arc::new(Mutex::new(VecDeque::new()));
        let metrics = Arc::new(Mutex::new(crate::metrics::MetricsTracker::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(BTreeMap::new()));
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let outbox_stage: PendingOutboxStage = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let mut seq_store: Option<crate::seq_store::SeqStore> = None;

        // A tiny 1x1 opaque-red PNG — a real, non-sensitive image.
        let rgba = vec![0xff, 0x00, 0x00, 0xff];
        let png = encode_png(1, 1, rgba.clone()).expect("encode test PNG");
        let hash_hex = hex::encode(image_rgba_hash(1, 1, &rgba));

        dispatch(
            vec![Action::WriteClipboard {
                kind: Kind::Image,
                payload: png.clone(),
                sensitive: false,
            }],
            &mut app,
            &transport,
            &trusted,
            None,
            &state_watch_tx,
            &logs_bcast_tx,
            &log_tail,
            &last_written_hashes,
            &metrics,
            &inflight,
            &peer_meta,
            &outbox,
            &pending_pairs,
            &mut seq_store,
        )
        .await;

        assert_eq!(
            lookup_cached_image(&hash_hex),
            Some(png),
            "a non-sensitive desktop image must be FetchItem-fetchable byte-for-byte"
        );

        // A second, sensitive image must never enter the cache at all.
        let rgba2 = vec![0x00, 0xff, 0x00, 0xff];
        let png2 = encode_png(1, 1, rgba2.clone()).expect("encode test PNG 2");
        let hash2_hex = hex::encode(image_rgba_hash(1, 1, &rgba2));

        dispatch(
            vec![Action::WriteClipboard {
                kind: Kind::Image,
                payload: png2,
                sensitive: true,
            }],
            &mut app,
            &transport,
            &trusted,
            None,
            &state_watch_tx,
            &logs_bcast_tx,
            &log_tail,
            &last_written_hashes,
            &metrics,
            &inflight,
            &peer_meta,
            &outbox,
            &pending_pairs,
            &mut seq_store,
        )
        .await;

        assert!(
            lookup_cached_image(&hash2_hex).is_none(),
            "a sensitive image must never be cached on desktop either"
        );

        // A security wipe must purge the non-sensitive image cached above.
        let mut last_wipe_gen = app.snapshot().vault_wipe_gen;
        let wall = StubWallClock::new("12:00", 1_000);
        app.handle(Event::ClearHistory { include_favorites: true }, &wall);
        let wiped = sync_security_wipe_if_needed(
            &app,
            &mut last_wipe_gen,
            &outbox,
            &outbox_stage,
            &inflight,
            None,
        )
        .await;
        assert!(wiped, "must fire once vault_wipe_gen advances");
        assert!(
            lookup_cached_image(&hash_hex).is_none(),
            "a security wipe must purge a previously cached desktop image too"
        );

        image_cache().lock().expect("lock image cache").clear();
    }

    /// Phase 5: reassembly is namespaced per source peer, so two paired peers
    /// sending the same item_id get DISTINCT reassembly slots (no cross-peer
    /// chunk overwrite), while a given (peer, item_id) pair is stable.
    #[test]
    fn reassembly_key_namespaces_by_source_peer() {
        use super::reassembly_key;
        let item = [0xAAu8; 32];
        let peer_a = [1u8; 32];
        let peer_b = [2u8; 32];

        // Same peer + same item ⇒ stable key (header and chunks collate).
        assert_eq!(reassembly_key(peer_a, item), reassembly_key(peer_a, item));
        // Different source peers, same item_id ⇒ different keys (the fix).
        assert_ne!(reassembly_key(peer_a, item), reassembly_key(peer_b, item));
        // Same peer, different items ⇒ different keys.
        assert_ne!(reassembly_key(peer_a, item), reassembly_key(peer_a, [0xBBu8; 32]));
        // The key is not just the item_id passed through.
        assert_ne!(reassembly_key(peer_a, item), item);
    }

    /// FS-041: an inbound `Msg::Bye` must emit `Event::PeerLost` so the FSM
    /// closes the session and re-discovers. On `main` the shared empty match
    /// arm (`Bye | HandshakeInit | HandshakeResp`) dropped `Bye` silently.
    #[tokio::test]
    async fn fs041_bye_frame_emits_peer_lost() {
        use super::{dispatch_inbound_frame, Event, Reassembly};
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_proto::{Frame, Msg, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        // Make the Bye sender the primary peer so the primary-gated PeerLost
        // fires (FluxMesh 2C-b: only the primary peer drives the single FSM).
        let peer_id = [7u8; 32];
        transport.set_cached_peer_id(peer_id).await;
        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let outbox = Arc::new(Mutex::new(super::Outbox::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        let frame = Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::Bye,
        };
        dispatch_inbound_frame(
            frame,
            peer_id,
            &Arc::new(Mutex::new(super::SeenSet::default())),
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &inflight,
            &pending_pairs,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            None,
            &outbox,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        assert!(
            matches!(event_rx.try_recv(), Ok(Event::PeerLost { peer_id: p }) if p == peer_id),
            "Msg::Bye must emit Event::PeerLost with the sender's peer_id"
        );
    }

    /// An inbound `Msg::Revoke` must remove the sending peer from the
    /// trust store (so we don't auto-reconnect into its TOFU window)
    /// and emit `Event::PeerLost`.
    #[tokio::test]
    async fn revoke_frame_removes_trust_and_emits_peer_lost() {
        use super::{
            dispatch_inbound_frame, BackoffMap, DiscoveryCache, Event, Reassembly, ResolvedPeer,
        };
        use crate::backoff::PeerBackoff;
        use crate::handshake::tofu_trusted_peer;
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_proto::{Frame, Msg, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Instant;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let peer_id = [7u8; 32];
        transport.set_cached_peer_id(peer_id).await;

        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(peer_id, tofu_trusted_peer(peer_id));
        // DIR-P2-04a: pre-seed a stale discovery-cache entry for this peer
        // (as a real mDNS resolve would) so the test can prove Msg::Revoke
        // purges it, not just the trust store.
        let disc_cache: DiscoveryCache = Arc::new(Mutex::new(HashMap::new()));
        disc_cache.lock().await.insert(
            peer_id,
            ResolvedPeer {
                static_pub: [0x42u8; 32],
                addr: "127.0.0.1:1".parse().unwrap(),
                name: "stale-peer".into(),
                pair_pin: Some("123456".into()),
                last_seen: Instant::now(),
            },
        );
        // DIR-P1-02: pre-seed a backoff timer for this peer too, so the
        // test can prove Msg::Revoke purges it alongside disc_cache
        // (mirrors DIR-P2-04a's purge-on-revoke).
        let backoff: BackoffMap = Arc::new(Mutex::new(HashMap::new()));
        let mut pb = PeerBackoff::new();
        pb.on_attempt_failed(Instant::now(), &mut rand_core::OsRng);
        backoff.lock().await.insert(peer_id, pb);
        let outbox = Arc::new(Mutex::new(super::Outbox::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::Revoke,
            },
            peer_id,
            &Arc::new(Mutex::new(super::SeenSet::default())),
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &inflight,
            &pending_pairs,
            &trusted,
            &disc_cache,
            &backoff,
            &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            None,
            &outbox,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        assert!(
            !trusted.lock().await.contains_key(&peer_id),
            "Msg::Revoke must remove the sender from the trust store"
        );
        assert!(
            !disc_cache.lock().await.contains_key(&peer_id),
            "Msg::Revoke must purge the sender's mDNS discovery-cache entry (DIR-P2-04a)"
        );
        assert!(
            !backoff.lock().await.contains_key(&peer_id),
            "Msg::Revoke must purge the sender's backoff timer (DIR-P1-02)"
        );
        assert!(
            matches!(event_rx.try_recv(), Ok(Event::PeerLost { peer_id: p }) if p == peer_id),
            "Msg::Revoke must emit Event::PeerLost with the sender's peer_id"
        );
    }

    /// Hardening sibling of the `run_pending_reaper` fix: the FS-052 gate
    /// used to check `pending_pairs` membership ONLY, so a peer in NEITHER
    /// `trusted` NOR `pending_pairs` — exactly what a reaped/expired peer
    /// looks like once the reaper sweeps its pending entry away while its
    /// live `extra` session survives — fell through as "not pending, so
    /// allowed" and could still push clipboard data. The gate must
    /// fail-closed: a clipboard-bearing frame is only accepted from a peer
    /// that IS trusted AND is NOT still pending confirmation.
    #[tokio::test]
    async fn fs052_gate_blocks_clipboard_from_untrusted_non_pending_peer() {
        use super::{dispatch_inbound_frame, Outbox, Reassembly};
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_core::SeenSet;
        use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let peer_id = [4u8; 32];

        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        // Neither trusted nor pending — exactly what a reaped/expired peer
        // looks like once its entries are swept from both maps, while its
        // live session (not modeled here — irrelevant to this gate) survives.
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        let disc_cache = Arc::new(Mutex::new(HashMap::new()));
        let backoff = Arc::new(Mutex::new(HashMap::new()));
        let peer_meta = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        let hash = super::clipboard_dedup_hash("should be blocked");
        let item = ClipboardItem {
            lamport: 1,
            hash,
            kind: Kind::Text,
            payload: b"should be blocked".to_vec(),
            sensitive: false,
            wall_time_ms: 0,
            origin: peer_id,
            event_seq: 1,
        };

        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::ClipboardItem(item),
            },
            peer_id,
            &mesh_seen,
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &inflight,
            &pending_pairs,
            &trusted,
            &disc_cache,
            &backoff,
            &peer_meta,
            None,
            &outbox,
            &pending_pulls,
            &outbox_stage,
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        assert!(
            outbox.lock().await.is_empty(),
            "FS-052 hardening: a clipboard frame from a peer that is neither \
             trusted nor pending must be dropped, not admitted to the outbox"
        );
        assert!(
            inflight.lock().await.is_empty(),
            "a dropped frame must never be relayed either"
        );
    }

    // ── sas-confirm (FS-052 wire mutual confirm) ─────────────────

    fn test_pending_pair(expires_at: std::time::Instant) -> crate::handshake::PendingPair {
        crate::handshake::PendingPair {
            static_pub: [0x42u8; 32],
            name: "pending-peer".into(),
            sas_words: std::array::from_fn(|i| format!("word{i}")),
            from: "127.0.0.1:1".parse().unwrap(),
            expires_at,
        }
    }

    /// Inbound `Msg::PairConfirm { accept: true }` while our own pending
    /// entry still exists must refresh its 90s window (the peer's human is
    /// engaged) and emit `Event::SasPeerConfirmed`. Trust is untouched.
    #[tokio::test]
    async fn inbound_pair_confirm_accept_refreshes_pending_and_emits_peer_confirmed() {
        use super::{dispatch_inbound_frame, Event, Reassembly};
        use crate::handshake::tofu_trusted_peer;
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_proto::{Frame, Msg, PairConfirm, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let peer_id = [8u8; 32];
        transport.set_cached_peer_id(peer_id).await;

        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(peer_id, tofu_trusted_peer(peer_id));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        // Nearly-expired entry: the refresh must push it back out to ~90s.
        let soon = Instant::now() + Duration::from_secs(5);
        pending_pairs
            .lock()
            .await
            .insert(peer_id, test_pending_pair(soon));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::PairConfirm(PairConfirm { accept: true }),
            },
            peer_id,
            &Arc::new(Mutex::new(super::SeenSet::default())),
            &event_tx,
            &transport,
            &reassembly,
            &Arc::new(Mutex::new(MetricsTracker::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            None,
            &Arc::new(Mutex::new(super::Outbox::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        let refreshed = pending_pairs
            .lock()
            .await
            .get(&peer_id)
            .expect("pending entry must survive an accept")
            .expires_at;
        assert!(
            refreshed > Instant::now() + Duration::from_secs(80),
            "accept must refresh the pending window to ~90s"
        );
        assert!(
            trusted.lock().await.contains_key(&peer_id),
            "accept must not touch the trust store"
        );
        assert!(
            matches!(event_rx.try_recv(), Ok(Event::SasPeerConfirmed { peer_id: p }) if p == peer_id),
            "accept must emit Event::SasPeerConfirmed with the matching peer_id"
        );
    }

    /// Legacy echo-ack path (peers with `sas-confirm` but not
    /// `verify-restart` — two working-tree builds never reach it, so the
    /// loopback tests can't cover it): an inbound `PairConfirm{accept:true}`
    /// from a TRUSTED peer with NO pending entry and NO live SAS flow gets
    /// exactly one once-per-session echo-ack (loop guard), never advances
    /// our own sas_phase, and never fires for an untrusted or
    /// legacy-without-sas-confirm sender.
    #[tokio::test]
    async fn inbound_pair_confirm_accept_outside_flow_echo_acks_once_for_trusted_sas_peer() {
        use super::{dispatch_inbound_frame, Reassembly};
        use crate::handshake::tofu_trusted_peer;
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_proto::{Frame, Msg, PairConfirm, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let peer_id = [11u8; 32];
        transport.set_cached_peer_id(peer_id).await;

        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(peer_id, tofu_trusted_peer(peer_id));
        // NO pending entry, idle sas_phase — the outside-a-flow case.
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let peer_meta: super::PeerMetaMap =
            Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        {
            let mut meta = peer_meta.lock().await;
            let e = meta.entry(peer_id).or_insert_with(super::PeerMeta::new);
            e.caps = vec!["core-1".into(), "sas-confirm".into()];
            e.hello_seen = true;
        }
        let echo_ack: super::EchoAckSent =
            Arc::new(Mutex::new(std::collections::HashSet::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        let frame = || Frame {
            version: PROTOCOL_VERSION,
            msg: Msg::PairConfirm(PairConfirm { accept: true }),
        };
        // Twice: the second delivery must be swallowed by the loop guard.
        for _ in 0..2 {
            dispatch_inbound_frame(
                frame(),
                peer_id,
                &Arc::new(Mutex::new(super::SeenSet::default())),
                &event_tx,
                &transport,
                &reassembly,
                &Arc::new(Mutex::new(MetricsTracker::new())),
                &Arc::new(Mutex::new(HashMap::new())),
                &pending_pairs,
                &trusted,
                &Arc::new(Mutex::new(HashMap::new())),
                &Arc::new(Mutex::new(HashMap::new())),
                &peer_meta,
                None,
                &Arc::new(Mutex::new(super::Outbox::new())),
                &Arc::new(Mutex::new(HashMap::new())),
                &Arc::new(Mutex::new(HashMap::new())),
                &state_rx,
                &Arc::new(Mutex::new(std::collections::HashSet::new())),
                &echo_ack,
                &Arc::new(Mutex::new(HashMap::new())),
            )
            .await;
        }
        assert!(
            echo_ack.lock().await.contains(&peer_id),
            "trusted+sas-confirm sender outside a flow must be echo-acked"
        );
        assert_eq!(
            echo_ack.lock().await.len(),
            1,
            "the loop guard must keep the echo to once per session"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "an outside-a-flow accept must not advance our own sas_phase"
        );

        // Untrusted sender: same shape, different peer — never acked.
        let stranger = [12u8; 32];
        dispatch_inbound_frame(
            frame(),
            stranger,
            &Arc::new(Mutex::new(super::SeenSet::default())),
            &event_tx,
            &transport,
            &reassembly,
            &Arc::new(Mutex::new(MetricsTracker::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &peer_meta,
            None,
            &Arc::new(Mutex::new(super::Outbox::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &echo_ack,
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;
        assert!(
            !echo_ack.lock().await.contains(&stranger),
            "an untrusted sender must never be echo-acked"
        );

        // Trusted but WITHOUT the `sas-confirm` cap: also never acked (an
        // old build could not decode the echo anyway).
        let legacy = [13u8; 32];
        trusted
            .lock()
            .await
            .insert(legacy, tofu_trusted_peer(legacy));
        {
            let mut meta = peer_meta.lock().await;
            let e = meta.entry(legacy).or_insert_with(super::PeerMeta::new);
            e.caps = vec!["core-1".into()];
            e.hello_seen = true;
        }
        dispatch_inbound_frame(
            frame(),
            legacy,
            &Arc::new(Mutex::new(super::SeenSet::default())),
            &event_tx,
            &transport,
            &reassembly,
            &Arc::new(Mutex::new(MetricsTracker::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &peer_meta,
            None,
            &Arc::new(Mutex::new(super::Outbox::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &echo_ack,
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;
        assert!(
            !echo_ack.lock().await.contains(&legacy),
            "a trusted peer without `sas-confirm` must never be echo-acked"
        );
    }

    /// verify-restart: an inbound `Msg::PairVerifyStarted` from a TRUSTED
    /// peer with a live session and no pending/flow on our side must insert
    /// a real pending pair whose 6 SAS words derive from the session's
    /// Noise transcript hash, and fire `Event::SasPairingStarted`. An
    /// untrusted sender is ignored, and a duplicate announcement does not
    /// reset an existing flow.
    #[tokio::test]
    async fn inbound_pair_verify_started_reopens_pending_for_trusted_peer_only() {
        use super::{dispatch_inbound_frame, Event, Reassembly};
        use crate::handshake::tofu_trusted_peer;
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use fluxsync_proto::{Frame, Msg, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let peer_id = [21u8; 32];

        // A real session so the handler has a transcript hash to derive
        // words from; the expected words come from the same hash.
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let (sess_local, _sess_peer) = pair_for_test(&id_a, &id_b).expect("pair");
        let expected_words: Vec<String> =
            fluxsync_crypto::fingerprint_from_handshake_hash(sess_local.handshake_hash())
                .iter()
                .map(|w| (*w).to_string())
                .collect();
        transport.install_session(peer_id, sess_local).await;
        transport
            .set_peer_info(peer_id, "127.0.0.1:1".parse().unwrap())
            .await;

        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        let dispatch = |sender: [u8; 32]| {
            let event_tx = event_tx.clone();
            let transport = transport.clone();
            let reassembly = reassembly.clone();
            let trusted = trusted.clone();
            let pending_pairs = pending_pairs.clone();
            let state_rx = state_rx.clone();
            async move {
                dispatch_inbound_frame(
                    Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::PairVerifyStarted,
                    },
                    sender,
                    &Arc::new(Mutex::new(super::SeenSet::default())),
                    &event_tx,
                    &transport,
                    &reassembly,
                    &Arc::new(Mutex::new(MetricsTracker::new())),
                    &Arc::new(Mutex::new(HashMap::new())),
                    &pending_pairs,
                    &trusted,
                    &Arc::new(Mutex::new(HashMap::new())),
                    &Arc::new(Mutex::new(HashMap::new())),
                    &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
                    None,
                    &Arc::new(Mutex::new(super::Outbox::new())),
                    &Arc::new(Mutex::new(HashMap::new())),
                    &Arc::new(Mutex::new(HashMap::new())),
                    &state_rx,
                    &Arc::new(Mutex::new(std::collections::HashSet::new())),
                    &Arc::new(Mutex::new(std::collections::HashSet::new())),
                    &Arc::new(Mutex::new(HashMap::new())),
                )
                .await;
            }
        };

        // Untrusted sender first: must be ignored outright.
        dispatch(peer_id).await;
        assert!(
            pending_pairs.lock().await.is_empty(),
            "an untrusted PairVerifyStarted must never create a pending pair"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "an untrusted PairVerifyStarted must not fire SasPairingStarted"
        );

        // Trusted sender: pending inserted with the transcript-derived
        // words + SasPairingStarted fired.
        trusted
            .lock()
            .await
            .insert(peer_id, tofu_trusted_peer(peer_id));
        dispatch(peer_id).await;
        {
            let g = pending_pairs.lock().await;
            let p = g
                .get(&peer_id)
                .expect("trusted PairVerifyStarted must insert a pending pair");
            assert_eq!(
                p.sas_words.to_vec(),
                expected_words,
                "pending words must derive from the session's Noise transcript hash"
            );
        }
        assert!(
            matches!(event_rx.try_recv(), Ok(Event::SasPairingStarted { peer_id: p }) if p == peer_id),
            "trusted PairVerifyStarted must fire Event::SasPairingStarted"
        );

        // Duplicate announcement: the existing pending must survive
        // untouched and no second SasPairingStarted may fire.
        let expires_before = pending_pairs.lock().await.get(&peer_id).unwrap().expires_at;
        dispatch(peer_id).await;
        assert_eq!(
            pending_pairs.lock().await.get(&peer_id).unwrap().expires_at,
            expires_before,
            "a duplicate PairVerifyStarted must not reset the pending entry"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "a duplicate PairVerifyStarted must not re-fire SasPairingStarted"
        );
    }

    /// Inbound `Msg::PairConfirm { accept: false }` is a wire-level reject:
    /// same effect as a local reject — pending + trust purged, session
    /// dropped — plus `Event::SasPeerRejected` so the UI can say why.
    #[tokio::test]
    async fn inbound_pair_confirm_reject_revokes_trust_and_emits_peer_rejected() {
        use super::{dispatch_inbound_frame, Event, Reassembly};
        use crate::handshake::tofu_trusted_peer;
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_proto::{Frame, Msg, PairConfirm, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let peer_id = [9u8; 32];
        transport.set_cached_peer_id(peer_id).await;

        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(peer_id, tofu_trusted_peer(peer_id));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        pending_pairs
            .lock()
            .await
            .insert(peer_id, test_pending_pair(Instant::now() + Duration::from_secs(60)));
        let deferred: super::DeferredSasConfirm =
            Arc::new(Mutex::new(std::collections::HashSet::new()));
        deferred.lock().await.insert(peer_id);
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::PairConfirm(PairConfirm { accept: false }),
            },
            peer_id,
            &Arc::new(Mutex::new(super::SeenSet::default())),
            &event_tx,
            &transport,
            &reassembly,
            &Arc::new(Mutex::new(MetricsTracker::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            None,
            &Arc::new(Mutex::new(super::Outbox::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &state_rx,
            &deferred,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        assert!(
            !pending_pairs.lock().await.contains_key(&peer_id),
            "reject must remove the pending entry"
        );
        assert!(
            !trusted.lock().await.contains_key(&peer_id),
            "reject must revoke the sender from the trust store"
        );
        assert!(
            !deferred.lock().await.contains(&peer_id),
            "reject must clear any deferred local accept"
        );
        assert!(
            matches!(event_rx.try_recv(), Ok(Event::SasPeerRejected { peer_id: p }) if p == peer_id),
            "reject must emit Event::SasPeerRejected with the matching peer_id first"
        );
        assert!(
            matches!(event_rx.try_recv(), Ok(Event::PeerLost { peer_id: p }) if p == peer_id),
            "reject must emit Event::PeerLost with the matching peer_id after the teardown"
        );
    }

    /// L3 fix: an inbound reject from a peer with no pending entry of its
    /// own — the "again-trusted peer" case the bug describes — must NOT
    /// emit `Event::SasPeerRejected` while a DIFFERENT peer's SAS flow is
    /// the one actually live (`State.sas_peer` names someone else). Trust
    /// revocation for the stray peer is unconditional and untouched by
    /// this fix; only the phase-stomping event is suppressed.
    #[tokio::test]
    async fn inbound_pair_confirm_reject_from_non_pairing_peer_does_not_emit_sas_event() {
        use super::{dispatch_inbound_frame, Reassembly};
        use crate::handshake::tofu_trusted_peer;
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_proto::{Frame, Msg, PairConfirm, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let stray_peer = [21u8; 32];
        let other_pairing_peer = [22u8; 32];
        // Cache the OTHER peer as primary, not the stray one, so the
        // reject branch's final `PeerLost` emission is skipped too —
        // isolating this test to just the `SasPeerRejected` guard.
        transport.set_cached_peer_id(other_pairing_peer).await;

        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(stray_peer, tofu_trusted_peer(stray_peer));
        // No pending entry for `stray_peer` at all.
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

        // A DIFFERENT peer's pairing is the one actually live.
        let mut live_state = fluxsync_core::State::initial(&fluxsync_core::Config::default());
        live_state.sas_phase = "showing".to_string();
        live_state.sas_peer = Some(other_pairing_peer);
        let (_state_tx, state_rx) = tokio::sync::watch::channel(live_state);

        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::PairConfirm(PairConfirm { accept: false }),
            },
            stray_peer,
            &Arc::new(Mutex::new(super::SeenSet::default())),
            &event_tx,
            &transport,
            &reassembly,
            &Arc::new(Mutex::new(MetricsTracker::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            None,
            &Arc::new(Mutex::new(super::Outbox::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        // Trust revocation is unconditional and untouched by this fix.
        assert!(
            !trusted.lock().await.contains_key(&stray_peer),
            "an explicit reject still revokes trust regardless of the SAS-flow guard"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "a stray reject outside any live SAS flow for THIS peer must not emit \
             SasPeerRejected — nor anything else, since it isn't cached as primary"
        );
    }

    // ── resync-1 ─────────────────────────────────────────────────

    /// resync-1: hashes we don't hold are returned in the offer's original
    /// order, with held hashes (history or outbox) filtered out.
    #[test]
    fn missing_resync_hashes_filters_held_and_preserves_order() {
        use super::missing_resync_hashes;
        let offered = vec![
            "aa".to_string(),
            "bb".to_string(),
            "cc".to_string(),
            "dd".to_string(),
        ];
        let history = vec!["bb".to_string()];
        let outbox_hashes = vec!["dd".to_string()];
        let missing = missing_resync_hashes(&offered, &history, &outbox_hashes, &[], &[]);
        assert_eq!(missing, vec!["aa".to_string(), "cc".to_string()]);
    }

    /// resync-1: nothing missing when every offered hash is already held.
    #[test]
    fn missing_resync_hashes_empty_when_all_held() {
        use super::missing_resync_hashes;
        let offered = vec!["aa".to_string(), "bb".to_string()];
        let history = vec!["aa".to_string()];
        let outbox_hashes = vec!["bb".to_string()];
        assert!(missing_resync_hashes(&offered, &history, &outbox_hashes, &[], &[]).is_empty());
    }

    /// H2: a deliberately-cleared hash is excluded from the pull list even
    /// though the peer still offers it, while a genuinely-missing, never
    /// cleared hash is still returned — proves the tombstone gates exactly
    /// the cleared hash(es), not resync in general.
    #[test]
    fn missing_resync_hashes_excludes_cleared_but_keeps_genuinely_missing() {
        use super::missing_resync_hashes;
        let cleared_x = "aa".repeat(32);
        let missing_y = "bb".repeat(32);
        let offered = vec![cleared_x.clone(), missing_y.clone()];
        let missing = missing_resync_hashes(&offered, &[], &[], std::slice::from_ref(&cleared_x), &[]);
        assert_eq!(
            missing,
            vec![missing_y],
            "cleared hash X must be excluded; genuinely-missing hash Y must still be pulled"
        );
    }

    /// resync-1: defensive cap — even if a caller hands in more than
    /// `MAX_RESYNC_HASHES` offered hashes, the result never exceeds it.
    #[test]
    fn missing_resync_hashes_caps_at_max_resync_hashes() {
        use super::{missing_resync_hashes, MAX_RESYNC_HASHES};
        let offered: Vec<String> = (0..(MAX_RESYNC_HASHES + 5))
            .map(|i| format!("{i:064x}"))
            .collect();
        let missing = missing_resync_hashes(&offered, &[], &[], &[], &[]);
        assert_eq!(missing.len(), MAX_RESYNC_HASHES);
        assert_eq!(missing[0], offered[0], "must keep the offer's original order");
    }

    /// resync-1: a `ResyncOffer` hex-encodes each outbox hash, preserving
    /// `Outbox::hashes`' (newest-first) order.
    #[test]
    fn build_resync_offer_hex_encodes_in_given_order() {
        use super::build_resync_offer;
        let h1 = [0x11u8; 32];
        let h2 = [0x22u8; 32];
        let offer = build_resync_offer(&[h1, h2]);
        assert_eq!(offer.hashes, vec![hex::encode(h1), hex::encode(h2)]);
    }

    /// resync-1: an empty outbox produces an empty offer (the `Msg::Hello`
    /// handler is expected to skip sending one in that case).
    #[test]
    fn build_resync_offer_empty_outbox_yields_empty_offer() {
        use super::build_resync_offer;
        assert!(build_resync_offer(&[]).hashes.is_empty());
    }

    /// resync-1 security invariant: a sensitive item must never enter the
    /// outbox on first-sight reception, while a non-sensitive one does —
    /// mirrors the same gate `app.rs` already applies before history
    /// insertion (see `crate::outbox`'s module doc).
    #[tokio::test]
    async fn complete_reassembled_item_gates_outbox_on_sensitivity() {
        use super::{complete_reassembled_item, Outbox};
        use crate::transport::Transport;
        use fluxsync_core::SeenSet;
        use fluxsync_proto::Kind;
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        // Default (disabled) firewall decides Pass for any non-sensitive
        // item, so this exercises the immediate-insert branch of the
        // Pass/Ask/Block mirror in `complete_reassembled_item`.
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        // SE-14 (Fix D): `complete_reassembled_item` now verifies the claimed
        // hash against the payload before doing anything else, so these must
        // be real `clipboard_dedup_hash` values, not arbitrary constants.
        let sensitive_hash = super::clipboard_dedup_hash("secret");
        complete_reassembled_item(
            &transport,
            &inflight,
            &mesh_seen,
            &event_tx,
            [1u8; 32],
            [2u8; 32],
            1,
            sensitive_hash,
            Kind::Text,
            true,
            0,
            b"secret".to_vec(),
            &outbox,
            &outbox_stage,
            &pending_pulls,
            &state_rx,
            &pending_pairs,
        )
        .await;
        assert!(
            outbox.lock().await.get(sensitive_hash).is_none(),
            "sensitive item must not enter the outbox"
        );

        let plain_hash = super::clipboard_dedup_hash("hello");
        complete_reassembled_item(
            &transport,
            &inflight,
            &mesh_seen,
            &event_tx,
            [1u8; 32],
            [2u8; 32],
            2,
            plain_hash,
            Kind::Text,
            false,
            0,
            b"hello".to_vec(),
            &outbox,
            &outbox_stage,
            &pending_pulls,
            &state_rx,
            &pending_pairs,
        )
        .await;
        assert!(
            outbox.lock().await.get(plain_hash).is_some(),
            "non-sensitive item must enter the outbox"
        );
    }

    /// DIR-P2-05 sibling of `complete_reassembled_item_gates_outbox_on_sensitivity`:
    /// the outbox gate is keyed on `sensitive` alone, not on `Kind` — so a
    /// sensitive IMAGE (the new `CmdOp::PushImage { sensitive: true }` path)
    /// must be excluded exactly like a sensitive text item, while a
    /// non-sensitive image still populates the outbox normally.
    #[tokio::test]
    async fn complete_reassembled_item_gates_outbox_on_sensitivity_for_images() {
        use super::{complete_reassembled_item, Outbox};
        use crate::transport::Transport;
        use fluxsync_core::SeenSet;
        use fluxsync_proto::Kind;
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        // SE-14 (Fix D): `complete_reassembled_item` now verifies an image's
        // claimed hash against its decoded RGBA before anything else, so
        // these need a real (tiny, 1x1) PNG + its matching `image_rgba_hash`
        // instead of arbitrary constants over non-PNG bytes.
        let secret_rgba = vec![10u8, 20, 30, 255];
        let secret_png = super::encode_png(1, 1, secret_rgba.clone()).expect("encode test png");
        let sensitive_hash = super::image_rgba_hash(1, 1, &secret_rgba);
        complete_reassembled_item(
            &transport,
            &inflight,
            &mesh_seen,
            &event_tx,
            [1u8; 32],
            [2u8; 32],
            1,
            sensitive_hash,
            Kind::Image,
            true,
            0,
            secret_png,
            &outbox,
            &outbox_stage,
            &pending_pulls,
            &state_rx,
            &pending_pairs,
        )
        .await;
        assert!(
            outbox.lock().await.get(sensitive_hash).is_none(),
            "sensitive image must not enter the outbox"
        );

        let plain_rgba = vec![40u8, 50, 60, 255];
        let plain_png = super::encode_png(1, 1, plain_rgba.clone()).expect("encode test png");
        let plain_hash = super::image_rgba_hash(1, 1, &plain_rgba);
        complete_reassembled_item(
            &transport,
            &inflight,
            &mesh_seen,
            &event_tx,
            [1u8; 32],
            [2u8; 32],
            2,
            plain_hash,
            Kind::Image,
            false,
            0,
            plain_png,
            &outbox,
            &outbox_stage,
            &pending_pulls,
            &state_rx,
            &pending_pairs,
        )
        .await;
        assert!(
            outbox.lock().await.get(plain_hash).is_some(),
            "non-sensitive image must enter the outbox"
        );
    }

    /// FIX1 (P0 parked-payload leak), integration point (b): a revoked
    /// peer's `PendingOutboxStage` entry — staged by the REAL
    /// `complete_reassembled_item` admission-gate path when the firewall
    /// parks an inbound item under `Ask` — must be purged by
    /// `purge_dropped_pending_from_outbox_stage` once `fluxsync_core`
    /// reports it dropped via `Event::PeerRevoked`'s `Action::
    /// PendingDropped`. A DIFFERENT peer's staged entry must survive.
    ///
    /// This can't be proven as a daemon-level black-box IPC test: an
    /// already-purged pending row and a leaked-but-orphaned
    /// `PendingOutboxStage` entry are externally indistinguishable (neither
    /// is ever promoted without a live `state.pending` row to approve, and
    /// that row is gone in both cases) — the leak is a pure process-memory
    /// residency issue. So this drives the exact real functions instead:
    /// the daemon's own staging path (`complete_reassembled_item`) plus the
    /// core's own revoke path (`App::handle(Event::PeerRevoked)`) plus the
    /// daemon's own purge helper, wired together exactly as `run()`'s main
    /// loop and `CmdOp::Revoke` do.
    #[tokio::test]
    async fn revoke_purges_only_that_peers_staged_outbox_entry() {
        use super::{complete_reassembled_item, purge_dropped_pending_from_outbox_stage, Outbox};
        use crate::transport::Transport;
        use fluxsync_core::{
            Action, App, Config, Event, FirewallPolicy, Rule, SeenSet, StubWallClock,
        };
        use fluxsync_proto::Kind;
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        const PEER_A: [u8; 32] = [0xAAu8; 32];
        const PEER_B: [u8; 32] = [0xBBu8; 32];
        // SE-14 (Fix D): must be the real content hash of each payload below,
        // not arbitrary constants — `complete_reassembled_item` now verifies
        // it before staging anything.
        let hash_a = super::clipboard_dedup_hash("secret-a");
        let hash_b = super::clipboard_dedup_hash("secret-b");

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

        let firewall = FirewallPolicy {
            enabled: true,
            text: Rule::Ask,
            ..FirewallPolicy::default()
        };
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &Config { firewall: firewall.clone(), ..Config::default() },
        ));

        // Real staging path: both items are Ask-deferred, so both land in
        // `outbox_stage`, neither in the real `outbox`.
        complete_reassembled_item(
            &transport, &inflight, &mesh_seen, &event_tx, PEER_A, PEER_A, 1, hash_a, Kind::Text,
            false, 0, b"secret-a".to_vec(), &outbox, &outbox_stage, &pending_pulls, &state_rx,
            &pending_pairs,
        )
        .await;
        complete_reassembled_item(
            &transport, &inflight, &mesh_seen, &event_tx, PEER_B, PEER_B, 1, hash_b, Kind::Text,
            false, 0, b"secret-b".to_vec(), &outbox, &outbox_stage, &pending_pulls, &state_rx,
            &pending_pairs,
        )
        .await;
        assert_eq!(
            outbox_stage.lock().await.len(),
            2,
            "precondition: both peers' Ask-deferred items must be staged"
        );
        assert!(
            outbox.lock().await.is_empty(),
            "precondition: neither is admitted to the real outbox yet"
        );

        // Real core-side park: mirrors what the main loop's `app.handle`
        // would have done with the `Event::FrameReceivedClipboard` that
        // `complete_reassembled_item` sent via `event_tx` above.
        let mut app = App::new(Config { firewall, ..Config::default() });
        let wall = StubWallClock::new("12:00", 1_000);
        // Distinct payloads per peer — the core content-dedup ring keys on
        // the PAYLOAD, not the hash param, so two identical payloads here
        // would make the second `handle` call a no-op duplicate and never
        // reach the firewall park at all.
        for (peer_id, hash, text) in [(PEER_A, hash_a, "irrelevant-a"), (PEER_B, hash_b, "irrelevant-b")] {
            app.handle(
                Event::FrameReceivedClipboard {
                    peer_id,
                    hash,
                    kind: Kind::Text,
                    payload: text.as_bytes().to_vec(),
                    preview: text.into(),
                    sensitive: false,
                    lamport: 1,
                    resync: false,
                },
                &wall,
            );
        }
        assert_eq!(app.snapshot().pending.len(), 2, "precondition: both parked");

        // Real revoke path + real purge helper.
        let actions = app.handle(Event::PeerRevoked { peer_id: PEER_A }, &wall);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::PendingDropped { hashes } if hashes == &[hash_a])),
            "PeerRevoked must report exactly A's dropped hash"
        );
        purge_dropped_pending_from_outbox_stage(&actions, &outbox_stage).await;

        let stage = outbox_stage.lock().await;
        assert!(
            stage.get(&hash_a).is_none(),
            "FIXED: A's revoked staged outbox entry must be purged"
        );
        assert!(
            stage.get(&hash_b).is_some(),
            "B's staged outbox entry must survive A's revoke"
        );
    }

    /// Item 2 (firewall-enforcing relay): an inbound item the LOCAL firewall
    /// Blocks must not reach any OTHER mesh peer either. `forward_frames`
    /// used to run unconditionally in `complete_reassembled_item`, ignoring
    /// the exact same Pass/Ask/Block decision it had just computed a few
    /// lines above for outbox admission. `sensitive` items are deliberately
    /// exempt from this gate (ephemeral; the destination must still receive
    /// them) — case 3 below proves that invariant survives the fix.
    #[tokio::test]
    async fn complete_reassembled_item_does_not_relay_a_firewall_blocked_item() {
        use super::{complete_reassembled_item, Outbox};
        use crate::transport::Transport;
        use fluxsync_core::{Config, FirewallPolicy, Rule, SeenSet};
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use fluxsync_proto::Kind;
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        const SOURCE: [u8; 32] = [0x11u8; 32]; // direct sender, also origin here

        let self_id = Identity::generate();
        let downstream_id = Identity::generate();
        let downstream_peer = downstream_id.peer_id();
        let (sess_downstream, _) =
            pair_for_test(&self_id, &downstream_id).expect("pair downstream");

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        // A second mesh peer with a live session — the relay TARGET that
        // must NOT receive a firewall-Blocked item.
        transport.install_session(downstream_peer, sess_downstream).await;

        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

        // ── 1. Blocked (non-sensitive text): must NOT relay downstream. ──
        let block_firewall =
            FirewallPolicy { enabled: true, text: Rule::Deny, ..FirewallPolicy::default() };
        let (_tx1, state_rx1) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &Config { firewall: block_firewall, ..Config::default() },
        ));
        let hash_blocked = super::clipboard_dedup_hash("relay-blocked-text");
        complete_reassembled_item(
            &transport, &inflight, &mesh_seen, &event_tx, SOURCE, SOURCE, 1, hash_blocked,
            Kind::Text, false, 0, b"relay-blocked-text".to_vec(), &outbox, &outbox_stage,
            &pending_pulls, &state_rx1, &pending_pairs,
        )
        .await;
        assert!(
            inflight.lock().await.get(&hash_blocked).is_none(),
            "FIXED: a firewall-Blocked item must NOT be relayed to another mesh peer"
        );

        // ── 2. control: Allow (Pass) — must relay downstream. ──
        let pass_firewall =
            FirewallPolicy { enabled: true, text: Rule::Allow, ..FirewallPolicy::default() };
        let (_tx2, state_rx2) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &Config { firewall: pass_firewall, ..Config::default() },
        ));
        let hash_passed = super::clipboard_dedup_hash("relay-passed-text");
        complete_reassembled_item(
            &transport, &inflight, &mesh_seen, &event_tx, SOURCE, SOURCE, 2, hash_passed,
            Kind::Text, false, 0, b"relay-passed-text".to_vec(), &outbox, &outbox_stage,
            &pending_pulls, &state_rx2, &pending_pairs,
        )
        .await;
        assert!(
            inflight
                .lock()
                .await
                .get(&hash_passed)
                .is_some_and(|inf| inf.pending_peers.contains(&downstream_peer)),
            "control: a firewall-Passed item must still relay to the other mesh peer"
        );

        // ── 3. CRITICAL INVARIANT: sensitive items always relay, even under
        //        a Blocking firewall (they're ephemeral; the destination
        //        must still receive them — never gated by content policy). ──
        let hash_sensitive = super::clipboard_dedup_hash("relay-sensitive-secret");
        complete_reassembled_item(
            &transport, &inflight, &mesh_seen, &event_tx, SOURCE, SOURCE, 3, hash_sensitive,
            Kind::Text, true, 0, b"relay-sensitive-secret".to_vec(), &outbox, &outbox_stage,
            &pending_pulls, &state_rx1, &pending_pairs,
        )
        .await;
        assert!(
            inflight
                .lock()
                .await
                .get(&hash_sensitive)
                .is_some_and(|inf| inf.pending_peers.contains(&downstream_peer)),
            "CRITICAL INVARIANT: a sensitive item must still relay even under a Blocking firewall"
        );
    }

    /// resync-1: the common case — a small clipboard item arrives as a
    /// single `ClipboardItem` frame (payload non-empty) and never touches
    /// `complete_reassembled_item`, which only runs for chunked/reassembled
    /// transfers. This path must independently populate the outbox on
    /// first sight, gated on sensitivity the same way.
    #[tokio::test]
    async fn dispatch_inbound_frame_single_frame_item_populates_outbox_when_not_sensitive() {
        use super::{dispatch_inbound_frame, Outbox, Reassembly};
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_core::SeenSet;
        use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let peer_id = [9u8; 32];
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        // The hardened FS-052 gate drops clipboard frames from a peer that
        // is not in `trusted`; this test targets the outbox population
        // downstream of it, so the sender must be trusted.
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(peer_id, crate::handshake::tofu_trusted_peer(peer_id));
        let disc_cache = Arc::new(Mutex::new(HashMap::new()));
        let backoff = Arc::new(Mutex::new(HashMap::new()));
        let peer_meta = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        // SE-14 (Fix D): must be the real content hash of the payload below —
        // `dispatch_inbound_frame` now verifies it before touching the outbox.
        let hash = super::clipboard_dedup_hash("hello resync");
        let item = ClipboardItem {
            lamport: 1,
            hash,
            kind: Kind::Text,
            payload: b"hello resync".to_vec(),
            sensitive: false,
            wall_time_ms: 0,
            origin: [3u8; 32],
            event_seq: 5,
        };
        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::ClipboardItem(item),
            },
            peer_id,
            &mesh_seen,
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &inflight,
            &pending_pairs,
            &trusted,
            &disc_cache,
            &backoff,
            &peer_meta,
            None,
            &outbox,
            &pending_pulls,
            &outbox_stage,
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        let entry = outbox
            .lock()
            .await
            .get(hash)
            .cloned()
            .expect("non-sensitive single-frame item must populate the outbox");
        assert_eq!(entry.origin, [3u8; 32]);
        assert_eq!(entry.seq, 5);
        assert_eq!(entry.payload, b"hello resync");
    }

    /// Item 2 (firewall-enforcing relay), single-frame `ClipboardItem` site:
    /// the sibling gate to `complete_reassembled_item_does_not_relay_a_
    /// firewall_blocked_item` above, but for the path most clipboard items
    /// actually take (small enough to arrive as one frame, never touching
    /// `complete_reassembled_item`). `forward_item` used to run
    /// unconditionally here too.
    #[tokio::test]
    async fn dispatch_inbound_frame_single_frame_item_does_not_relay_when_firewall_blocks() {
        use super::{dispatch_inbound_frame, Outbox, Reassembly};
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_core::{Config, FirewallPolicy, Rule, SeenSet};
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let sender_id = Identity::generate();
        let downstream_id = Identity::generate();
        let peer_id = sender_id.peer_id();
        let downstream_peer = downstream_id.peer_id();
        let (sess_downstream, _) =
            pair_for_test(&sender_id, &downstream_id).expect("pair downstream");

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        // A second mesh peer with a live session — the relay TARGET that
        // must NOT receive a firewall-Blocked item.
        transport.install_session(downstream_peer, sess_downstream).await;

        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(peer_id, crate::handshake::tofu_trusted_peer(peer_id));
        let disc_cache = Arc::new(Mutex::new(HashMap::new()));
        let backoff = Arc::new(Mutex::new(HashMap::new()));
        let peer_meta = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));

        let block_firewall =
            FirewallPolicy { enabled: true, text: Rule::Deny, ..FirewallPolicy::default() };
        let (_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &Config { firewall: block_firewall, ..Config::default() },
        ));

        let hash = super::clipboard_dedup_hash("single-frame-relay-blocked");
        let item = ClipboardItem {
            lamport: 1,
            hash,
            kind: Kind::Text,
            payload: b"single-frame-relay-blocked".to_vec(),
            sensitive: false,
            wall_time_ms: 0,
            origin: peer_id,
            event_seq: 7,
        };
        dispatch_inbound_frame(
            Frame { version: PROTOCOL_VERSION, msg: Msg::ClipboardItem(item) },
            peer_id,
            &mesh_seen,
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &inflight,
            &pending_pairs,
            &trusted,
            &disc_cache,
            &backoff,
            &peer_meta,
            None,
            &outbox,
            &pending_pulls,
            &outbox_stage,
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        assert!(
            outbox.lock().await.get(hash).is_none(),
            "precondition: a firewall-Blocked item must not enter this node's own outbox"
        );
        assert!(
            inflight.lock().await.get(&hash).is_none(),
            "FIXED: a firewall-Blocked single-frame item must NOT be relayed to another mesh peer"
        );
    }

    // ── Phase 5 round 3 regressions ─────────────────────────────

    /// FS-052 egress hole fix (Fix A, part 1): `Action::SendItem`'s fan-out
    /// used to send to every `transport.linked_peer_ids()` peer regardless
    /// of pending status — `gate_outbound` only suppresses the whole action
    /// when the PRIMARY peer is pending. A pending SECONDARY mesh peer with
    /// a live session must now be excluded from both the wire send and the
    /// `Inflight::pending_peers` ack-tracking set.
    #[tokio::test]
    async fn send_item_fan_out_excludes_pending_secondary_peer() {
        use super::{dispatch, Outbox};
        use crate::transport::Transport;
        use fluxsync_core::{Action, App, Config};
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use fluxsync_proto::Kind;
        use std::collections::{BTreeMap, HashMap, VecDeque};
        use std::sync::Arc;
        use tokio::sync::{broadcast, watch, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);

        let self_id = Identity::generate();
        let confirmed_id = Identity::generate();
        let pending_id = Identity::generate();
        let confirmed_peer = confirmed_id.peer_id();
        let pending_peer = pending_id.peer_id();

        let (sess_confirmed, _) = pair_for_test(&self_id, &confirmed_id).expect("pair confirmed");
        let (sess_pending, _) = pair_for_test(&self_id, &pending_id).expect("pair pending");
        // First install claims the primary slot, the second lands in `extra`
        // — both then show up in `linked_peer_ids()` (FluxMesh 2C-b).
        transport.install_session(confirmed_peer, sess_confirmed).await;
        transport.install_session(pending_peer, sess_pending).await;
        assert_eq!(
            transport.linked_peer_ids().await.len(),
            2,
            "precondition: two live sessions"
        );

        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        pending_pairs.lock().await.insert(
            pending_peer,
            test_pending_pair(std::time::Instant::now() + std::time::Duration::from_secs(60)),
        );

        let mut app = App::new(Config::default());
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        let (state_watch_tx, _state_watch_rx) =
            watch::channel(fluxsync_core::State::initial(&Config::default()));
        let (logs_bcast_tx, _logs_rx) = broadcast::channel(16);
        let log_tail = Arc::new(super::LogTail::new());
        let last_written_hashes = Arc::new(Mutex::new(VecDeque::new()));
        let metrics = Arc::new(Mutex::new(crate::metrics::MetricsTracker::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(BTreeMap::new()));
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let mut seq_store: Option<crate::seq_store::SeqStore> = None;

        let hash = super::clipboard_dedup_hash("mesh secret");
        let actions = vec![Action::SendItem {
            hash,
            kind: Kind::Text,
            payload: b"mesh secret".to_vec(),
            sensitive: false,
        }];

        dispatch(
            actions,
            &mut app,
            &transport,
            &trusted,
            None,
            &state_watch_tx,
            &logs_bcast_tx,
            &log_tail,
            &last_written_hashes,
            &metrics,
            &inflight,
            &peer_meta,
            &outbox,
            &pending_pairs,
            &mut seq_store,
        )
        .await;

        let inf = inflight.lock().await;
        let entry = inf
            .get(&hash)
            .expect("item must still be inflight for the confirmed peer");
        assert!(
            entry.pending_peers.contains(&confirmed_peer),
            "the confirmed peer must be awaited for an ack"
        );
        assert!(
            !entry.pending_peers.contains(&pending_peer),
            "FS-052: an unconfirmed pending peer must NOT be in the SendItem fan-out"
        );
    }

    /// Sibling of `send_item_fan_out_excludes_pending_secondary_peer` for the
    /// MESH RELAY path (`forward_frames`/`forward_item`, driven by an inbound
    /// `Msg::ClipboardItem` from a third peer) rather than the local-origin
    /// `Action::SendItem` path. Before the fix, `forward_frames` computed its
    /// targets as `linked_peer_ids().filter(|d| *d != source && *d != origin)`
    /// with no `pending_pairs` check at all, so a confirmed peer's relayed
    /// clipboard reached any linked-but-unconfirmed TOFU secondary — bypassing
    /// the FS-052 confirmation gate entirely.
    #[tokio::test]
    async fn mesh_relay_excludes_pending_secondary_peer() {
        use super::{dispatch_inbound_frame, Outbox, Reassembly};
        use crate::handshake::tofu_trusted_peer;
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_core::SeenSet;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
        use std::collections::{BTreeMap, HashMap};
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);

        let self_id = Identity::generate();
        let source_id = Identity::generate();
        let confirmed_id = Identity::generate();
        let pending_id = Identity::generate();
        let source_peer = source_id.peer_id();
        let confirmed_peer = confirmed_id.peer_id();
        let pending_peer = pending_id.peer_id();

        let (sess_confirmed, _) = pair_for_test(&self_id, &confirmed_id).expect("pair confirmed");
        let (sess_pending, _) = pair_for_test(&self_id, &pending_id).expect("pair pending");
        // First install claims the primary slot, the second lands in `extra`
        // (FluxMesh 2C-b) — both are candidate mesh-relay targets for an item
        // whose sender is a THIRD peer (`source_peer`). The source itself is
        // deliberately never installed with a session: `forward_item`'s
        // targets come from `linked_peer_ids()`, and `ack_source`/relay both
        // tolerate a sourceless send failing silently.
        transport.install_session(confirmed_peer, sess_confirmed).await;
        transport.install_session(pending_peer, sess_pending).await;

        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(source_peer, tofu_trusted_peer(source_peer));

        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        pending_pairs.lock().await.insert(
            pending_peer,
            test_pending_pair(std::time::Instant::now() + std::time::Duration::from_secs(60)),
        );

        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let disc_cache = Arc::new(Mutex::new(HashMap::new()));
        let backoff = Arc::new(Mutex::new(HashMap::new()));
        let peer_meta = Arc::new(Mutex::new(BTreeMap::new()));
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        let hash = super::clipboard_dedup_hash("mesh relay secret");
        let item = ClipboardItem {
            lamport: 1,
            hash,
            kind: Kind::Text,
            payload: b"mesh relay secret".to_vec(),
            sensitive: false,
            wall_time_ms: 0,
            origin: source_peer,
            event_seq: 1,
        };

        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::ClipboardItem(item),
            },
            source_peer,
            &mesh_seen,
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &inflight,
            &pending_pairs,
            &trusted,
            &disc_cache,
            &backoff,
            &peer_meta,
            None,
            &outbox,
            &pending_pulls,
            &outbox_stage,
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        let inf = inflight.lock().await;
        let entry = inf
            .get(&hash)
            .expect("relayed item must be inflight for the confirmed secondary");
        assert!(
            entry.pending_peers.contains(&confirmed_peer),
            "the confirmed secondary must receive the mesh relay"
        );
        assert!(
            !entry.pending_peers.contains(&pending_peer),
            "FS-052 mesh-relay hole: an unconfirmed pending secondary must NOT receive the relayed clipboard item"
        );
    }

    /// Inflight merge fix (Fix B): a `ResyncPull` serve used to blindly
    /// `insert` into `inflight`, REPLACING any entry already tracking OTHER
    /// peers still awaiting an ack for the same hash (from a concurrent live
    /// `SendItem`/`forward_frames` fan-out) — silently dropping them from
    /// `pending_peers` so they'd never get a retransmit. The serve must
    /// instead merge: keep the pre-existing peer, add the puller.
    #[tokio::test]
    async fn resync_pull_serve_merges_inflight_pending_peers_instead_of_replacing() {
        use super::{dispatch_inbound_frame, Inflight, Outbox, PeerMeta, Reassembly};
        use crate::metrics::MetricsTracker;
        use crate::outbox::Entry as OutboxEntry;
        use crate::transport::Transport;
        use fluxsync_core::SeenSet;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use fluxsync_proto::{Frame, Kind, Msg, ResyncPull, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Instant;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);

        let self_id = Identity::generate();
        let puller_id = Identity::generate();
        let puller = puller_id.peer_id();
        let (sess_self_puller, _) = pair_for_test(&self_id, &puller_id).expect("pair puller");
        transport.install_session(puller, sess_self_puller).await;

        let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let mut pm = PeerMeta::new();
        pm.caps = vec!["resync-1".to_string()];
        peer_meta.lock().await.insert(puller, pm);

        let hash = super::clipboard_dedup_hash("resync-merge-item");
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        outbox.lock().await.insert(
            hash,
            OutboxEntry {
                payload: b"resync-merge-item".to_vec(),
                kind: Kind::Text,
                origin: [9u8; 32],
                seq: 1,
                created: Instant::now(),
            },
        );

        // A DIFFERENT peer is already awaiting an ack for this same hash —
        // as if from a concurrent live SendItem/forward_frames fan-out.
        let other_peer = [0x55u8; 32];
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        inflight.lock().await.insert(
            hash,
            Inflight {
                frames: vec![vec![1, 2, 3]],
                attempts: 2,
                last_sent: Instant::now()
                    .checked_sub(std::time::Duration::from_secs(5))
                    .unwrap(),
                first_sent: Instant::now()
                    .checked_sub(std::time::Duration::from_secs(5))
                    .unwrap(),
                pending_peers: std::iter::once(other_peer).collect(),
            },
        );

        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        // The hardened FS-052 gate drops ResyncPull from a peer that is not
        // in `trusted`; this test targets the inflight-merge behavior
        // downstream of it, so the puller must be trusted.
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(puller, crate::handshake::tofu_trusted_peer(puller));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::ResyncPull(ResyncPull { hashes: vec![hex::encode(hash)] }),
            },
            puller,
            &mesh_seen,
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &inflight,
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &peer_meta,
            None,
            &outbox,
            &pending_pulls,
            &outbox_stage,
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        let inf = inflight.lock().await;
        let entry = inf.get(&hash).expect("hash must still be tracked inflight");
        assert!(
            entry.pending_peers.contains(&other_peer),
            "FIX B: the pre-existing peer must survive the ResyncPull serve's \
             inflight update, not be clobbered by a blind insert"
        );
        assert!(
            entry.pending_peers.contains(&puller),
            "the new puller must be folded into pending_peers too"
        );
    }

    /// Resync serve firewall gate (Fix C): an item cached in the outbox
    /// before a policy tightened to Block afterward must not be re-served
    /// via `ResyncPull` — the live firewall must be re-checked at serve
    /// time, not just at admission time.
    #[tokio::test]
    async fn resync_pull_serve_skips_entries_blocked_by_live_firewall() {
        use super::{dispatch_inbound_frame, Outbox, PeerMeta, Reassembly};
        use crate::metrics::MetricsTracker;
        use crate::outbox::Entry as OutboxEntry;
        use crate::transport::Transport;
        use fluxsync_core::{Config, FirewallPolicy, Rule, SeenSet};
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use fluxsync_proto::{Frame, Kind, Msg, ResyncPull, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Instant;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);

        let self_id = Identity::generate();
        let puller_id = Identity::generate();
        let puller = puller_id.peer_id();
        let (sess_self_puller, _) = pair_for_test(&self_id, &puller_id).expect("pair puller");
        transport.install_session(puller, sess_self_puller).await;

        let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let mut pm = PeerMeta::new();
        pm.caps = vec!["resync-1".to_string()];
        peer_meta.lock().await.insert(puller, pm);

        let hash = super::clipboard_dedup_hash("now-blocked-item");
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        outbox.lock().await.insert(
            hash,
            OutboxEntry {
                payload: b"now-blocked-item".to_vec(),
                kind: Kind::Text,
                origin: [9u8; 32],
                seq: 1,
                created: Instant::now(),
            },
        );

        // The item was cached before the policy tightened; the LIVE
        // firewall now denies text outright.
        let firewall = FirewallPolicy { enabled: true, text: Rule::Deny, ..FirewallPolicy::default() };
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &Config { firewall, ..Config::default() },
        ));

        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        // The puller must be trusted so this ResyncPull passes the hardened
        // FS-052 gate — otherwise the serve would be skipped by the trust
        // check and the FIREWALL skip below would never be exercised.
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted
            .lock()
            .await
            .insert(puller, crate::handshake::tofu_trusted_peer(puller));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));

        dispatch_inbound_frame(
            Frame {
                version: PROTOCOL_VERSION,
                msg: Msg::ResyncPull(ResyncPull { hashes: vec![hex::encode(hash)] }),
            },
            puller,
            &mesh_seen,
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &inflight,
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &peer_meta,
            None,
            &outbox,
            &pending_pulls,
            &outbox_stage,
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        assert!(
            inflight.lock().await.get(&hash).is_none(),
            "FIX C: an outbox entry the LIVE firewall now blocks must not be \
             re-served via ResyncPull"
        );
        assert_eq!(
            metrics.lock().await.snapshot().items_resynced,
            0,
            "a firewall-blocked entry must not count as resynced"
        );
    }

    /// SE-14 defense in depth (Fix D): `dispatch_inbound_frame` must verify
    /// a `ClipboardItem`'s claimed hash against its payload before trusting
    /// it. Honest text and image pushes (real sender-side hashes) must still
    /// be accepted; a frame whose claimed hash does not match its payload
    /// must be dropped before it ever reaches the outbox.
    #[tokio::test]
    async fn se14_verify_content_hash_gates_clipboard_item_ingestion() {
        use super::{dispatch_inbound_frame, Outbox, Reassembly};
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_core::SeenSet;
        use fluxsync_proto::{ClipboardItem, Frame, Kind, Msg, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        async fn dispatch_one(
            transport: &Arc<Transport>,
            peer_id: [u8; 32],
            item: ClipboardItem,
        ) -> super::SharedOutbox {
            let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
            let (event_tx, _event_rx) = mpsc::channel(1024);
            let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> =
                Arc::new(Mutex::new(HashMap::new()));
            let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
            let inflight = Arc::new(Mutex::new(HashMap::new()));
            let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
            // The hardened FS-052 gate drops clipboard frames from a peer
            // that is not in `trusted`; this test targets the SE-14 hash
            // check downstream of it, so the sender must be trusted.
            let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
            trusted
                .lock()
                .await
                .insert(peer_id, crate::handshake::tofu_trusted_peer(peer_id));
            let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
            let outbox = Arc::new(Mutex::new(Outbox::new()));
            let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
            let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
            let (_state_tx, state_rx) = tokio::sync::watch::channel(
                fluxsync_core::State::initial(&fluxsync_core::Config::default()),
            );

            dispatch_inbound_frame(
                Frame { version: PROTOCOL_VERSION, msg: Msg::ClipboardItem(item) },
                peer_id,
                &mesh_seen,
                &event_tx,
                transport,
                &reassembly,
                &metrics,
                &inflight,
                &pending_pairs,
                &trusted,
                &Arc::new(Mutex::new(HashMap::new())),
                &Arc::new(Mutex::new(HashMap::new())),
                &peer_meta,
                None,
                &outbox,
                &pending_pulls,
                &outbox_stage,
                &state_rx,
                &Arc::new(Mutex::new(std::collections::HashSet::new())),
                &Arc::new(Mutex::new(std::collections::HashSet::new())),
                &Arc::new(Mutex::new(HashMap::new())),
            )
            .await;
            outbox
        }

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let peer_id = [0x21u8; 32];

        // Honest text: real sender-side hash, must be accepted.
        let honest_text_hash = super::clipboard_dedup_hash("legit text push");
        let outbox = dispatch_one(
            &transport,
            peer_id,
            ClipboardItem {
                lamport: 1,
                hash: honest_text_hash,
                kind: Kind::Text,
                payload: b"legit text push".to_vec(),
                sensitive: false,
                wall_time_ms: 0,
                origin: [1u8; 32],
                event_seq: 1,
            },
        )
        .await;
        assert!(
            outbox.lock().await.get(honest_text_hash).is_some(),
            "an honest text item (real hash) must be accepted"
        );

        // Honest image: real PNG + matching sender-side `image_rgba_hash`.
        let rgba = vec![1u8, 2, 3, 255];
        let png = super::encode_png(1, 1, rgba.clone()).expect("encode test png");
        let honest_image_hash = super::image_rgba_hash(1, 1, &rgba);
        let outbox = dispatch_one(
            &transport,
            peer_id,
            ClipboardItem {
                lamport: 1,
                hash: honest_image_hash,
                kind: Kind::Image,
                payload: png,
                sensitive: false,
                wall_time_ms: 0,
                origin: [1u8; 32],
                event_seq: 2,
            },
        )
        .await;
        assert!(
            outbox.lock().await.get(honest_image_hash).is_some(),
            "an honest image item (real hash) must be accepted"
        );

        // Forged: claimed hash does not match the payload — must be dropped
        // before ever touching the outbox.
        let forged_hash = [0xEEu8; 32];
        let outbox = dispatch_one(
            &transport,
            peer_id,
            ClipboardItem {
                lamport: 1,
                hash: forged_hash,
                kind: Kind::Text,
                payload: b"attacker-controlled bytes".to_vec(),
                sensitive: false,
                wall_time_ms: 0,
                origin: [1u8; 32],
                event_seq: 3,
            },
        )
        .await;
        assert!(
            outbox.lock().await.get(forged_hash).is_none(),
            "SE-14: a forged hash/payload pair must be dropped, never cached"
        );
    }

    /// `read_line_capped`'s bound is on the total line length AS READ FROM
    /// THE WIRE, delimiter included (`bytes.len() + take > max` — the check
    /// counts the newline). So a line whose content+`\n` together total
    /// exactly `MAX_IPC_LINE` bytes is the largest accepted line, and one
    /// byte more (content of `MAX_IPC_LINE` bytes, i.e. one longer, plus the
    /// same trailing `\n`) is the smallest rejected one.
    #[tokio::test]
    async fn read_line_capped_accepts_exactly_the_cap() {
        use super::{read_line_capped, MAX_IPC_LINE};

        // Content is MAX_IPC_LINE - 1 bytes so content + '\n' == MAX_IPC_LINE.
        let mut data = vec![b'a'; MAX_IPC_LINE - 1];
        data.push(b'\n');
        let mut reader = tokio::io::BufReader::new(data.as_slice());
        let mut out = String::new();

        let n = read_line_capped(&mut reader, &mut out, MAX_IPC_LINE)
            .await
            .expect("a line totalling exactly MAX_IPC_LINE bytes must be accepted");

        assert_eq!(n, MAX_IPC_LINE, "accepted line must report its full byte count");
        assert_eq!(out.len(), MAX_IPC_LINE);
    }

    /// One byte over the cap must be rejected with `InvalidData`, and the
    /// caller's connection-teardown contract holds: `read_line_capped` never
    /// returns a truncated `Ok` for an over-cap line. `handle_ipc_client`
    /// propagates the `Err` via `?` and drops the connection on it, so a
    /// caller must never be able to mistake a partial write into `out` for a
    /// valid (if truncated) line — this asserts `out` is left untouched.
    #[tokio::test]
    async fn read_line_capped_rejects_one_byte_over_the_cap() {
        use super::{read_line_capped, MAX_IPC_LINE};

        // Content is MAX_IPC_LINE bytes so content + '\n' == MAX_IPC_LINE + 1.
        let mut data = vec![b'a'; MAX_IPC_LINE];
        data.push(b'\n');
        let mut reader = tokio::io::BufReader::new(data.as_slice());
        let mut out = String::new();

        let err = read_line_capped(&mut reader, &mut out, MAX_IPC_LINE)
            .await
            .expect_err("a line totalling MAX_IPC_LINE + 1 bytes must be rejected");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            out.is_empty(),
            "on error, read_line_capped must never have written a truncated line into `out`"
        );
    }

    /// Bug #2 (NAK is born dead): the selective-NAK tick used to build
    /// `Nak.item_id` from `reassembly`'s HashMap key — `reassembly_key
    /// (source, item_hash)`, a composite BLAKE3 digest — which the sender's
    /// `inflight` (keyed by the REAL content hash) can never match, and sent
    /// it over the primary link instead of to the transfer's actual sender.
    /// `build_pending_naks` must use `Reassembly::item_hash` /
    /// `Reassembly::source` instead of the map key.
    #[test]
    fn build_pending_naks_uses_real_hash_and_true_sender_not_composite_key() {
        use super::{build_pending_naks, reassembly_key, Reassembly};
        use fluxsync_proto::Kind;
        use std::collections::HashMap;
        use std::time::Instant;

        let source = [7u8; 32];
        let item_hash = [9u8; 32];
        let key = reassembly_key(source, item_hash);
        let mut map: HashMap<[u8; 32], Reassembly> = HashMap::new();
        map.insert(
            key,
            Reassembly {
                metadata: Some((1, Kind::Text, false)),
                origin: [1u8; 32],
                event_seq: 1,
                chunks: vec![Some(vec![1]), None],
                last_update: Instant::now(),
                first_seen: Instant::now(),
                source,
                item_hash,
            },
        );

        let naks = build_pending_naks(&map);
        assert_eq!(naks.len(), 1, "one incomplete chunked transfer must produce one NAK");
        let (dest, nak) = &naks[0];
        assert_eq!(
            *dest, source,
            "the NAK must be routed to the transfer's actual sender, not the primary link"
        );
        assert_eq!(
            nak.item_id, item_hash,
            "the NAK must carry the real content hash, not the composite reassembly-map key"
        );
        assert_eq!(nak.missing, vec![1], "the NAK must list the still-missing chunk index");
    }

    /// Bug #3 (inflight blind-insert clobber): `forward_frames` used to
    /// blindly `insert` into `inflight`, REPLACING any entry a concurrent
    /// relay or local `Action::SendItem` already created for the same hash —
    /// silently dropping whichever peers that earlier entry was still
    /// awaiting an ack from. Sibling of the already-fixed ResyncPull-serve
    /// merge (`resync_pull_serve_merges_inflight_pending_peers_instead_of_replacing`).
    #[tokio::test]
    async fn forward_frames_merges_inflight_pending_peers_instead_of_replacing() {
        use super::{forward_frames, Inflight};
        use crate::transport::Transport;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Instant;
        use tokio::sync::Mutex;

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);

        let self_id = Identity::generate();
        let source_id = Identity::generate();
        let origin_id = Identity::generate();
        let new_id = Identity::generate();
        let source = source_id.peer_id();
        let origin = origin_id.peer_id();
        let new_peer = new_id.peer_id();
        let (sess_new, _) = pair_for_test(&self_id, &new_id).expect("pair new");
        transport.install_session(new_peer, sess_new).await;

        let hash = [0x33u8; 32];
        let existing_peer = [0x44u8; 32];
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        inflight.lock().await.insert(
            hash,
            Inflight {
                frames: vec![vec![0u8; 1]],
                attempts: 0,
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                pending_peers: std::iter::once(existing_peer).collect(),
            },
        );

        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

        forward_frames(&transport, &inflight, &pending_pairs, source, origin, hash, vec![vec![9u8; 1]])
            .await;

        let map = inflight.lock().await;
        let entry = map.get(&hash).expect("inflight entry must survive the relay");
        assert!(
            entry.pending_peers.contains(&existing_peer),
            "FIXED: a concurrent relay must not drop a peer an earlier Inflight entry \
             was still awaiting an ack from"
        );
        assert!(
            entry.pending_peers.contains(&new_peer),
            "the newly relayed-to peer must also be tracked"
        );
    }

    /// Bug #3, second call site: `Action::SendItem`'s own inflight insert had
    /// the identical blind-`insert` defect as `forward_frames` — a locally
    /// copied item hashing to the same value as one already tracked inflight
    /// (e.g. a concurrent mesh relay of that exact hash) would clobber the
    /// existing entry's `pending_peers` instead of merging into it.
    #[tokio::test]
    async fn send_item_merges_inflight_pending_peers_instead_of_replacing() {
        use super::{dispatch, Inflight, Outbox};
        use crate::transport::Transport;
        use fluxsync_core::{Action, App, Config};
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use fluxsync_proto::Kind;
        use std::collections::{BTreeMap, HashMap, VecDeque};
        use std::sync::Arc;
        use std::time::Instant;
        use tokio::sync::{broadcast, watch, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);

        let self_id = Identity::generate();
        let confirmed_id = Identity::generate();
        let confirmed_peer = confirmed_id.peer_id();
        let (sess_confirmed, _) = pair_for_test(&self_id, &confirmed_id).expect("pair confirmed");
        transport.install_session(confirmed_peer, sess_confirmed).await;

        let hash = super::clipboard_dedup_hash("send-item-merge secret");
        let existing_peer = [0x66u8; 32];
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        inflight.lock().await.insert(
            hash,
            Inflight {
                frames: vec![vec![0u8; 1]],
                attempts: 0,
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                pending_peers: std::iter::once(existing_peer).collect(),
            },
        );

        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let mut app = App::new(Config::default());
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        let (state_watch_tx, _state_watch_rx) =
            watch::channel(fluxsync_core::State::initial(&Config::default()));
        let (logs_bcast_tx, _logs_rx) = broadcast::channel(16);
        let log_tail = Arc::new(super::LogTail::new());
        let last_written_hashes = Arc::new(Mutex::new(VecDeque::new()));
        let metrics = Arc::new(Mutex::new(crate::metrics::MetricsTracker::new()));
        let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(BTreeMap::new()));
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let mut seq_store: Option<crate::seq_store::SeqStore> = None;

        let actions = vec![Action::SendItem {
            hash,
            kind: Kind::Text,
            payload: b"send-item-merge secret".to_vec(),
            sensitive: false,
        }];

        dispatch(
            actions,
            &mut app,
            &transport,
            &trusted,
            None,
            &state_watch_tx,
            &logs_bcast_tx,
            &log_tail,
            &last_written_hashes,
            &metrics,
            &inflight,
            &peer_meta,
            &outbox,
            &pending_pairs,
            &mut seq_store,
        )
        .await;

        let inf = inflight.lock().await;
        let entry = inf.get(&hash).expect("inflight entry must survive SendItem");
        assert!(
            entry.pending_peers.contains(&existing_peer),
            "FIXED: Action::SendItem must not drop a peer an earlier Inflight entry \
             was still awaiting an ack from"
        );
        assert!(
            entry.pending_peers.contains(&confirmed_peer),
            "the freshly targeted peer must also be tracked"
        );
    }

    /// Bug #7: a hash we already have an outstanding `ResyncPull` in flight
    /// for (to ANY peer) must not be re-requested, even though it's neither
    /// held nor cleared.
    #[test]
    fn missing_resync_hashes_excludes_hash_with_in_flight_pull() {
        use super::missing_resync_hashes;
        let already_pending = "aa".repeat(32);
        let genuinely_missing = "bb".repeat(32);
        let offered = vec![already_pending.clone(), genuinely_missing.clone()];
        let missing = missing_resync_hashes(
            &offered,
            &[],
            &[],
            &[],
            std::slice::from_ref(&already_pending),
        );
        assert_eq!(
            missing,
            vec![genuinely_missing],
            "a hash already pending from another peer must not trigger a second ResyncPull"
        );
    }

    /// Bug #7 (pending_pulls stale suppression), end to end: two peers both
    /// offering the same hash via `Msg::ResyncOffer` used to BOTH get a
    /// `ResyncPull` — `missing_resync_hashes` checked only history/outbox/
    /// cleared, not hashes already being chased. Only one response can ever
    /// be first-sight (`mesh_seen` drops the other, identical-`EventId`
    /// arrival before it reaches `take_pending_pull`), so the loser's
    /// `pending_pulls` entry was left stale for up to `RESYNC_PULL_TIMEOUT` —
    /// long enough to misclassify that peer's next genuinely fresh copy of
    /// the same content as resync catch-up and silently drop it. Fixed by
    /// deduping offers against in-flight pulls before ever asking twice.
    #[tokio::test]
    async fn resync_offer_from_second_peer_does_not_duplicate_an_in_flight_pull() {
        use super::{dispatch_inbound_frame, Outbox, PeerMeta, Reassembly};
        use crate::metrics::MetricsTracker;
        use crate::transport::Transport;
        use fluxsync_core::SeenSet;
        use fluxsync_crypto::{test_util::pair_for_test, Identity};
        use fluxsync_proto::{Frame, Msg, ResyncOffer, PROTOCOL_VERSION};
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);

        let self_id = Identity::generate();
        let peer_a_id = Identity::generate();
        let peer_b_id = Identity::generate();
        let peer_a = peer_a_id.peer_id();
        let peer_b = peer_b_id.peer_id();
        let (sess_a, _) = pair_for_test(&self_id, &peer_a_id).expect("pair a");
        let (sess_b, _) = pair_for_test(&self_id, &peer_b_id).expect("pair b");
        transport.install_session(peer_a, sess_a).await;
        transport.install_session(peer_b, sess_b).await;

        let peer_meta: super::PeerMetaMap = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        for peer in [peer_a, peer_b] {
            let mut pm = PeerMeta::new();
            pm.caps = vec!["resync-1".to_string()];
            peer_meta.lock().await.insert(peer, pm);
        }

        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        for peer in [peer_a, peer_b] {
            trusted.lock().await.insert(peer, crate::handshake::tofu_trusted_peer(peer));
        }

        let hash = super::clipboard_dedup_hash("both-peers-offer-this");
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let reassembly: Arc<Mutex<HashMap<[u8; 32], Reassembly>>> = Arc::new(Mutex::new(HashMap::new()));
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let metrics = Arc::new(Mutex::new(MetricsTracker::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        let offer = ResyncOffer { hashes: vec![hex::encode(hash)] };

        dispatch_inbound_frame(
            Frame { version: PROTOCOL_VERSION, msg: Msg::ResyncOffer(offer.clone()) },
            peer_a,
            &mesh_seen,
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &Arc::new(Mutex::new(HashMap::new())),
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &peer_meta,
            None,
            &outbox,
            &pending_pulls,
            &outbox_stage,
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        assert!(
            pending_pulls.lock().await.get(&peer_a).is_some_and(|m| m.contains_key(&hash)),
            "precondition: peer A's offer must start a ResyncPull"
        );

        dispatch_inbound_frame(
            Frame { version: PROTOCOL_VERSION, msg: Msg::ResyncOffer(offer) },
            peer_b,
            &mesh_seen,
            &event_tx,
            &transport,
            &reassembly,
            &metrics,
            &Arc::new(Mutex::new(HashMap::new())),
            &pending_pairs,
            &trusted,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(Mutex::new(HashMap::new())),
            &peer_meta,
            None,
            &outbox,
            &pending_pulls,
            &outbox_stage,
            &state_rx,
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(std::collections::HashSet::new())),
            &Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        assert!(
            !pending_pulls.lock().await.contains_key(&peer_b),
            "FIXED: a hash already pending from another peer must not trigger a second ResyncPull"
        );
    }

    /// Bug #8 (outbox_stage collision): two DIFFERENT peers independently
    /// staging the IDENTICAL content hash (e.g. both relay/copy the same
    /// text) used to let the second arrival silently overwrite the first's
    /// `outbox_stage` entry via a blind `insert` — while `pending_payloads`
    /// (`fluxsync_core::App::park_pending`) is always first-wins by hash.
    /// The two stores could then credit DIFFERENT peers for the same
    /// staged item, so revoking the peer `pending_payloads` credits purges
    /// `outbox_stage`'s entry (`purge_dropped_pending_from_outbox_stage`)
    /// based on the wrong assumption that it's the same peer's data.
    /// `outbox_stage` must be first-wins too, exactly like `park_pending`.
    #[tokio::test]
    async fn outbox_stage_first_wins_matches_pending_payloads_on_same_hash_collision() {
        use super::{complete_reassembled_item, Outbox};
        use crate::transport::Transport;
        use fluxsync_core::{App, Config, Event, FirewallPolicy, Rule, SeenSet, StubWallClock};
        use fluxsync_proto::Kind;
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::{mpsc, Mutex};

        const PEER_A: [u8; 32] = [0xAAu8; 32];
        const PEER_B: [u8; 32] = [0xBBu8; 32];
        let hash = super::clipboard_dedup_hash("collision-secret");
        let payload = b"collision-secret".to_vec();

        let (transport, _port) = Transport::bind("127.0.0.1", 0)
            .await
            .expect("bind loopback transport");
        let transport = Arc::new(transport);
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        let mesh_seen = Arc::new(Mutex::new(SeenSet::default()));
        let (event_tx, _event_rx) = mpsc::channel(1024);
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let outbox_stage = Arc::new(Mutex::new(HashMap::new()));
        let pending_pairs: crate::handshake::PendingSet = Arc::new(Mutex::new(HashMap::new()));

        let firewall = FirewallPolicy { enabled: true, text: Rule::Ask, ..FirewallPolicy::default() };
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &Config { firewall: firewall.clone(), ..Config::default() },
        ));

        // A arrives first: stages the item under its own origin/seq.
        complete_reassembled_item(
            &transport, &inflight, &mesh_seen, &event_tx, PEER_A, PEER_A, 1, hash, Kind::Text,
            false, 0, payload.clone(), &outbox, &outbox_stage, &pending_pulls, &state_rx,
            &pending_pairs,
        )
        .await;
        // B independently relays/copies the IDENTICAL content: same wire
        // hash, different peer/origin.
        complete_reassembled_item(
            &transport, &inflight, &mesh_seen, &event_tx, PEER_B, PEER_B, 1, hash, Kind::Text,
            false, 0, payload.clone(), &outbox, &outbox_stage, &pending_pulls, &state_rx,
            &pending_pairs,
        )
        .await;

        // Real core-side park: mirrors what the main loop's `app.handle`
        // does with each `Event::FrameReceivedClipboard`. `park_pending`
        // (and, for this identical-payload case, the dedup ring too) is
        // first-wins: A is the one credited in `state.pending`/
        // `pending_payloads`.
        let mut app = App::new(Config { firewall, ..Config::default() });
        let wall = StubWallClock::new("12:00", 1_000);
        app.handle(
            Event::FrameReceivedClipboard {
                peer_id: PEER_A,
                hash,
                kind: Kind::Text,
                payload: payload.clone(),
                preview: "collision-secret".into(),
                sensitive: false,
                lamport: 1,
                resync: false,
            },
            &wall,
        );
        app.handle(
            Event::FrameReceivedClipboard {
                peer_id: PEER_B,
                hash,
                kind: Kind::Text,
                payload,
                preview: "collision-secret".into(),
                sensitive: false,
                lamport: 1,
                resync: false,
            },
            &wall,
        );
        assert_eq!(app.snapshot().pending.len(), 1, "precondition: only ONE parked row for this hash");
        assert_eq!(
            app.snapshot().pending[0].peer_id,
            Some(hex::encode(PEER_A)),
            "precondition: pending_payloads credits the FIRST peer (A)"
        );

        // FIXED: outbox_stage must agree with pending_payloads about who
        // owns this hash — the first peer, A — not silently adopt B's
        // later arrival.
        let staged = outbox_stage.lock().await;
        let entry = staged.get(&hash).expect("hash must still be staged");
        assert_eq!(
            entry.origin, PEER_A,
            "outbox_stage must keep the FIRST peer's entry (matching pending_payloads), \
             not the second peer's overwrite"
        );
    }

    /// Bug #9 (inflight survives revoke): revoking a peer must drop it from
    /// every `Inflight.pending_peers` — otherwise the retransmit timer keeps
    /// firing at a permanently-revoked peer, and a peer that later
    /// re-TOFU-joins under the same id within `INFLIGHT_MAX_AGE` could
    /// receive a stale retransmit into its new, unconfirmed session (a
    /// second FS-052 bypass). An entry whose `pending_peers` becomes empty
    /// must be dropped outright, not left orphaned.
    #[tokio::test]
    async fn purge_peer_from_inflight_drops_revoked_peer_and_empties_entries() {
        use super::{purge_peer_from_inflight, Inflight};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Instant;
        use tokio::sync::Mutex;

        let revoked = [0xAAu8; 32];
        let other = [0xBBu8; 32];
        let solo_hash = [1u8; 32];
        let shared_hash = [2u8; 32];

        let inflight = Arc::new(Mutex::new(HashMap::new()));
        inflight.lock().await.insert(
            solo_hash,
            Inflight {
                frames: vec![vec![1]],
                attempts: 0,
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                pending_peers: std::iter::once(revoked).collect(),
            },
        );
        inflight.lock().await.insert(
            shared_hash,
            Inflight {
                frames: vec![vec![2]],
                attempts: 0,
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                pending_peers: [revoked, other].into_iter().collect(),
            },
        );

        purge_peer_from_inflight(revoked, &inflight).await;

        let map = inflight.lock().await;
        assert!(
            map.get(&solo_hash).is_none(),
            "FIXED: an entry left with no pending peers after the revoke must be dropped entirely"
        );
        let shared = map.get(&shared_hash).expect("the other peer's item must survive");
        assert!(
            !shared.pending_peers.contains(&revoked),
            "the revoked peer must no longer be awaited"
        );
        assert!(
            shared.pending_peers.contains(&other),
            "an unrelated peer still awaiting this item must be untouched"
        );
    }

    /// FluxMesh bug fix (Bug #10a): `rekey_watchdog` used to read only the
    /// PRIMARY's clock (`cached_peer_id`/`session_established_at`/
    /// `session_bytes`) and only ever call `run_rekey_initiator` for that one
    /// peer, so a SECONDARY session — however long-lived — never rotated,
    /// violating the 24h/1GiB rekey policy for every mesh peer but the
    /// primary. Drives the REAL `rekey_watchdog` (not a mock) against a
    /// transport with a primary (A) and a secondary (B). Identities are
    /// arranged so this daemon is NOT the deterministic initiator for A (it
    /// must be correctly skipped — no responder is even bound for it) but IS
    /// the initiator for B: the secondary must still receive a genuine rekey
    /// handshake and end up with a bumped `session_generation`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rekey_watchdog_rekeys_a_secondary_session() {
        use super::{rekey_watchdog, BackoffMap};
        use crate::handshake::{peer_id_for, TrustedPeer, TrustedSet};
        use crate::transport::{Transport, TYPE_HANDSHAKE_INIT};
        use fluxsync_core::Event;
        use fluxsync_crypto::{test_util::pair_for_test, Identity, Responder};
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::net::UdpSocket;
        use tokio::sync::{mpsc, Mutex};
        use tokio_util::sync::CancellationToken;

        // Arrange identities so THIS daemon is not the initiator for A (the
        // primary) but IS the initiator for B (the secondary) — isolates the
        // test to the secondary path while also proving the primary is
        // correctly left alone.
        let (self_identity, peer_a_identity, peer_b_identity) = loop {
            let s = Identity::generate();
            let a = Identity::generate();
            let b = Identity::generate();
            if s.peer_id() > a.peer_id() && s.peer_id() < b.peer_id() {
                break (s, a, b);
            }
        };
        let peer_id_a = peer_id_for(&peer_a_identity.public_key());
        let peer_id_b = peer_id_for(&peer_b_identity.public_key());

        let (transport, _port) = Transport::bind("127.0.0.1", 0).await.expect("bind transport");
        let transport = Arc::new(transport);

        // Seed both sessions — A first (becomes primary), B second (routes
        // to `extra`, FluxMesh 2C-b) — with throwaway key material; only the
        // bookkeeping (established_at/generation) matters here, since the
        // rekey itself is a fresh, real Noise exchange against the genuine
        // identities registered in `trusted` below.
        let (sess_a, _) = pair_for_test(&self_identity, &Identity::generate()).unwrap();
        let (sess_b, _) = pair_for_test(&self_identity, &Identity::generate()).unwrap();
        transport.install_session(peer_id_a, sess_a).await;
        transport.install_session(peer_id_b, sess_b).await;
        assert_eq!(transport.cached_peer_id().await, Some(peer_id_a));

        let bare_a = UdpSocket::bind("127.0.0.1:0").await.expect("bind bare peer A socket");
        let bare_b = UdpSocket::bind("127.0.0.1:0").await.expect("bind bare peer B socket");
        transport.set_peer_addr_for(peer_id_a, bare_a.local_addr().unwrap()).await;
        transport.set_peer_addr_for(peer_id_b, bare_b.local_addr().unwrap()).await;

        let trusted: TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        trusted.lock().await.insert(
            peer_id_a,
            TrustedPeer { static_pub: peer_a_identity.public_key(), name: "peer-a".into() },
        );
        trusted.lock().await.insert(
            peer_id_b,
            TrustedPeer { static_pub: peer_b_identity.public_key(), name: "peer-b".into() },
        );

        let generation_a_before = transport.session_generation_for(peer_id_a).await.unwrap();
        let generation_b_before = transport.session_generation_for(peer_id_b).await.unwrap();

        let pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>> =
            Arc::new(Mutex::new(None));
        let (event_tx, mut event_rx) = mpsc::channel::<Event>(16);
        let backoff: BackoffMap = Arc::new(Mutex::new(HashMap::new()));
        let shutdown = CancellationToken::new();

        let watchdog = tokio::spawn(rekey_watchdog(
            self_identity.clone(),
            transport.clone(),
            trusted.clone(),
            pending_initiator_tx.clone(),
            event_tx.clone(),
            backoff.clone(),
            50,       // max_age_ms: force both sessions "due" almost immediately
            u64::MAX, // max_bytes: never trip the byte trigger
            None,
            shutdown.clone(),
        ));

        // Only B's bare socket should ever receive a HandshakeInit — A is
        // not this daemon's deterministic responsibility to initiate.
        let mut buf = [0u8; 2048];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(2), bare_b.recv_from(&mut buf))
            .await
            .expect("watchdog must send a rekey HandshakeInit to the secondary within 2s")
            .expect("recv msg1");
        assert_eq!(buf[0], TYPE_HANDSHAKE_INIT);
        let (_peer_session, msg2, _remote_static) =
            Responder::step(&peer_b_identity, &buf[1..n]).expect("responder step");

        // Deliver msg2 the way the real driver's `RecvFrame::HandshakeResp`
        // dispatch would — via the shared single-flight sender — without
        // needing a full receive-loop task for this test.
        let tx = pending_initiator_tx
            .lock()
            .await
            .clone()
            .expect("watchdog must have registered the single-flight sender for B's rekey");
        tx.send(msg2).expect("deliver msg2 to the rekey initiator");

        let mut rekeyed = false;
        for _ in 0..100 {
            if transport.session_generation_for(peer_id_b).await.unwrap_or(generation_b_before)
                > generation_b_before
            {
                rekeyed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(rekeyed, "secondary session must be rekeyed within ~2s");

        assert_eq!(
            transport.session_generation_for(peer_id_a).await,
            Some(generation_a_before),
            "the primary — not due (this daemon isn't its deterministic initiator) — must be untouched"
        );

        // A HandshakeOk fired for the completed secondary rekey.
        let mut saw_handshake_ok = false;
        while let Ok(ev) = event_rx.try_recv() {
            if matches!(ev, Event::HandshakeOk) {
                saw_handshake_ok = true;
            }
        }
        assert!(saw_handshake_ok, "a completed secondary rekey must fire HandshakeOk");

        // Prove the primary path was truly untouched, not just "generation
        // didn't change by luck": A's bare socket must never receive anything.
        let none_for_a =
            tokio::time::timeout(Duration::from_millis(200), bare_a.recv_from(&mut buf)).await;
        assert!(
            none_for_a.is_err(),
            "the primary must never receive a HandshakeInit from this daemon"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), watchdog).await;
    }
}
