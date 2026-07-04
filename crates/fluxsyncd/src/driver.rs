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
    dedup::DedupRing, kind_of, Action, App, Config as CoreConfig, DeviceId, Event, EventId,
    HistoryItem, LogEntry, LogLevel, PeerInfo, SeenSet, State, WallClock,
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
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};
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
    if let Some(dir) = keystore_dir.as_ref() {
        let loaded = load_trusted_peers(dir);
        let count = loaded.len();
        {
            let mut g = trusted.lock().await;
            for (peer_id, peer, last_addr) in loaded {
                g.insert(peer_id, peer);
                if let Some(addr) = last_addr {
                    last_known_addrs.push((peer_id, addr));
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
        transport.set_peer_info(peer_id, addr).await;
    }

    // Inform App about trusted peers for UI hints.
    {
        let g = trusted.lock().await;
        if let Some(peer) = g.values().next() {
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
        let state_rx_for_recv = state_watch_tx.subscribe();
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
                state_rx_for_recv,
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
        tasks.spawn(async move {
            handshake::run_pending_reaper(pending, trusted_r, transport_r, kd, s).await;
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
        tasks.spawn(async move {
            if let Err(e) = heartbeat_loop(
                transport,
                event_tx,
                shutdown,
                metrics,
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
        tasks.spawn(async move {
            discovery_dispatcher(
                disc_rx, identity, trusted, transport, pending, event_tx, disc_cache, backoff,
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
                let actions = app.handle(event.clone(), &*wall_clock);
                if !actions.is_empty() {
                    tracing::debug!(?event, ?actions, phase=?app.snapshot().phase, "FSM transition");
                }
                dispatch(actions, &mut app, &transport, &trusted, keystore_dir.as_ref(), &state_watch_tx, &logs_bcast_tx, &log_tail, &last_written_hashes, &metrics, &inflight, &peer_meta, &outbox, &mut seq_store).await;
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
                        dispatch(actions, &mut app, &transport, &trusted, keystore_dir.as_ref(), &state_watch_tx, &logs_bcast_tx, &log_tail, &last_written_hashes, &metrics, &inflight, &peer_meta, &outbox, &mut seq_store).await;
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
                            &mut seq_store,
                        ).await;
                    }
                }
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
                        tracing::info!(
                            peers = targets.len(),
                            frames = frames.len(),
                            "SendItem: fanning item out to linked peers"
                        );
                        // DIR-P1-09: counts logical items handed to the
                        // transport, not wire frames — a chunked image is
                        // still one `items_sent`.
                        metrics.lock().await.on_item_sent();
                        let multi = frames.len() > 1;
                        for peer in &targets {
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
                        // UDP gives no delivery guarantee.
                        inflight.lock().await.insert(
                            hash,
                            Inflight {
                                frames,
                                attempts: 0,
                                last_sent: Instant::now(),
                                first_sent: Instant::now(),
                                pending_peers: targets.into_iter().collect(),
                            },
                        );
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
            Action::WriteClipboard { kind, payload } => {
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
                        if let Some((w, h, rgba)) = decode_png_to_rgba(&payload) {
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
    seq_store: &mut Option<SeqStore>,
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
            transport.drop_session().await;
            let _ = event_tx.try_send(Event::PeerLost);
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
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::ResolvePending { hash, allow } => {
            tracing::info!(%hash, allow, "IPC: resolve-pending");
            let actions = app.handle(Event::ResolvePending { hash, allow }, &**wall);
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
                seq_store,
            )
            .await;
            CmdResponse::ok(req_id, None)
        }
        CmdOp::DebugCapture {} => CmdResponse::ok(req_id, None),
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
            transport.drop_session_for(arr).await;
            if peer_meta.lock().await.remove(&arr).is_some() {
                let _ = event_tx.try_send(Event::MeshPeersChanged);
            }
            // If the revoked peer was the primary, rebind State: fail over to a
            // live secondary if one exists, else walk Linked → Discovering
            // (CloseSession touches only the session, not the trust store).
            let active = app.snapshot().peer_id;
            if active == arr && !try_primary_failover(transport, event_tx, peer_meta).await {
                let actions = app.handle(Event::PeerLost, &**wall);
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
                    seq_store,
                )
                .await;
            }
            CmdResponse::ok(req_id, None)
        }
        CmdOp::SetLaunchAtLogin { value: _ } => {
            // [TODO] Persistence of this preference in config/peers.json
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
            if !accept {
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
            // An explicit QR scan is user intent to (re)verify, so it ALWAYS
            // engages the SAS gate — even for an already-trusted peer (see the
            // initiator `Some(pending_pairs)` below). This is what surfaces the
            // 6 SAS words on the scanning side: without it, re-scanning a known
            // peer ran as a silent reconnect and the initiator never created a
            // pending entry, so its verify screen showed nothing. Silent
            // discovery reconnects still pass `None` (no re-verify) elsewhere.
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
                    // Always Some on an explicit scan → the SAS gate engages and
                    // the initiator's verify screen gets its 6 words.
                    Some(pending_pairs.clone()),
                    backoff.clone(),
                    trusted.clone(),
                    keystore_dir.cloned(),
                )
                .await;
            }
            CmdResponse::ok(req_id, None)
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
            CmdResponse::ok(req_id, None)
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
    state_rx: watch::Receiver<State>,
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
                // reassembly, tell the sender exactly which chunk indices
                // (and the header) are still missing so it resends only
                // those — whole-item retransmit can't converge under
                // steady UDP loss.
                let mut naks: Vec<Vec<u8>> = Vec::new();
                {
                    let map = reassembly.lock().await;
                    for (item_id, r) in map.iter() {
                        if r.chunks.is_empty() {
                            // Only a header (or nothing) seen so far —
                            // total unknown, nothing concrete to ask for.
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
                        let nak = fluxsync_proto::Nak {
                            item_id: *item_id,
                            want_header,
                            missing,
                        };
                        let frame = Frame {
                            version: PROTOCOL_VERSION,
                            msg: Msg::Nak(nak),
                        };
                        if let Ok(bytes) = fluxsync_proto::encode(&frame) {
                            naks.push(bytes);
                        }
                    }
                }
                for bytes in &naks {
                    let _ = transport.send_encrypted(bytes).await;
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
                            Ok(f) => dispatch_inbound_frame(f, peer_id, &mesh_seen, &event_tx, &transport, &reassembly, &metrics, &inflight, &pending_pairs, &trusted, &disc_cache, &backoff, &peer_meta, keystore_dir.as_ref(), &outbox, &pending_pulls, &state_rx).await,
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
    // The disk clear is async relative to the in-memory wipe; a crash in
    // that sub-second window can leave history.enc on disk until the next
    // boot rehydrates+re-wipes it (residual, low-severity: the secret is
    // the user's own, on the user's own device).
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
/// content hash. The daemon never puts binary in the state JSON; on
/// Android the client pulls an inbound image's PNG bytes on demand via the
/// `fetch_item` IPC op, which reads this map. Bounded to the last few
/// images so a 16 MiB cap can't grow memory without limit. Desktop never
/// reads it (it writes images straight to the OS clipboard).
type ImageCache = std::sync::Mutex<VecDeque<(String, Vec<u8>)>>;
static IMAGE_CACHE: std::sync::OnceLock<ImageCache> = std::sync::OnceLock::new();

/// Max image payloads retained in [`IMAGE_CACHE`]. 4 × 16 MiB worst case.
const IMAGE_CACHE_CAP: usize = 4;

fn image_cache() -> &'static ImageCache {
    IMAGE_CACHE.get_or_init(|| std::sync::Mutex::new(VecDeque::with_capacity(IMAGE_CACHE_CAP)))
}

/// Store an inbound image's PNG bytes under its hex hash. No-op if the
/// hash is already cached. Android-only — desktop writes images straight
/// to the OS clipboard and never needs the cache.
#[cfg(target_os = "android")]
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

async fn heartbeat_loop(
    transport: Arc<Transport>,
    event_tx: mpsc::Sender<Event>,
    shutdown: CancellationToken,
    metrics: Arc<Mutex<MetricsTracker>>,
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
                            transport.set_last_rx(now);
                            // FluxMesh robustness slice 2: rebind to a live
                            // secondary if one exists; only fall to Discovering
                            // when the whole mesh is gone.
                            if !try_primary_failover(&transport, &event_tx, &peer_meta).await {
                                let _ = event_tx.try_send(Event::PeerLost);
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
                            transport.drop_session_for(peer_id).await;
                            secondary_missed.remove(&peer_id);
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
/// checks whether the primary session has crossed `max_age_ms` or
/// `max_bytes` (see [`crate::transport::rekey_due`]) and, if so, whether
/// this daemon is the deterministic rekey initiator for that peer
/// ([`crate::transport::is_rekey_initiator`] — exactly one side of a pair
/// ever is). The other side does nothing: it just accepts the fresh
/// handshake the same way it already accepts any reconnect, via
/// `handshake::run_responder`'s generation-gated install.
///
/// Reuses the same `pending_initiator_tx` single-flight slot as ordinary
/// reconnects so a rekey attempt can never race a concurrent
/// discovery-triggered handshake for the same peer. A rekey-triggered
/// re-handshake is intentional, not a failure: on success it feeds
/// `PeerBackoff::on_handshake_ok` exactly like any other completed
/// handshake; on failure it deliberately does **not** call
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
                if !transport.has_session().await {
                    continue;
                }
                let Some(peer_id) = transport.cached_peer_id().await else { continue };

                let age_ms = now_ms().saturating_sub(transport.session_established_at());
                let bytes = transport.session_bytes();
                if !rekey_due(age_ms, bytes, max_age_ms, max_bytes) {
                    continue;
                }
                if !is_rekey_initiator(identity.peer_id(), peer_id) {
                    // The peer is the deterministic initiator for this pair;
                    // we just wait to accept its handshake.
                    continue;
                }

                // Single-flight: never overlap with an organic reconnect or
                // an earlier rekey attempt still finishing.
                let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                {
                    let mut g = pending_initiator_tx.lock().await;
                    if g.is_some() {
                        continue;
                    }
                    *g = Some(tx);
                }

                let Some(peer_addr) = transport.current_peer_addr().await else {
                    *pending_initiator_tx.lock().await = None;
                    continue;
                };
                let static_pub = trusted.lock().await.get(&peer_id).map(|p| p.static_pub);
                let Some(static_pub) = static_pub else {
                    *pending_initiator_tx.lock().await = None;
                    continue;
                };
                let expected_generation = transport.primary_session_generation();

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
                                .on_handshake_ok();
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
            }
        }
    }
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
pub(crate) async fn persist_last_addr(
    keystore_dir: Option<&Path>,
    transport: &Transport,
    trusted: &TrustedSet,
    peer_id: [u8; 32],
    addr: SocketAddr,
) {
    let Some(dir) = keystore_dir else { return };
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
    source: [u8; 32],
    origin: [u8; 32],
    hash: [u8; 32],
    frames: Vec<Vec<u8>>,
) {
    let targets: Vec<[u8; 32]> = transport
        .linked_peer_ids()
        .await
        .into_iter()
        .filter(|d| *d != source && *d != origin)
        .collect();
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
    inflight.lock().await.insert(
        hash,
        Inflight {
            frames,
            attempts: 0,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            pending_peers: targets.into_iter().collect(),
        },
    );
}

async fn forward_item(
    transport: &Arc<Transport>,
    inflight: &InflightMap,
    source: [u8; 32],
    origin: [u8; 32],
    hash: [u8; 32],
    frame_bytes: Vec<u8>,
) {
    forward_frames(transport, inflight, source, origin, hash, vec![frame_bytes]).await;
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
    pending_pulls: &PendingPulls,
) {
    ack_source(transport, source, hash).await;
    let eid = EventId::new(DeviceId::from(origin), event_seq);
    if !mesh_seen.lock().await.observe(eid) {
        // Already seen this item on the mesh — don't re-apply or re-loop it.
        return;
    }
    // Resync-on-reconnect (resync-1): first sight of this item — keep a
    // resend copy under its original (origin, seq) so it can later be
    // offered to a peer that reconnects after missing it. Sensitive items
    // must never enter the outbox (see `crate::outbox`'s security invariant).
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
    let frames = build_item_frames(lamport, hash, kind, &payload, sensitive, origin, event_seq);
    forward_frames(transport, inflight, source, origin, hash, frames).await;
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
/// our clipboard history OR our own outbox.
fn missing_resync_hashes(
    offered: &[String],
    history_hashes: &[String],
    outbox_hashes: &[String],
) -> Vec<String> {
    offered
        .iter()
        .filter(|h| !history_hashes.iter().any(|x| x == *h) && !outbox_hashes.iter().any(|x| x == *h))
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
    state_rx: &watch::Receiver<State>,
) {
    // FS-052 strict gate (VULN-002 fix): if the active session's peer
    // landed via TOFU and has not been verbally confirmed yet, drop all
    // data-bearing frames (`ClipboardItem`, `Chunk`) until the user runs
    // `fluxctl pair confirm --accept`. Hello / Heartbeat / Ack / Nak /
    // Bye keep flowing so the link stays diagnosable and the FSM still
    // reacts to peer disconnects. Matches the design intent stated in
    // `docs/THREAT-MODEL.md` §3 row B-S: *"a hard gate that blocks
    // Msg::Item processing until the user runs --accept"*.
    let blocks_until_confirmed = matches!(frame.msg, Msg::ClipboardItem(_) | Msg::Chunk(_));
    if blocks_until_confirmed && pending_pairs.lock().await.contains_key(&peer_id) {
        tracing::warn!(
            peer = ?&peer_id[..6],
            "FS-052 gate: dropping clipboard frame — peer not yet verbally confirmed"
        );
        return;
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
                        item.hash, kind, sensitive, lamport, full_payload, outbox, pending_pulls,
                    )
                    .await;
                }
            } else {
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
                    if !item.sensitive {
                        outbox.lock().await.insert(
                            item.hash,
                            OutboxEntry {
                                payload: item.payload.clone(),
                                kind: item.kind,
                                origin: item.origin,
                                seq: item.event_seq,
                                created: Instant::now(),
                            },
                        );
                    }
                    if let Ok(bytes) = fluxsync_proto::encode(&Frame {
                        version: PROTOCOL_VERSION,
                        msg: Msg::ClipboardItem(item.clone()),
                    }) {
                        forward_item(transport, inflight, peer_id, item.origin, item.hash, bytes)
                            .await;
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
                    c.item_id, kind, sensitive, lamport, full_payload, outbox, pending_pulls,
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
            transport.drop_session_for(peer_id).await;
            // FluxMesh Phase 3: drop it from the mesh `peers` list too.
            if peer_meta.lock().await.remove(&peer_id).is_some() {
                let _ = event_tx.try_send(Event::MeshPeersChanged);
            }
            // Only the primary peer drives the single FSM's PeerLost (which
            // clears State + the primary session). A secondary mesh peer
            // leaving must not disturb the primary link (FluxMesh 2C-b).
            // Robustness slice 2: if the primary said Bye but a secondary is
            // still live, fail over to it instead of disconnecting.
            if transport.cached_peer_id().await == Some(peer_id)
                && !try_primary_failover(transport, event_tx, peer_meta).await
            {
                let _ = event_tx.try_send(Event::PeerLost);
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
            pending_pairs.lock().await.remove(&peer_id);
            transport.drop_session_for(peer_id).await;
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
                let _ = event_tx.try_send(Event::PeerLost);
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
                if changed {
                    let _ = event_tx.try_send(Event::MeshPeersChanged);
                }
            }
            // resync-1: offer our outbox to this peer once negotiated. Hello
            // arrives exactly once per session establishment (rekey never
            // re-sends it), so this can't spam a peer with repeated offers.
            if caps.iter().any(|c| c == "resync-1") {
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
            let missing = missing_resync_hashes(&offer.hashes, &history_hashes, &outbox_hashes);
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
                inflight.lock().await.insert(
                    hash,
                    Inflight {
                        frames,
                        attempts: 0,
                        last_sent: Instant::now(),
                        first_sent: Instant::now(),
                        pending_peers: std::iter::once(peer_id).collect(),
                    },
                );
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
                        if !transport.has_session().await {
                            let _ = event_tx.try_send(Event::PeerLost);
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
                    // Linked. DIR-P1-02: a *completed* handshake (not just
                    // this send) resets backoff — the peer is confirmed
                    // reachable, so the next drop starts fresh at the fast
                    // initial retry.
                    backoff
                        .lock()
                        .await
                        .entry(peer_id)
                        .or_insert_with(PeerBackoff::new)
                        .on_handshake_ok();
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
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            accept = server.accept() => {
                let conn = match accept {
                    Ok(c) => c,
                    Err(e) => { tracing::warn!(error = %e, "ipc accept"); continue; }
                };
                let cmd_tx = cmd_tx.clone();
                let state_rx = state_rx.clone();
                let logs_bcast_rx = logs_bcast_tx.subscribe();
                let log_tail = log_tail.clone();
                let client_shutdown = shutdown.clone();
                clients.spawn(async move {
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
            &state_rx,
        )
        .await;

        assert!(
            matches!(event_rx.try_recv(), Ok(Event::PeerLost)),
            "Msg::Bye must emit Event::PeerLost"
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
            &state_rx,
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
            matches!(event_rx.try_recv(), Ok(Event::PeerLost)),
            "Msg::Revoke must emit Event::PeerLost"
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
        let missing = missing_resync_hashes(&offered, &history, &outbox_hashes);
        assert_eq!(missing, vec!["aa".to_string(), "cc".to_string()]);
    }

    /// resync-1: nothing missing when every offered hash is already held.
    #[test]
    fn missing_resync_hashes_empty_when_all_held() {
        use super::missing_resync_hashes;
        let offered = vec!["aa".to_string(), "bb".to_string()];
        let history = vec!["aa".to_string()];
        let outbox_hashes = vec!["bb".to_string()];
        assert!(missing_resync_hashes(&offered, &history, &outbox_hashes).is_empty());
    }

    /// resync-1: defensive cap — even if a caller hands in more than
    /// `MAX_RESYNC_HASHES` offered hashes, the result never exceeds it.
    #[test]
    fn missing_resync_hashes_caps_at_max_resync_hashes() {
        use super::{missing_resync_hashes, MAX_RESYNC_HASHES};
        let offered: Vec<String> = (0..(MAX_RESYNC_HASHES + 5))
            .map(|i| format!("{i:064x}"))
            .collect();
        let missing = missing_resync_hashes(&offered, &[], &[]);
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

        let sensitive_hash = [0xAAu8; 32];
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
            &pending_pulls,
        )
        .await;
        assert!(
            outbox.lock().await.get(sensitive_hash).is_none(),
            "sensitive item must not enter the outbox"
        );

        let plain_hash = [0xBBu8; 32];
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
            &pending_pulls,
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

        let sensitive_hash = [0xCCu8; 32];
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
            b"fake-png-secret".to_vec(),
            &outbox,
            &pending_pulls,
        )
        .await;
        assert!(
            outbox.lock().await.get(sensitive_hash).is_none(),
            "sensitive image must not enter the outbox"
        );

        let plain_hash = [0xDDu8; 32];
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
            b"fake-png-plain".to_vec(),
            &outbox,
            &pending_pulls,
        )
        .await;
        assert!(
            outbox.lock().await.get(plain_hash).is_some(),
            "non-sensitive image must enter the outbox"
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
        let trusted: crate::handshake::TrustedSet = Arc::new(Mutex::new(HashMap::new()));
        let disc_cache = Arc::new(Mutex::new(HashMap::new()));
        let backoff = Arc::new(Mutex::new(HashMap::new()));
        let peer_meta = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let pending_pulls = Arc::new(Mutex::new(HashMap::new()));
        let (_state_tx, state_rx) = tokio::sync::watch::channel(fluxsync_core::State::initial(
            &fluxsync_core::Config::default(),
        ));

        let hash = [0x77u8; 32];
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
            &state_rx,
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
}
