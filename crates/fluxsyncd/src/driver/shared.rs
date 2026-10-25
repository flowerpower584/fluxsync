//! Long-lived shared handles and small shared types used across the driver.

use super::*;

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
pub(super) const MAX_CLEARED_TOMBSTONE: usize = 4096;

/// Record `hashes` as deliberately cleared. Purges tombstone entries older
/// than `crate::outbox::MAX_AGE` first, then evicts the oldest surviving
/// entries if the insert would exceed `MAX_CLEARED_TOMBSTONE`.
pub(super) async fn mark_cleared(tombstone: &ClearedTombstone, hashes: &[[u8; 32]]) {
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
pub(super) async fn cleared_hex_snapshot(tombstone: &ClearedTombstone) -> Vec<String> {
    let now = Instant::now();
    tombstone
        .lock()
        .await
        .iter()
        .filter(|(_, cleared_at)| {
            now.saturating_duration_since(**cleared_at) <= crate::outbox::MAX_AGE
        })
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
pub(super) async fn in_flight_pull_hashes(pending_pulls: &PendingPulls) -> Vec<String> {
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

pub(super) struct Reassembly {
    pub(super) metadata: Option<(u64, Kind, bool)>,
    /// FluxMesh robustness slice 3: the header's EventId, kept so a completed
    /// chunked item can be anti-loop-gated and relayed across a third hop with
    /// the SAME identity (set in the header arm; meaningful once metadata Some).
    pub(super) origin: [u8; 32],
    pub(super) event_seq: u64,
    pub(super) chunks: Vec<Option<Vec<u8>>>,
    pub(super) last_update: Instant,
    pub(super) first_seen: Instant,
    /// The direct sender of this hop's frames (namespaces `reassembly_key`
    /// alongside `item_hash`). A selective NAK must go back to whoever is
    /// actually retransmitting this transfer — the primary link otherwise —
    /// so this is never assumed to equal the mesh `origin` above.
    pub(super) source: [u8; 32],
    /// The real wire content hash (`ClipboardItem.hash` / `Chunk.item_id`),
    /// as opposed to `reassembly_key(source, item_hash)` — the composite
    /// digest used only as this map's key. A `Nak` must carry THIS value:
    /// the sender's `inflight` is keyed by content hash and can never match
    /// the composite digest.
    pub(super) item_hash: [u8; 32],
}

/// An outbound clipboard item awaiting the peer's `Msg::Ack`. Frames are
/// stored already-encoded so the retransmit timer can re-send them
/// verbatim until the ack lands or `MAX_RETRANSMIT` attempts elapse.
/// This is the only delivery guarantee on the UDP path — without it a
/// dropped datagram silently loses the item.
pub(super) struct Inflight {
    pub(super) frames: Vec<Vec<u8>>,
    pub(super) attempts: u8,
    pub(super) last_sent: Instant,
    /// When the item was first queued. Selective-NAK resends keep
    /// `last_sent` perpetually fresh, which defers the `attempts`-based
    /// whole-item retransmit forever — so this is the backstop that
    /// drops an item that never converges. See `INFLIGHT_MAX_AGE`.
    pub(super) first_sent: Instant,
    /// FluxMesh 2C-b: peers this item still awaits an Ack from. An item
    /// (locally copied or relayed) is fanned out to every linked peer; each
    /// peer's Ack removes it from this set, and the item is cleared only
    /// when the set empties. Retransmits go to whoever is still pending.
    pub(super) pending_peers: HashSet<[u8; 32]>,
}

/// Clipboard content this daemon itself wrote to the OS clipboard lately
/// (canonical hash + when), so the watcher can tell the read-back of its own
/// write — an echo, never to be sent back — from the user copying that
/// content again later, which must sync like any other copy.
#[derive(Debug, Default)]
pub(super) struct RecentWrites(pub(super) VecDeque<([u8; 32], Instant)>);

impl RecentWrites {
    const CAP: usize = 10;
    const ECHO_WINDOW: Duration = Duration::from_millis(fluxsync_core::ECHO_WINDOW_MS);

    pub(super) fn record(&mut self, hash: [u8; 32]) {
        self.0.push_back((hash, Instant::now()));
        if self.0.len() > Self::CAP {
            self.0.pop_front();
        }
    }

    /// `hash`, just read off the clipboard, is one of our own writes coming
    /// back. Bounded in time: it used to match any of the last ten writes,
    /// so re-copying something received a while ago was never sent. A
    /// read-back that is somehow later than the window still stops in the
    /// core, where the newest content is always an echo.
    pub(super) fn is_echo(&self, hash: &[u8; 32]) -> bool {
        self.0
            .iter()
            .any(|(h, at)| h == hash && at.elapsed() < Self::ECHO_WINDOW)
    }
}

/// Map of clipboard items sent but not yet acked, keyed by item hash.
pub(super) type InflightMap = Arc<Mutex<HashMap<[u8; 32], Inflight>>>;

/// Resync-on-reconnect (resync-1): shared resend buffer of recent
/// non-sensitive items, written on send/first-sight-receive and read to
/// build a `ResyncOffer` / serve a `ResyncPull`. See `crate::outbox`.
pub(super) type SharedOutbox = Arc<Mutex<Outbox>>;

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
pub(super) type PendingPulls = Arc<Mutex<HashMap<[u8; 32], HashMap<[u8; 32], Instant>>>>;

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
pub(super) type PendingOutboxStage = Arc<Mutex<HashMap<[u8; 32], OutboxEntry>>>;

/// How long a `ResyncPull` we sent stays "pending" before we give up
/// expecting it and would treat a same-hash arrival as a fresh item instead.
pub(super) const RESYNC_PULL_TIMEOUT: Duration = Duration::from_secs(60);

/// Most fresh `ResyncPull` hashes tracked per peer — a few offers' worth.
/// Past it, an offer's extra hashes are simply not pulled this time; a pull
/// we can't track would let the item land as a fresh copy and overwrite the
/// OS clipboard with catch-up content.
pub(super) const MAX_PENDING_PULLS_PER_PEER: usize = 4 * MAX_RESYNC_HASHES;

/// Record the hashes we are about to `ResyncPull` from `peer_id` and return
/// the ones actually tracked — the only ones the caller may pull. Sweeps the
/// peer's stale entries first, then admits new ones up to
/// `MAX_PENDING_PULLS_PER_PEER`, so a stream of offers naming hashes that
/// never get served can't grow the map without bound. Malformed hex (the
/// codec bounds shape and count, but a corrupt entry still fails
/// `decode_hex32`) is dropped, as `Msg::ResyncPull` would skip it anyway.
pub(super) async fn track_pending_pulls(
    pending_pulls: &PendingPulls,
    peer_id: [u8; 32],
    missing: Vec<String>,
) -> Vec<String> {
    let now = Instant::now();
    let mut map = pending_pulls.lock().await;
    let per_peer = map.entry(peer_id).or_default();
    per_peer.retain(|_, asked_at| asked_at.elapsed() < RESYNC_PULL_TIMEOUT);
    let mut tracked = Vec::new();
    for hex_hash in missing {
        if per_peer.len() >= MAX_PENDING_PULLS_PER_PEER {
            break;
        }
        if let Ok(hash) = decode_hex32(&hex_hash) {
            per_peer.insert(hash, now);
            tracked.push(hex_hash);
        }
    }
    if per_peer.is_empty() {
        map.remove(&peer_id);
    }
    tracked
}

/// Consume a pending resync pull for `hash` from `peer_id`, if one is still
/// outstanding and fresh. Also lazily sweeps every other stale entry for that
/// peer (`RESYNC_PULL_TIMEOUT` old) so the bounded map never accumulates
/// pulls that were never served.
pub(super) async fn take_pending_pull(
    pending_pulls: &PendingPulls,
    peer_id: [u8; 32],
    hash: [u8; 32],
) -> bool {
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
pub(super) type MeshSeen = Arc<Mutex<SeenSet>>;

/// FluxMesh Phase 3: per-peer UI metadata (name/platform/battery) captured
/// from EVERY linked peer's Hello/Battery — including the secondaries the
/// single-peer State projection ignores. The `State.peers` list is rebuilt at
/// each `EmitState` by joining this with the live session set
/// (`linked_peer_ids`), so an entry here that lost its session never shows.
#[derive(Debug, Clone)]
pub(super) struct PeerMeta {
    pub(super) name: String,
    pub(super) platform: String,
    /// DIR-P1-01: negotiated capability set for this peer (intersection of
    /// their `Hello.caps` with `SUPPORTED_CAPS`).
    pub(super) caps: Vec<String>,
    pub(super) battery: u8,
    pub(super) charging: bool,
    /// FS-052 wire mutual confirm: true once this peer's `Msg::Hello` has
    /// been processed at least once, so `caps` (possibly empty) is known
    /// to be real negotiated data rather than "not seen yet". Lets
    /// `CmdOp::PairConfirm` tell "peer caps unknown, defer the wire send"
    /// apart from "peer caps known and empty/legacy".
    pub(super) hello_seen: bool,
    /// verify-restart: true once this session has announced its fresh
    /// pending pair to the peer via `Msg::PairVerifyStarted`, so a repeated
    /// (or malicious duplicate) `Hello` can't re-send it. `PeerMeta` is
    /// dropped on session teardown (Bye/Revoke/reject), which is exactly
    /// the "once per session" lifetime the announcement needs.
    pub(super) verify_restart_sent: bool,
}

impl PeerMeta {
    /// Battery defaults to the 255 "unknown" sentinel so a peer seen via Hello
    /// before its first `BatteryStatus` renders "—", not a fake 100%. 255 is
    /// also safe for the Critical check (255 <= 5 is false).
    pub(super) fn new() -> Self {
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

pub(super) type PeerMetaMap = Arc<Mutex<BTreeMap<[u8; 32], PeerMeta>>>;

/// Build the `State.peers` list from the live session set joined with the
/// captured per-peer metadata. Only peers with a live session appear, so a
/// torn-down link never lingers as a ghost. `primary` flags the peer the
/// single-peer `State.peer_*` fields project.
pub(super) async fn build_peers(
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

/// `State.paired`: every trusted device joined with the live `peers` list.
/// Sorted (primary, then online, then by name) so an unchanged set always
/// yields an identical `State` — `EmitState` only wakes subscribers when the
/// snapshot actually differs.
pub(super) async fn build_paired(
    trusted: &TrustedSet,
    peers: &[PeerInfo],
    primary: Option<[u8; 32]>,
) -> Vec<PairedDevice> {
    let mut out: Vec<PairedDevice> = trusted
        .lock()
        .await
        .iter()
        .map(|(id, tp)| {
            let live = peers.iter().find(|p| p.peer_id == *id);
            PairedDevice {
                peer_id: *id,
                name: live
                    .map(|p| p.name.clone())
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or_else(|| tp.name.clone()),
                platform: live.map(|p| p.platform.clone()).unwrap_or_default(),
                online: live.is_some(),
                primary: live.is_some() && Some(*id) == primary,
                battery: live.map_or(255, |p| p.battery),
                charging: live.is_some_and(|p| p.charging),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        (b.primary, b.online, &a.name, a.peer_id).cmp(&(a.primary, a.online, &b.name, b.peer_id))
    });
    out
}

/// Wait this long for an ack before re-sending an inflight item.
pub(super) const RETRANSMIT_INTERVAL: Duration = Duration::from_secs(2);
/// Drop the item after this many re-sends with no ack.
pub(super) const MAX_RETRANSMIT: u8 = 6;
/// Absolute lifetime cap for an inflight item. Selective-NAK resends bump
/// `last_sent`, so the `attempts`/`MAX_RETRANSMIT` path can be deferred
/// indefinitely while a transfer slowly progresses; this is the hard
/// backstop that frees the buffer if it simply never converges.
pub(super) const INFLIGHT_MAX_AGE: Duration = Duration::from_secs(90);
/// How often the receiver emits a selective NAK for an incomplete
/// chunked transfer still in reassembly.
pub(super) const NAK_INTERVAL: Duration = Duration::from_millis(700);
/// Cap on chunk indices a single NAK asks for — kept under
/// `fluxsync_proto::MAX_NAK_MISSING` (512) so the encoded NAK fits one
/// datagram. Remaining gaps are picked up by the next NAK tick.
pub(super) const NAK_MISSING_PER_FRAME: usize = 400;

// ─────────────────────────────────────────────────────────────────
// mDNS discovery dispatcher
// ─────────────────────────────────────────────────────────────────

/// Inbound chunked transfers still being reassembled, keyed by
/// `reassembly_key(source, item_id)`.
pub(super) type ReassemblyMap = Arc<Mutex<HashMap<[u8; 32], Reassembly>>>;

/// Every long-lived handle the driver's tasks share, built once in `run()`.
///
/// Before this existed, each task and handler received these as separate
/// parameters — up to 28 of them, behind `#[allow(clippy::too_many_arguments)]`
/// — and adding one shared map meant threading it through every signature
/// and every test call. Tasks now hold an `Arc<Shared>`; per-call data (the
/// frame, the actions) stays a parameter, and the two pieces of state the
/// event loop owns exclusively (`App`, `SeqStore`) are still passed `&mut`
/// alongside it.
///
/// Everything in here is either immutable after boot or internally
/// synchronized, so `&Shared` is all any task needs.
pub(super) struct Shared {
    // ── Identity and boot configuration (immutable) ──────────────
    pub(super) identity: Identity,
    pub(super) wall_clock: Arc<dyn WallClock + Send + Sync>,
    pub(super) keystore_dir: Option<PathBuf>,
    pub(super) udp_bind: String,
    pub(super) udp_port: u16,
    pub(super) lan_only_handshakes: bool,
    pub(super) shutdown: CancellationToken,

    // ── Channels: into the event loop, out to subscribers ────────
    pub(super) event_tx: mpsc::Sender<Event>,
    pub(super) cmd_tx: mpsc::UnboundedSender<DriverCmd>,
    pub(super) state_watch_tx: watch::Sender<State>,
    pub(super) logs_bcast_tx: broadcast::Sender<LogEntry>,
    pub(super) log_tail: Arc<LogTail>,

    // ── Network, trust and pairing ───────────────────────────────
    pub(super) transport: Arc<Transport>,
    pub(super) metrics: Arc<Mutex<MetricsTracker>>,
    pub(super) trusted: TrustedSet,
    pub(super) pairing_window: PairingWindow,
    pub(super) pending_pairs: PendingSet,
    pub(super) pending_initiator_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    pub(super) deferred_sas_confirm: DeferredSasConfirm,
    pub(super) pin_advert: PinAdvertisement,
    pub(super) disc_cache: DiscoveryCache,
    pub(super) backoff: BackoffMap,
    pub(super) mdns_ctx: MdnsCtx,
    pub(super) peer_meta: PeerMetaMap,

    // ── Item transfer ────────────────────────────────────────────
    pub(super) inflight: InflightMap,
    pub(super) reassembly: ReassemblyMap,
    pub(super) mesh_seen: MeshSeen,
    pub(super) echo_ack_sent: EchoAckSent,
    pub(super) last_written_hashes: Arc<Mutex<RecentWrites>>,

    // ── Resync and history bookkeeping ───────────────────────────
    pub(super) outbox: SharedOutbox,
    pub(super) outbox_stage: PendingOutboxStage,
    pub(super) pending_pulls: PendingPulls,
    pub(super) cleared_tombstone: ClearedTombstone,

    // ── This device's battery: written by the event loop, read by
    //    the heartbeat loop (255 = not read yet) ───────────────────
    pub(super) self_batt_level: std::sync::atomic::AtomicU8,
    pub(super) self_batt_charging: std::sync::atomic::AtomicBool,
    /// Session generation each linked peer was last sent our `Hello` on —
    /// see [`Shared::greet_new_sessions`].
    pub(super) hello_sent: Mutex<HashMap<[u8; 32], u64>>,
}

impl Shared {
    /// Whether the user has sync switched on. While it is off the daemon
    /// neither dials nor answers handshakes: "off" means no link at all, not
    /// a live session the FSM (sitting in `Idle`) pretends isn't there.
    pub(super) fn sync_on(&self) -> bool {
        self.state_watch_tx.borrow().on
    }

    /// Send `msg` (a `Bye` or a `Revoke`) to every linked peer — primary and
    /// mesh secondaries alike — then drop its session. `permanent` (a revoke)
    /// also removes the peer's connection stub, see
    /// [`Transport::purge_peer`]. Returns the peers that were torn down.
    pub(super) async fn tear_down_links(&self, msg: Msg, permanent: bool) -> Vec<[u8; 32]> {
        let ids = self.transport.linked_peer_ids().await;
        if let Ok(bytes) = fluxsync_proto::encode(&Frame {
            version: PROTOCOL_VERSION,
            msg,
        }) {
            for id in &ids {
                let _ = self.transport.send_encrypted_to(*id, &bytes).await;
            }
        }
        for id in &ids {
            if permanent {
                self.transport.purge_peer(*id).await;
            } else {
                self.transport.drop_session_for(*id).await;
            }
        }
        let mut meta = self.peer_meta.lock().await;
        let mut changed = false;
        for id in &ids {
            changed |= meta.remove(id).is_some();
        }
        drop(meta);
        if changed {
            let _ = self.event_tx.try_send(Event::MeshPeersChanged);
        }
        ids
    }

    /// Send our `Hello` (name, platform, caps) once per session to every
    /// linked peer that hasn't had it on its current session generation —
    /// whichever path brought the session up: first link, a mesh secondary
    /// joining while already Linked, a peer's restart replacing a stale
    /// session, a rekey. It used to ride only on the FSM's Handshaking →
    /// Linked transition, so a session that came up while already Linked
    /// never got one: the peer never learned this device's name or caps (no
    /// resync with it, and a SAS confirm on its side waiting forever).
    pub(super) async fn greet_new_sessions(&self, name: &str) {
        let ids = self.transport.linked_peer_ids().await;
        let mut sent = self.hello_sent.lock().await;
        sent.retain(|id, _| ids.contains(id));
        let mut frame: Option<Vec<u8>> = None;
        for id in ids {
            let Some(generation) = self.transport.session_generation_for(id).await else {
                continue;
            };
            if sent.get(&id) == Some(&generation) {
                continue;
            }
            if frame.is_none() {
                frame = fluxsync_proto::encode(&Frame {
                    version: PROTOCOL_VERSION,
                    msg: Msg::Hello(fluxsync_proto::Hello {
                        name: name.to_string(),
                        platform: self_platform().to_string(),
                        caps: SUPPORTED_CAPS.iter().map(|c| (*c).to_string()).collect(),
                    }),
                })
                .ok();
            }
            let Some(bytes) = frame.as_deref() else {
                return;
            };
            match self.transport.send_encrypted_to(id, bytes).await {
                Ok(()) => {
                    sent.insert(id, generation);
                }
                Err(e) => tracing::warn!(peer = ?&id[..6], error = %e, "send hello failed"),
            }
        }
    }

    /// The `State` clients see: the app's snapshot plus connection metrics,
    /// the live mesh peer list and the paired-device list. Shared by
    /// `EmitState` (the watch) and `Status` (a direct poll).
    pub(super) async fn publishable_state(&self, app: &mut App) -> State {
        let m = self.metrics.lock().await.snapshot();
        app.set_metrics(Some(m));
        let mut snap = app.snapshot().clone();
        let primary = self.transport.cached_peer_id().await;
        snap.peers = build_peers(&self.transport, &self.peer_meta, primary).await;
        snap.paired = build_paired(&self.trusted, &snap.peers, primary).await;
        snap
    }

    /// A context with fresh, empty state around `transport` — for unit
    /// tests, which then override or inspect the fields they care about.
    #[cfg(test)]
    pub(super) fn for_test(transport: Arc<Transport>) -> Self {
        let (event_tx, _) = mpsc::channel(EVENT_CHANNEL_CAP);
        let (cmd_tx, _) = mpsc::unbounded_channel();
        let (state_watch_tx, _) = watch::channel(State::initial(&CoreConfig::default()));
        let (logs_bcast_tx, _) = broadcast::channel(64);
        Self {
            identity: Identity::generate(),
            wall_clock: Arc::new(crate::wall::ChronoWallClock),
            keystore_dir: None,
            udp_bind: "127.0.0.1".into(),
            udp_port: 0,
            lan_only_handshakes: false,
            shutdown: CancellationToken::new(),
            event_tx,
            cmd_tx,
            state_watch_tx,
            logs_bcast_tx,
            log_tail: Arc::new(LogTail::new()),
            metrics: transport.metrics.clone(),
            transport,
            trusted: Arc::new(Mutex::new(HashMap::new())),
            pairing_window: Arc::new(Mutex::new(None)),
            pending_pairs: Arc::new(Mutex::new(HashMap::new())),
            pending_initiator_tx: Arc::new(Mutex::new(None)),
            deferred_sas_confirm: Arc::new(Mutex::new(HashSet::new())),
            pin_advert: Arc::new(Mutex::new(None)),
            disc_cache: Arc::new(Mutex::new(HashMap::new())),
            backoff: Arc::new(Mutex::new(HashMap::new())),
            mdns_ctx: Arc::new(Mutex::new(None)),
            peer_meta: Arc::new(Mutex::new(BTreeMap::new())),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            reassembly: Arc::new(Mutex::new(HashMap::new())),
            mesh_seen: Arc::new(Mutex::new(SeenSet::default())),
            echo_ack_sent: Arc::new(Mutex::new(HashSet::new())),
            last_written_hashes: Arc::new(Mutex::new(RecentWrites::default())),
            outbox: Arc::new(Mutex::new(Outbox::new())),
            outbox_stage: Arc::new(Mutex::new(HashMap::new())),
            pending_pulls: Arc::new(Mutex::new(HashMap::new())),
            cleared_tombstone: Arc::new(Mutex::new(HashMap::new())),
            self_batt_level: std::sync::atomic::AtomicU8::new(255),
            self_batt_charging: std::sync::atomic::AtomicBool::new(false),
            hello_sent: Mutex::new(HashMap::new()),
        }
    }
}
