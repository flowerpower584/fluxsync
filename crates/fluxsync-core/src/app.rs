//! Composes the FSM, state, dedup ring, Lamport clock, and policy into one
//! object the daemon can drive event-by-event.
//!
//! The daemon owns one `App`. Every external nudge becomes an `Event`;
//! `App::handle` returns the list of `Action`s the daemon must execute.
//!
//! `App` is `Send + Sync`-free on purpose: the daemon runs it inside a
//! single tokio task. That removes a whole class of races at zero runtime
//! cost.

use crate::clock::{Clock, LamportClock, WallClock};
use crate::dedup::{ContentHash, DedupRing, SeenSet};
use crate::error::CoreError;
use crate::events::{Action, Event, LogEntry};
use crate::fsm::{transition, Phase};
use crate::id::{DeviceId, EventId};
use crate::policy::{status_for, Decision, Direction, FirewallPolicy};
use crate::state::{Config, HistoryItem, PendingItem, State};
use fluxsync_proto::Kind;
use std::collections::BTreeMap;

/// The bytes + routing the daemon needs to actually emit a deferred item once
/// the user approves it. Kept OUT of `State` (and thus off the IPC wire) — the
/// serializable [`PendingItem`] carries only a hash + preview, mirroring how
/// history keeps payloads local.
#[derive(Debug, Clone)]
struct PendingPayload {
    direction: Direction,
    kind: Kind,
    payload: Vec<u8>,
    sensitive: bool,
    hash: [u8; 32],
}

const HISTORY_SOFT_CAP: usize = 50;

/// Cap the live history to `HISTORY_SOFT_CAP`, but NEVER evict a pinned item.
/// Mirrors the on-disk vault's favorite-aware prune: favorites are exempt from
/// the cap, so a pinned item past the soft cap stays visible in the UI instead
/// of vanishing from `state.history` (the only structure clients render) while
/// surviving orphaned on disk. Order (newest-first) is preserved.
fn cap_history_keeping_favorites(history: &mut Vec<HistoryItem>) {
    let mut non_fav_kept = 0usize;
    history.retain(|h| {
        if h.favorite {
            return true;
        }
        non_fav_kept += 1;
        non_fav_kept <= HISTORY_SOFT_CAP
    });
}

/// One per-peer link in the mesh. Today it carries only the FSM phase; later
/// phases grow per-peer session metrics, role (send/receive-only), and
/// last-seen. Keeping a phase *per link* is what lets several devices be in
/// different states at once (one Linked, one Handshaking) — the core thing the
/// single-peer `App.phase` cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLink {
    pub phase: Phase,
}

impl PeerLink {
    #[must_use]
    pub fn new() -> Self {
        Self { phase: Phase::Idle }
    }
}

impl Default for PeerLink {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of ingesting a remote clipboard item at this node (mesh anti-loop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingest {
    /// First time this `EventId` is seen here: apply it locally, then forward
    /// it to the listed links (everyone Linked except the sender and origin).
    Apply { forward_to: Vec<DeviceId> },
    /// Already seen (looped back, or a duplicate from another path): drop it.
    Dropped,
}

pub struct App {
    pub phase: Phase,
    pub state: State,
    pub clock: LamportClock,
    pub dedup: DedupRing,
    config: Config,
    /// Peer id of the last peer this app paired with. Survives `ManualUnpair`
    /// (which zeroes `state.peer_id`) so a later re-pair can tell whether the
    /// new peer is the same device or a different one — see FS-046.
    last_paired_peer_id: [u8; 32],
    // ── FluxMesh foundation (Phase 1) ────────────────────────────────
    // These back the multi-peer coordinator API (`handle_peer`,
    // `broadcast_local`, `ingest_remote`). The single-peer `handle` path
    // above is untouched and does NOT use them yet; the daemon migrates onto
    // them in Phase 2 once it can route inbound frames per peer.
    /// This device's own id, used as `EventId.origin` for locally-copied
    /// items. `ZERO` until set via [`App::new_with_device`].
    self_device: DeviceId,
    /// Per-origin monotonic counter for `EventId`s this device originates.
    local_seq: u64,
    /// Mesh anti-loop guard — recently-seen `EventId`s. Independent of the
    /// content-hash `dedup` ring (which guards OS clipboard echoes).
    seen: SeenSet,
    /// Per-peer link state, keyed by device. One entry per known peer.
    links: BTreeMap<DeviceId, PeerLink>,
    /// Firewall `Ask` parking lot: hex content hash → the bytes/routing needed
    /// to emit the item if the user approves it. The display half lives in
    /// `state.pending`; this half never leaves the daemon.
    pending_payloads: BTreeMap<String, PendingPayload>,
}

impl App {
    #[must_use]
    pub fn new(config: Config) -> Self {
        let state = State::initial(&config);
        Self {
            phase: Phase::Idle,
            state,
            clock: LamportClock::new(),
            dedup: DedupRing::default(),
            config,
            last_paired_peer_id: [0u8; 32],
            self_device: DeviceId::ZERO,
            local_seq: 0,
            seen: SeenSet::default(),
            links: BTreeMap::new(),
            pending_payloads: BTreeMap::new(),
        }
    }

    /// Same as [`App::new`] but stamps this device's own id, used as the
    /// `EventId.origin` of locally-copied items in the mesh coordinator.
    #[must_use]
    pub fn new_with_device(config: Config, self_device: DeviceId) -> Self {
        let mut app = Self::new(config);
        app.self_device = self_device;
        app
    }

    /// Read-only snapshot. Cheap; no allocation.
    #[must_use]
    pub fn snapshot(&self) -> &State {
        &self.state
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn set_metrics(&mut self, m: Option<crate::state::ConnectionMetrics>) {
        self.state.metrics = m;
    }

    pub fn set_latency(&mut self, ms: u32) {
        self.state.link_latency_ms = ms;
    }

    pub fn set_charge_override(&mut self, value: bool) {
        self.config.charge_override = value;
        self.state.charge_override = value;
    }

    /// DIR-P3-01: rename this device. Validates non-empty (after trim),
    /// within the `Msg::Hello.name` wire bound, and printable — the same
    /// gate `fluxsync_proto::codec` enforces on the receiving end, checked
    /// here too so a rejected name never reaches the config/state at all.
    /// Takes effect for an already-linked peer on the next session
    /// establishment (`Action::OpenSession` reads `config.peer_name_self`
    /// fresh every time); the caller is responsible for persisting it
    /// across restarts.
    pub fn set_device_name(&mut self, name: &str) -> Result<(), CoreError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidDeviceName("name is empty".into()));
        }
        if trimmed.len() > fluxsync_proto::MAX_HELLO_NAME {
            return Err(CoreError::InvalidDeviceName(format!(
                "name exceeds {} bytes",
                fluxsync_proto::MAX_HELLO_NAME
            )));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(CoreError::InvalidDeviceName(
                "name contains non-printable characters".into(),
            ));
        }
        self.config.peer_name_self = trimmed.to_string();
        self.state.device_name = trimmed.to_string();
        Ok(())
    }

    /// Replace the clipboard firewall policy at runtime (driven by an IPC
    /// command). Takes effect on the next clipboard event. Mirrored into
    /// `state.firewall` so the next snapshot shows it to clients.
    pub fn set_firewall(&mut self, policy: FirewallPolicy) {
        self.config.firewall = policy.clone();
        self.state.firewall = policy;
    }

    /// Current firewall policy (for the state projection / IPC readback).
    #[must_use]
    pub fn firewall(&self) -> &FirewallPolicy {
        &self.config.firewall
    }

    /// Clipboard firewall gate (chantier A). Judges the item, then either lets
    /// the sync action through (`Pass`), drops it silently (`Never`), or parks
    /// it for the user (`Ask`) — stripping the action and queuing it in
    /// `state.pending` + `pending_payloads`. The inbound `AckItem` is always
    /// KEPT so a held/blocked peer stops retransmitting (same contract as the
    /// dedup-suppress path).
    fn apply_firewall(&mut self, event: &Event, actions: &mut Vec<Action>) {
        let (kind, sensitive, dir, hash, payload, preview) = match event {
            Event::LocalClipboardChange {
                kind,
                sensitive,
                hash,
                payload,
                preview,
                ..
            } => (*kind, *sensitive, Direction::Outbound, *hash, payload, preview),
            Event::FrameReceivedClipboard {
                kind,
                sensitive,
                hash,
                payload,
                preview,
                ..
            } => (*kind, *sensitive, Direction::Inbound, *hash, payload, preview),
            _ => return,
        };
        match self.config.firewall.decide(kind, sensitive, dir) {
            Decision::Pass => {}
            Decision::Block => Self::strip_sync_action(dir, actions),
            Decision::Defer => {
                Self::strip_sync_action(dir, actions);
                self.park_pending(dir, kind, sensitive, hash, payload, preview);
            }
        }
    }

    /// Drop the action that would have synced this item, by direction.
    fn strip_sync_action(dir: Direction, actions: &mut Vec<Action>) {
        match dir {
            Direction::Outbound => actions.retain(|a| !matches!(a, Action::SendItem { .. })),
            Direction::Inbound => actions.retain(|a| !matches!(a, Action::WriteClipboard { .. })),
        }
    }

    /// Park an `Ask`-held item: record the display half in `state.pending` and
    /// the payload half in `pending_payloads`, both keyed by hex content hash.
    /// Re-parking the same hash is a no-op (idempotent on retransmits).
    fn park_pending(
        &mut self,
        dir: Direction,
        kind: Kind,
        sensitive: bool,
        hash: [u8; 32],
        payload: &[u8],
        preview: &str,
    ) {
        let key = hex32(&hash);
        if self.pending_payloads.contains_key(&key) {
            return;
        }
        self.pending_payloads.insert(
            key.clone(),
            PendingPayload {
                direction: dir,
                kind,
                payload: payload.to_vec(),
                sensitive,
                hash,
            },
        );
        self.state.pending.push(PendingItem {
            hash: key,
            kind,
            preview: preview.trim().to_string(),
            sensitive,
            direction: dir,
        });
    }

    /// Resolve a parked item by hex `hash`. Always removes it from both queues
    /// and emits state; on `allow` it also re-emits the held sync action so the
    /// daemon finally sends/writes it. An unknown hash is a harmless no-op.
    fn resolve_pending(&mut self, hash: &str, allow: bool) -> Vec<Action> {
        self.state.pending.retain(|p| p.hash != hash);
        let Some(p) = self.pending_payloads.remove(hash) else {
            return vec![Action::EmitState];
        };
        if !allow {
            return vec![Action::EmitState];
        }
        let action = match p.direction {
            Direction::Outbound => Action::SendItem {
                hash: p.hash,
                kind: p.kind,
                payload: p.payload,
                sensitive: p.sensitive,
            },
            Direction::Inbound => Action::WriteClipboard {
                kind: p.kind,
                payload: p.payload,
            },
        };
        vec![action, Action::EmitState]
    }

    /// Drop every parked `Ask` item (both the display row and the held
    /// payload). Called by the teardown paths — manual unpair, the security
    /// wipes, and a peer-swap — because once the peer those items were waiting
    /// on is gone there is nobody to deliver them to. Without this they leak:
    /// repeated park+unpair cycles accumulate orphaned rows in memory and in
    /// every client's UI forever (no code path else clears them).
    fn drop_pending(&mut self) {
        self.state.pending.clear();
        self.pending_payloads.clear();
    }

    // ── FluxMesh coordinator API (Phase 1 foundation) ───────────────────
    // Pure, peer-keyed primitives that the daemon adopts in Phase 2. They
    // own only per-peer phase + the mesh seen-set; they never touch the
    // single-peer `handle` path, so existing behaviour is unaffected.

    /// This device's own id (`ZERO` unless set via [`App::new_with_device`]).
    #[must_use]
    pub fn self_device(&self) -> DeviceId {
        self.self_device
    }

    /// Current FSM phase of one peer's link, or `None` if no such link.
    #[must_use]
    pub fn link_phase(&self, peer: DeviceId) -> Option<Phase> {
        self.links.get(&peer).map(|l| l.phase)
    }

    /// Every peer whose link is currently `Linked`.
    #[must_use]
    pub fn linked_peers(&self) -> Vec<DeviceId> {
        self.links
            .iter()
            .filter(|(_, l)| l.phase == Phase::Linked)
            .map(|(d, _)| *d)
            .collect()
    }

    /// Drive ONE peer's link with an event, returning that link's actions.
    ///
    /// Runs the same pure `transition` the single-peer `handle` does, but each
    /// peer's phase advances independently in `links`, so devices can be in
    /// different phases at once. Creates the link (Idle) on first sight. This
    /// performs no global state mutation — phase is the only state it owns.
    pub fn handle_peer(&mut self, peer: DeviceId, event: &Event) -> Vec<Action> {
        let link = self.links.entry(peer).or_default();
        let (next, actions) = transition(link.phase, event);
        link.phase = next;
        actions
    }

    /// Allocate the next `EventId` for an item this device originates.
    pub fn next_local_event_id(&mut self) -> EventId {
        let seq = self.local_seq;
        self.local_seq += 1;
        EventId::new(self.self_device, seq)
    }

    /// Fan a locally-copied item out to every `Linked` peer.
    ///
    /// Returns the fresh `EventId` stamped on the item (already recorded in the
    /// seen-set so an echo can't loop back) and one `(peer, SendItem)` per live
    /// link — the daemon sends each on that peer's transport.
    pub fn broadcast_local(
        &mut self,
        hash: [u8; 32],
        kind: Kind,
        payload: &[u8],
        sensitive: bool,
    ) -> (EventId, Vec<(DeviceId, Action)>) {
        let id = self.next_local_event_id();
        self.seen.observe(id);
        let targets = self
            .links
            .iter()
            .filter(|(_, l)| l.phase == Phase::Linked)
            .map(|(d, _)| {
                (
                    *d,
                    Action::SendItem {
                        hash,
                        kind,
                        payload: payload.to_vec(),
                        sensitive,
                    },
                )
            })
            .collect();
        (id, targets)
    }

    /// Ingest a remote item identified by `event_id`, arriving on link
    /// `source`. Mesh anti-loop: drop if the id was already seen here;
    /// otherwise mark it seen and forward to every `Linked` peer EXCEPT the
    /// sender and the origin device — so it never echoes back the way it came
    /// and never returns to whoever first created it.
    pub fn ingest_remote(&mut self, source: DeviceId, event_id: EventId) -> Ingest {
        if !self.seen.observe(event_id) {
            return Ingest::Dropped;
        }
        let forward_to = self
            .links
            .iter()
            .filter(|(d, l)| {
                l.phase == Phase::Linked && **d != source && **d != event_id.origin
            })
            .map(|(d, _)| *d)
            .collect();
        Ingest::Apply { forward_to }
    }

    /// Drive the state machine with one event. Returns the side-effect
    /// commands the daemon must execute, in order.
    ///
    /// `wall` is `?Sized` so callers may pass either a concrete value
    /// (`&StubWallClock` in tests) or a trait object (`&dyn WallClock`
    /// in the daemon, which holds an `Arc<dyn WallClock + Send + Sync>`).
    #[allow(clippy::needless_pass_by_value)] // Event is consumed by design; callers lose ownership.
    #[allow(clippy::too_many_lines)] // One match arm per event; splitting the dispatch hurts readability.
    pub fn handle<W: WallClock + ?Sized>(&mut self, event: Event, wall: &W) -> Vec<Action> {
        // [FIX] Optimization: Removed expensive state.clone().
        // Instead, we manually track if we need to EmitState.

        // ── Firewall Ask resolution (chantier A) ────────────────────────
        // A parked item's approve/deny bypasses the FSM entirely: it touches
        // no phase, only the pending queues, and re-emits the held action.
        if let Event::ResolvePending { hash, allow } = &event {
            return self.resolve_pending(hash, *allow);
        }

        // ── Pre-transition state mutations ──────────────────────────────
        // (everything that is "data the FSM expects to already be in state")
        let mut suppress_action = false;
        match &event {
            Event::ToggleOn => self.state.on = true,
            Event::ToggleOff => self.state.on = false,
            Event::PeerSeen { name, peer_id } => {
                if self.is_peer_mismatch(*peer_id) {
                    // [REMEDIATION] Completely abort the process.
                    // DO NOT transition, DO NOT return any actions.
                    return vec![];
                }
                self.state.peer_name.clone_from(name);
                // Don't overwrite peer_id with placeholder
                if *peer_id != [0u8; 32] {
                    // FS-046: a re-pair with a *different* peer must drop the
                    // previous peer's clipboard history. ManualUnpair keeps the
                    // history (same-device reconnect is expected to resume it),
                    // but without this a new peer would inherit — and could
                    // BurstReplay — the prior peer's secrets.
                    if self.last_paired_peer_id != [0u8; 32] && *peer_id != self.last_paired_peer_id
                    {
                        self.state.history.clear();
                        self.drop_pending();
                        self.state.vault_wipe_gen += 1; // also wipe the on-disk vault
                    }
                    self.last_paired_peer_id = *peer_id;
                    self.state.peer_id = *peer_id;
                }
            }
            Event::BatteryChangedSelf { level, charging } => {
                self.state.battery_level = *level;
                self.state.charging = *charging;
            }
            Event::BatteryChangedPeer { level, charging } => {
                self.state.peer_battery = *level;
                self.state.peer_charging = *charging;
            }
            Event::PeerPlatform { platform } => {
                self.state.peer_platform.clone_from(platform);
            }
            Event::PeerCaps { caps } => {
                self.state.peer_caps.clone_from(caps);
            }
            Event::LocalClipboardChange {
                hash,
                kind,
                preview,
                sensitive,
                lamport,
                ..
            } => {
                let preview = preview.trim();
                self.clock.observe(*lamport);
                // SE-14: `hash` here was computed locally by the daemon
                // from the OS clipboard payload, so wrapping in
                // `ContentHash::from_blake3` is sound.
                if !self.dedup.observe(ContentHash::from_blake3(*hash)) {
                    suppress_action = true; // saw it from peer already, don't echo
                } else if !sensitive {
                    self.push_history(HistoryItem {
                        kind: *kind,
                        preview: preview.to_string(),
                        time: wall.hhmm(),
                        source: crate::state::HistorySource::Local,
                        sensitive: *sensitive,
                        lamport: *lamport,
                        hash: hex32(hash),
                        favorite: false,
                    });
                }
            }
            Event::FrameReceivedClipboard {
                hash,
                kind,
                payload,
                preview,
                sensitive,
                lamport,
            } => {
                // Strip leading/trailing whitespace from the preview
                let preview = preview.trim();

                // On synchronise notre horloge logique (Lamport) avec celle de l'Android
                self.clock.observe(*lamport);

                // SE-14: the wire `hash` field is sender-controlled, so
                // we recompute the digest from the payload before keying
                // the dedup ring. Trusting `*hash` would let a hostile
                // peer pick which slot in the ring gets occupied,
                // poisoning history with a chosen-collision payload.
                // CRLF-canonicalize text payloads (not binary images) so an
                // LF/CRLF line-ending difference can't defeat dedup and
                // ping-pong the item back to the peer.
                let computed = if matches!(kind, Kind::Image) {
                    DedupRing::hash(payload)
                } else {
                    DedupRing::hash(
                        crate::canon_text(&String::from_utf8_lossy(payload)).as_bytes(),
                    )
                };

                // Dedup by content hash. `observe` returns false when this
                // hash was already seen — that covers three cases at once:
                // an echo of our own local copy, a duplicate retransmit, and
                // a malicious peer reusing a hash to poison history. In every
                // case we drop the frame and only send an Ack.
                if !self.dedup.observe(computed) {
                    suppress_action = true;
                } else if !sensitive {
                    // Record only items the firewall ADMITS. A Block or Defer
                    // (Ask) decision must not enter history/vault before the
                    // gate runs (apply_firewall, post-transition): otherwise
                    // blocked content is persisted and shown to every client
                    // despite the policy, and a not-yet-approved deferred item
                    // is recorded before the user decides. Deferred items are
                    // parked in `pending` by apply_firewall and written on
                    // approval; denied/blocked ones are dropped here.
                    let admitted = matches!(
                        self.config
                            .firewall
                            .decide(*kind, *sensitive, Direction::Inbound),
                        Decision::Pass
                    );
                    if admitted {
                        self.push_history(HistoryItem {
                            kind: *kind,
                            preview: preview.to_string(),
                            time: wall.hhmm(),
                            source: crate::state::HistorySource::Remote,
                            sensitive: *sensitive,
                            lamport: *lamport,
                            hash: hex32(hash),
                            favorite: false,
                        });
                    }
                }
            }
            Event::PeerLost => {
                self.state.peer_battery = 255; // sentinel: unknown → UI shows "—"
                self.state.peer_charging = false;
            }
            Event::PrimaryFailover {
                peer_id,
                name,
                platform,
                caps,
            } => {
                // Deliberate rebind to an already-trusted, already-session-live
                // secondary (the daemon promoted it into the primary slot). No
                // is_peer_mismatch guard: this is a vouched promotion, not a
                // stranger appearing. History is KEPT — the promoted peer was an
                // active mesh peer whose items are already legitimately present
                // (unlike a fresh re-pair, which clears under FS-046).
                self.state.peer_name.clone_from(name);
                self.state.peer_platform.clone_from(platform);
                self.state.peer_caps.clone_from(caps);
                if *peer_id != [0u8; 32] {
                    self.last_paired_peer_id = *peer_id;
                    self.state.peer_id = *peer_id;
                }
                // Promoted peer's charge is unknown until its next Battery frame.
                self.state.peer_battery = 255; // sentinel: unknown → UI shows "—"
                self.state.peer_charging = false;
            }
            Event::UntrustedPeerSeen { .. } => {
                self.state.peer_name.clear();
                self.state.peer_platform.clear();
                self.state.peer_caps.clear();
                self.state.peer_id = [0u8; 32];
                self.state.peer_battery = 255; // sentinel: unknown → UI shows "—"
                self.state.peer_charging = false;
                self.state.history.clear();
                self.drop_pending();
                self.state.vault_wipe_gen += 1; // also wipe the on-disk vault
            }
            Event::GhostTimeout
                if !matches!(self.phase, Phase::Linked | Phase::Paused | Phase::Halted) =>
            {
                self.state.peer_name.clear();
                self.state.peer_platform.clear();
                self.state.peer_caps.clear();
                self.state.peer_id = [0u8; 32];
                self.state.peer_battery = 255; // sentinel: unknown → UI shows "—"
                self.state.peer_charging = false;
                self.state.history.clear();
                self.drop_pending();
                self.state.vault_wipe_gen += 1; // also wipe the on-disk vault
            }
            Event::ManualUnpair => {
                self.state.on = false;
                self.state.peer_name.clear();
                self.state.peer_id = [0u8; 32];
                self.state.trusted_peer_name = None;
                self.state.peer_battery = 255; // sentinel: unknown → UI shows "—"
                self.state.peer_charging = false;
                // History is deliberately KEPT (same-device reconnect resumes
                // it), but parked Ask items are dropped: the peer they targeted
                // is gone, so they would otherwise leak forever.
                self.drop_pending();
            }
            Event::SetTrustedPeer { name } => {
                self.state.trusted_peer_name = Some(name.clone());
            }
            Event::SetFavorite { hash, favorite } => {
                for h in self.state.history.iter_mut().filter(|h| &h.hash == hash) {
                    h.favorite = *favorite;
                }
            }
            _ => {}
        }

        if suppress_action {
            // [REMEDIATION] If suppressed (duplicate/replay), we skip the FSM transition entirely.
            // However, for incoming clipboard frames, we still MUST send an Ack to stop the peer's retransmission.
            // DIR-P1-09: `DuplicateDropped` lets the daemon count this at the
            // dedup chokepoint without the FSM performing any I/O itself.
            if let Event::FrameReceivedClipboard { hash, .. } = &event {
                return vec![Action::DuplicateDropped, Action::AckItem { hash: *hash }];
            }
            return vec![Action::DuplicateDropped];
        }

        // ── Run the pure transition ─────────────────────────────────────
        let (next, mut actions) = transition(self.phase, &event);

        // ── Clipboard firewall gate (chantier A) ────────────────────────
        // Drop the apply/broadcast action when the policy blocks this item.
        // No-op while the firewall is disabled (the default) → behaviour
        // identical to pre-firewall.
        self.apply_firewall(&event, &mut actions);

        // The HandshakeOk→Linked transition emits a placeholder `SendBattery`
        // (fsm.rs uses level=100). Overwrite every outgoing battery action with
        // this device's real, current reading so a freshly linked peer shows the
        // true battery immediately instead of a bogus 100% until the next poll.
        actions.retain_mut(|a| {
            if let Action::SendBattery { level, charging } = a {
                *level = self.state.battery_level;
                *charging = self.state.charging;
                // 255 = no real reading yet (desktop without a battery, or the
                // first seconds before the watcher runs). Drop it: the proto
                // caps level at 100 so 255 cannot be encoded, and the peer
                // correctly keeps its own "—" until a real value arrives via
                // the heartbeat.
                return *level != 255;
            }
            true
        });

        // Battery-policy phase override (post-transition)
        // [FIX] Force Halted/Paused even in Discovering/Handshaking if battery is bad.
        self.phase = match next {
            Phase::Idle => Phase::Idle,
            _ => self.phase_for_policy_ext(next),
        };

        // Sync phase name into the serializable State so Android/macOS
        // can read the actual FSM phase from the JSON.
        self.state.phase = match self.phase {
            Phase::Idle => "idle",
            Phase::Discovering => "discovering",
            Phase::Handshaking => "handshaking",
            Phase::Linked => "linked",
            Phase::Paused => "paused",
            Phase::Halted => "halted",
        }
        .to_string();

        // Recompute derived `status` field after every event, then make
        // sure subscribers are notified if it actually changed.
        let new_status = status_for(&self.state);
        if self.state.status != new_status {
            self.state.status = new_status;
            if !actions.contains(&Action::EmitState) {
                actions.push(Action::EmitState);
            }
        }

        // Catch-all: Ensure EmitState is present if any significant state changed.
        // We unconditionally add it for events that mutate state.
        if matches!(
            event,
            Event::ToggleOn
                | Event::ToggleOff
                | Event::BatteryChangedSelf { .. }
                | Event::BatteryChangedPeer { .. }
                | Event::PeerSeen { .. }
                | Event::PeerLost
                | Event::ManualUnpair
                | Event::UntrustedPeerSeen { .. }
                | Event::GhostTimeout
                | Event::SetTrustedPeer { .. }
                | Event::SetFavorite { .. }
                | Event::FrameReceivedClipboard { .. }
                | Event::LocalClipboardChange { .. }
        ) && !actions.contains(&Action::EmitState)
        {
            actions.push(Action::EmitState);
        }

        actions
    }

    #[must_use]
    pub fn is_peer_mismatch(&self, other_id: [u8; 32]) -> bool {
        // If we are already handshaking or linked with someone else
        if !self.state.peer_name.is_empty() && self.state.peer_id != other_id {
            // We only care about mismatches if we are NOT in Idle or Discovering
            return !matches!(self.phase, Phase::Idle | Phase::Discovering);
        }
        false
    }

    fn push_history(&mut self, item: HistoryItem) {
        // [FIX] Zero-Day: Lamport clocks reset to 0 when the daemon restarts, causing
        // new items from the Mac to be sorted to the BOTTOM of the Android's history.
        // Android Kotlin code only checks the FIRST item to update the OS clipboard,
        // so it silently ignored new copies.
        // By inserting at index 0 and NOT sorting by Lamport, we guarantee the
        // newest item is always at the top of the history.
        self.state.history.insert(0, item);

        if self.state.history.len() > HISTORY_SOFT_CAP {
            cap_history_keeping_favorites(&mut self.state.history);
        }
    }

    /// Rehydrate history persisted by FluxVault. Called once at startup,
    /// before the daemon serves any state, so the first snapshot already
    /// carries the restored list. `items` are newest-first; the list is
    /// capped to the in-memory soft cap.
    pub fn restore_history(&mut self, mut items: Vec<HistoryItem>) {
        cap_history_keeping_favorites(&mut items);
        self.state.history = items;
    }

    fn phase_for_policy_ext(&self, fsm_next: Phase) -> Phase {
        use crate::state::Status;
        match status_for(&self.state) {
            Status::Critical => {
                // Critical battery: force Halted ONLY if we're in a
                // connected phase. Never override Discovering/Handshaking
                // — the FSM needs those to reconnect.
                match fsm_next {
                    Phase::Linked | Phase::Paused | Phase::Halted => Phase::Halted,
                    other => other,
                }
            }
            Status::Paused => {
                // If FSM wants to be Linked/Paused/Halted, we obey battery.
                // If it wants to be Discovering/Handshaking, we let it stay there
                // unless it's Critical.
                match fsm_next {
                    Phase::Linked | Phase::Paused | Phase::Halted => Phase::Paused,
                    other => other,
                }
            }
            Status::Syncing | Status::Inactive => {
                // Battery is healthy: upgrade Paused/Halted back to Linked.
                // NEVER promote Discovering/Handshaking to Linked — that
                // would trap the FSM with a dead session after PeerLost.
                match fsm_next {
                    Phase::Paused | Phase::Halted => Phase::Linked,
                    other => other,
                }
            }
        }
    }

    /// Logger helper for the daemon — wraps a manual `EmitLog` in a single
    /// place so the friendly text stays consistent with what the FSM emits.
    #[must_use]
    pub fn log(level_msg: LogEntry) -> Action {
        Action::EmitLog(level_msg)
    }
}

/// Lowercase hex of a 32-byte content hash, for `HistoryItem::hash`.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::StubWallClock;
    use crate::events::LogLevel;
    use crate::state::Status;
    use fluxsync_proto::Kind;

    fn wall() -> StubWallClock {
        StubWallClock::new("14:32", 1_700_000_000_000)
    }

    fn boot() -> App {
        App::new(Config::default())
    }

    #[test]
    fn fresh_app_is_idle_inactive() {
        let app = boot();
        assert_eq!(app.phase, Phase::Idle);
        assert_eq!(app.state.status, Status::Inactive);
        assert!(!app.state.on);
    }

    #[test]
    fn toggle_on_marks_on_and_starts_discovery() {
        let mut app = boot();
        let actions = app.handle(Event::ToggleOn, &wall());
        assert!(app.state.on);
        assert_eq!(app.phase, Phase::Discovering);
        assert!(actions.iter().any(|a| matches!(a, Action::StartDiscovery)));
    }

    #[test]
    fn full_happy_path_to_linked() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy S21 Ultra".into(),
            },
            &wall(),
        );
        let _ = app.handle(Event::HandshakeOk, &wall());
        // After HandshakeOk, with both batteries healthy, status should be Syncing
        // and phase should be Linked.
        app.state.battery_level = 80;
        app.state.peer_battery = 70;
        let _ = app.handle(
            Event::BatteryChangedSelf {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        assert_eq!(app.state.status, Status::Syncing);
        assert_eq!(app.phase, Phase::Linked);
        assert_eq!(app.state.peer_name, "Galaxy S21 Ultra");
    }

    /// FluxMesh robustness slice 2: when the primary link dies but a secondary
    /// is live, `PrimaryFailover` rebinds State onto the survivor while Linked —
    /// which a plain `PeerSeen` cannot do (anti-hijack guard) — and keeps the
    /// existing history (the promoted peer's items are already in it).
    #[test]
    fn primary_failover_rebinds_while_linked_keeping_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Mac".into(),
            },
            &wall(),
        );
        let _ = app.handle(Event::HandshakeOk, &wall());
        assert_eq!(app.phase, Phase::Linked);
        assert_eq!(app.state.peer_id, [7; 32]);

        // Populate history (an item the mesh already synced).
        app.handle(
            Event::FrameReceivedClipboard {
                hash: [1; 32],
                kind: Kind::Text,
                payload: b"hi".to_vec(),
                preview: "hi".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        let history_len = app.state.history.len();
        assert!(history_len > 0);

        // A plain PeerSeen for a DIFFERENT peer is rejected while Linked
        // (the anti-hijack guard) — exactly why failover needs its own event.
        assert!(app.is_peer_mismatch([9; 32]));
        let rejected = app.handle(
            Event::PeerSeen {
                peer_id: [9; 32],
                name: "Phone".into(),
            },
            &wall(),
        );
        assert!(rejected.is_empty());
        assert_eq!(app.state.peer_id, [7; 32]);

        // Failover rebinds onto the promoted secondary, stays Linked, keeps history.
        let acts = app.handle(
            Event::PrimaryFailover {
                peer_id: [9; 32],
                name: "Phone".into(),
                platform: "android".into(),
                caps: vec!["core-1".into()],
            },
            &wall(),
        );
        assert!(acts.contains(&Action::EmitState));
        assert_eq!(app.phase, Phase::Linked);
        assert_eq!(app.state.peer_id, [9; 32]);
        assert_eq!(app.state.peer_name, "Phone");
        assert_eq!(app.state.peer_platform, "android");
        assert_eq!(app.state.peer_caps, vec!["core-1".to_string()]);
        assert_eq!(app.state.history.len(), history_len);
    }

    /// DIR-P1-01 AC: the daemon's Hello handler already filtered out unknown
    /// caps via `negotiate_caps` before firing this event, so only
    /// recognized tags ever reach `App` — receiving them updates state and
    /// never tears down the Linked session.
    #[test]
    fn peer_caps_event_updates_state_without_tearing_down_session() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Mac".into(),
            },
            &wall(),
        );
        let _ = app.handle(Event::HandshakeOk, &wall());
        assert_eq!(app.phase, Phase::Linked);

        let acts = app.handle(
            Event::PeerCaps {
                caps: vec!["core-1".to_string()],
            },
            &wall(),
        );
        assert!(acts.contains(&Action::EmitState));
        assert_eq!(
            app.phase,
            Phase::Linked,
            "an unrecognized/negotiated cap must never tear down the session"
        );
        assert_eq!(app.state.peer_caps, vec!["core-1".to_string()]);
    }

    #[test]
    fn fs043_zero_peer_id_is_a_mismatch_while_handshaking() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        assert_eq!(app.phase, Phase::Handshaking);
        // An all-zero peer_id must NOT be treated as a trusted sentinel.
        assert!(app.is_peer_mismatch([0u8; 32]));
        // A different real peer_id is still a mismatch.
        assert!(app.is_peer_mismatch([9u8; 32]));
        // The actual paired peer is not a mismatch.
        assert!(!app.is_peer_mismatch([7u8; 32]));
    }

    #[test]
    fn battery_drop_below_threshold_pauses_phase_and_status() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        // Now drop peer to below threshold.
        app.handle(
            Event::BatteryChangedPeer {
                level: 10,
                charging: false,
            },
            &wall(),
        );
        assert_eq!(app.state.status, Status::Paused);
        assert_eq!(app.phase, Phase::Paused);
    }

    #[test]
    fn critical_battery_halts_phase_and_status() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 4,
                charging: false,
            },
            &wall(),
        );
        assert_eq!(app.state.status, Status::Critical);
        assert_eq!(app.phase, Phase::Halted);
    }

    #[test]
    fn local_clipboard_change_pushes_history_and_emits_send_item() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        let actions = app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Url,
                payload: "https://github.com".to_string().into_bytes(),
                preview: "https://github.com".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SendItem { hash, .. } if hash == &[1u8; 32])));
        assert_eq!(app.state.history.len(), 1);
        assert_eq!(app.state.history[0].preview, "https://github.com");
        assert_eq!(app.state.history[0].time, "14:32");
    }

    #[test]
    fn fs046_manual_unpair_keeps_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Url,
                payload: "https://github.com".to_string().into_bytes(),
                preview: "https://github.com".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert_eq!(app.state.history.len(), 1);

        app.handle(Event::ManualUnpair, &wall());

        // Unpair disconnects the peer but must not wipe local history (FS-046).
        assert_eq!(app.state.history.len(), 1);
        assert_eq!(app.state.history[0].preview, "https://github.com");
        assert!(!app.state.on);
        assert_eq!(app.state.peer_id, [0u8; 32]);
        assert_eq!(app.state.trusted_peer_name, None);
    }

    #[test]
    fn fs046_repair_with_a_different_peer_clears_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Phone A".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Text,
                payload: "MY_PASSWORD".to_string().into_bytes(),
                preview: "MY_PASSWORD".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert_eq!(app.state.history.len(), 1);

        // Unpair keeps the history (FS-046).
        app.handle(Event::ManualUnpair, &wall());
        assert_eq!(app.state.history.len(), 1);

        // Re-pair with a DIFFERENT peer: the old secret must be gone, or it
        // would leak to the new peer on a BurstReplay.
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [0xB; 32],
                name: "Phone B".into(),
            },
            &wall(),
        );
        assert!(
            app.state.history.is_empty(),
            "different-peer re-pair leaked prior history: {:?}",
            app.state.history
        );
    }

    #[test]
    fn fs046_repair_with_the_same_peer_keeps_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Phone A".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::LocalClipboardChange {
                hash: [1; 32],
                kind: Kind::Url,
                payload: "https://github.com".to_string().into_bytes(),
                preview: "https://github.com".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert_eq!(app.state.history.len(), 1);

        // Reconnect the SAME peer — history stays (FS-046 intent).
        app.handle(Event::ManualUnpair, &wall());
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Phone A".into(),
            },
            &wall(),
        );
        assert_eq!(app.state.history.len(), 1);
        assert_eq!(app.state.history[0].preview, "https://github.com");
    }

    #[test]
    fn sensitive_clipboard_does_not_persist_to_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        app.handle(
            Event::LocalClipboardChange {
                hash: [9; 32],
                kind: Kind::Text,
                payload: "sk_live_aaaaaaaaaaaaaaaaaaaaaaaa".to_string().into_bytes(),
                preview: "sk_live_aaaaaaaaaaaaaaaaaaaaaaaa".into(),
                sensitive: true,
                lamport: 1,
            },
            &wall(),
        );
        assert!(app.state.history.is_empty());
    }

    #[test]
    fn duplicate_local_clipboard_suppresses_send_item() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        // First copy: emit send.
        let a1 = app.handle(
            Event::LocalClipboardChange {
                hash: [3; 32],
                kind: Kind::Text,
                payload: "x".to_string().into_bytes(),
                preview: "x".into(),
                sensitive: false,
                lamport: 1,
            },
            &wall(),
        );
        assert!(a1.iter().any(|a| matches!(a, Action::SendItem { .. })));
        // Same hash again: suppressed.
        let a2 = app.handle(
            Event::LocalClipboardChange {
                hash: [3; 32],
                kind: Kind::Text,
                payload: "x".to_string().into_bytes(),
                preview: "x".into(),
                sensitive: false,
                lamport: 2,
            },
            &wall(),
        );
        assert!(!a2.iter().any(|a| matches!(a, Action::SendItem { .. })));
    }

    #[test]
    fn frame_received_writes_clipboard_and_pushes_history() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        let actions = app.handle(
            Event::FrameReceivedClipboard {
                hash: [4; 32],
                kind: Kind::Text,
                payload: "Bonjour".to_string().into_bytes(),
                preview: "Bonjour".into(),
                lamport: 5,
                sensitive: false,
            },
            &wall(),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::AckItem { hash } if hash == &[4u8; 32])));
        assert_eq!(app.state.history[0].preview, "Bonjour");
    }

    #[test]
    fn fs045_old_lamport_retransmit_is_still_accepted() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        // A first frame advances our Lamport clock far ahead.
        app.handle(
            Event::FrameReceivedClipboard {
                hash: [1; 32],
                kind: Kind::Text,
                payload: "recent".to_string().into_bytes(),
                preview: "recent".into(),
                lamport: 500,
                sensitive: false,
            },
            &wall(),
        );
        // A legitimate retransmit carrying an old Lamport stamp (peer
        // restarted and re-sent earlier history). It must still be
        // accepted — Noise nonces and content-hash dedup cover replay.
        let actions = app.handle(
            Event::FrameReceivedClipboard {
                hash: [2; 32],
                kind: Kind::Text,
                payload: "old retransmit".to_string().into_bytes(),
                preview: "old retransmit".into(),
                lamport: 3,
                sensitive: false,
            },
            &wall(),
        );
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })));
        assert!(app
            .state
            .history
            .iter()
            .any(|h| h.preview == "old retransmit"));
    }

    #[test]
    fn history_capped_at_soft_cap() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        // Push 60 distinct items.
        for i in 0..60u8 {
            app.handle(
                Event::FrameReceivedClipboard {
                    hash: [i; 32],
                    kind: Kind::Text,
                    payload: format!("item-{i}").into_bytes(),
                    preview: format!("item-{i}"),
                    lamport: u64::from(i),
                    sensitive: false,
                },
                &wall(),
            );
        }
        assert_eq!(app.state.history.len(), HISTORY_SOFT_CAP);
        // Most-recent at index 0.
        assert_eq!(app.state.history[0].preview, "item-59");
    }

    #[test]
    fn toggle_off_clears_phase_and_emits_state() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        let actions = app.handle(Event::ToggleOff, &wall());
        assert!(!app.state.on);
        assert_eq!(app.phase, Phase::Idle);
        assert_eq!(app.state.status, Status::Inactive);
        assert!(actions.iter().any(|a| matches!(a, Action::EmitState)));
    }

    #[test]
    fn handshake_timeout_emits_warn_log_and_falls_back() {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        let actions = app.handle(Event::HandshakeTimeout, &wall());
        assert_eq!(app.phase, Phase::Discovering);
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::EmitLog(LogEntry {
                level: LogLevel::Warn,
                ..
            })
        )));
    }

    #[test]
    fn log_helper_constructs_emit_log_action() {
        let a = App::log(LogEntry::ok("hello"));
        assert_eq!(
            a,
            Action::EmitLog(LogEntry {
                level: LogLevel::Ok,
                msg: "hello".into()
            })
        );
    }

    // ── Clipboard firewall gate (chantier A, slice 2) ───────────────────
    use crate::policy::{FirewallPolicy, Rule};

    /// Drive a fresh app to Linked with both batteries healthy.
    fn linked() -> App {
        let mut app = boot();
        app.handle(Event::ToggleOn, &wall());
        app.handle(
            Event::PeerSeen {
                peer_id: [7; 32],
                name: "Galaxy".into(),
            },
            &wall(),
        );
        app.handle(Event::HandshakeOk, &wall());
        app.handle(
            Event::BatteryChangedPeer {
                level: 80,
                charging: false,
            },
            &wall(),
        );
        app
    }

    fn local_text(hash: u8) -> Event {
        Event::LocalClipboardChange {
            hash: [hash; 32],
            kind: Kind::Text,
            payload: b"hello".to_vec(),
            preview: "hello".into(),
            sensitive: false,
            lamport: 1,
        }
    }

    /// Enabled firewall with a given text rule; all other kinds Allow,
    /// sensitive at the default Ask.
    fn fw_text(text: Rule) -> FirewallPolicy {
        FirewallPolicy {
            enabled: true,
            text,
            ..FirewallPolicy::default()
        }
    }

    #[test]
    fn firewall_disabled_passes_outbound_send() {
        let mut app = linked();
        // Default policy is disabled — SendItem survives, as before.
        let acts = app.handle(local_text(1), &wall());
        assert!(acts.iter().any(|a| matches!(a, Action::SendItem { .. })));
    }

    #[test]
    fn firewall_deny_outbound_strips_send_item() {
        let mut app = linked();
        app.set_firewall(fw_text(Rule::Deny));
        let acts = app.handle(local_text(2), &wall());
        assert!(
            !acts.iter().any(|a| matches!(a, Action::SendItem { .. })),
            "Never-text must block the broadcast: {acts:?}"
        );
    }

    #[test]
    fn firewall_ask_outbound_parks_item_then_send_on_approve() {
        let mut app = linked();
        app.set_firewall(fw_text(Rule::Ask));
        // Ask holds the send and parks the item instead of emitting SendItem.
        let acts = app.handle(local_text(3), &wall());
        assert!(!acts.iter().any(|a| matches!(a, Action::SendItem { .. })));
        assert_eq!(app.snapshot().pending.len(), 1);
        let key = app.snapshot().pending[0].hash.clone();
        assert_eq!(app.snapshot().pending[0].direction, Direction::Outbound);

        // Approve → the held SendItem fires and the parking lot empties.
        let resolved = app.handle(
            Event::ResolvePending {
                hash: key,
                allow: true,
            },
            &wall(),
        );
        assert!(resolved
            .iter()
            .any(|a| matches!(a, Action::SendItem { hash, .. } if hash == &[3u8; 32])));
        assert!(app.snapshot().pending.is_empty());
    }

    #[test]
    fn firewall_ask_outbound_deny_drops_item_without_send() {
        let mut app = linked();
        app.set_firewall(fw_text(Rule::Ask));
        app.handle(local_text(3), &wall());
        let key = app.snapshot().pending[0].hash.clone();
        let resolved = app.handle(
            Event::ResolvePending {
                hash: key,
                allow: false,
            },
            &wall(),
        );
        assert!(!resolved.iter().any(|a| matches!(a, Action::SendItem { .. })));
        assert!(app.snapshot().pending.is_empty());
    }

    #[test]
    fn firewall_ask_inbound_parks_then_writes_on_approve() {
        let mut app = linked();
        app.set_firewall(fw_text(Rule::Ask));
        let acts = app.handle(
            Event::FrameReceivedClipboard {
                hash: [8; 32],
                kind: Kind::Text,
                payload: b"from peer".to_vec(),
                preview: "from peer".into(),
                sensitive: false,
                lamport: 9,
            },
            &wall(),
        );
        // Held: no write, but the ack still fires so the peer stops resending.
        assert!(!acts.iter().any(|a| matches!(a, Action::WriteClipboard { .. })));
        assert!(acts
            .iter()
            .any(|a| matches!(a, Action::AckItem { hash } if hash == &[8u8; 32])));
        assert_eq!(app.snapshot().pending.len(), 1);
        assert_eq!(app.snapshot().pending[0].direction, Direction::Inbound);

        let key = app.snapshot().pending[0].hash.clone();
        let resolved = app.handle(
            Event::ResolvePending {
                hash: key,
                allow: true,
            },
            &wall(),
        );
        assert!(resolved
            .iter()
            .any(|a| matches!(a, Action::WriteClipboard { .. })));
        assert!(app.snapshot().pending.is_empty());
    }

    #[test]
    fn resolve_unknown_hash_is_a_noop() {
        let mut app = linked();
        let acts = app.handle(
            Event::ResolvePending {
                hash: "deadbeef".into(),
                allow: true,
            },
            &wall(),
        );
        assert!(acts.iter().all(|a| matches!(a, Action::EmitState)));
        assert!(app.snapshot().pending.is_empty());
    }

    #[test]
    fn firewall_ask_dedupes_reparked_same_hash() {
        let mut app = linked();
        app.set_firewall(fw_text(Rule::Ask));
        app.handle(local_text(3), &wall());
        // A retransmit of the same content must not stack a second pending row.
        // (The dedup ring suppresses it anyway, but parking is idempotent too.)
        app.handle(local_text(3), &wall());
        assert_eq!(app.snapshot().pending.len(), 1);
    }

    #[test]
    fn firewall_sensitive_ask_blocks_secret_even_when_kind_allows() {
        let mut app = linked();
        app.set_firewall(fw_text(Rule::Allow)); // text Allow, sensitive Ask (default)
        let acts = app.handle(
            Event::LocalClipboardChange {
                hash: [4; 32],
                kind: Kind::Text,
                payload: concat!("sk_live_", "xxxxxxxxxxxxxxxxxxxxxxxx").as_bytes().to_vec(),
                preview: concat!("sk_live_", "xxxxxxxxxxxxxxxxxxxxxxxx").into(),
                sensitive: true,
                lamport: 1,
            },
            &wall(),
        );
        assert!(!acts.iter().any(|a| matches!(a, Action::SendItem { .. })));
    }

    #[test]
    fn firewall_deny_inbound_strips_write_but_keeps_ack() {
        let mut app = linked();
        app.set_firewall(fw_text(Rule::Deny));
        let acts = app.handle(
            Event::FrameReceivedClipboard {
                hash: [5; 32],
                kind: Kind::Text,
                payload: b"from peer".to_vec(),
                preview: "from peer".into(),
                sensitive: false,
                lamport: 9,
            },
            &wall(),
        );
        assert!(
            !acts.iter().any(|a| matches!(a, Action::WriteClipboard { .. })),
            "Never-text must not write the OS clipboard"
        );
        assert!(
            acts.iter()
                .any(|a| matches!(a, Action::AckItem { hash } if hash == &[5u8; 32])),
            "ack must still fire so the peer stops retransmitting: {acts:?}"
        );
    }

    #[test]
    fn firewall_allow_inbound_still_writes() {
        let mut app = linked();
        app.set_firewall(fw_text(Rule::Allow));
        let acts = app.handle(
            Event::FrameReceivedClipboard {
                hash: [6; 32],
                kind: Kind::Text,
                payload: b"from peer".to_vec(),
                preview: "from peer".into(),
                sensitive: false,
                lamport: 9,
            },
            &wall(),
        );
        assert!(acts.iter().any(|a| matches!(a, Action::WriteClipboard { .. })));
    }

    // ── FluxMesh coordinator (Phase 1) ──────────────────────────────────
    use crate::id::{DeviceId, EventId};

    fn dev(b: u8) -> DeviceId {
        DeviceId::from([b; 32])
    }

    /// Drive one peer's link Idle → Discovering → Handshaking → Linked via the
    /// pure per-peer FSM.
    fn link_to_linked(app: &mut App, peer: DeviceId) {
        app.handle_peer(peer, &Event::ToggleOn);
        app.handle_peer(
            peer,
            &Event::PeerSeen {
                peer_id: peer.into_bytes(),
                name: "p".into(),
            },
        );
        app.handle_peer(peer, &Event::HandshakeOk);
    }

    #[test]
    fn per_peer_phase_is_independent() {
        let mut app = App::new_with_device(Config::default(), dev(0x5));
        let a = dev(1);
        let b = dev(2);
        app.handle_peer(a, &Event::ToggleOn); // a → Discovering
        link_to_linked(&mut app, b); // b → Linked
        assert_eq!(app.link_phase(a), Some(Phase::Discovering));
        assert_eq!(app.link_phase(b), Some(Phase::Linked));
        assert_eq!(app.link_phase(dev(9)), None);
        assert_eq!(app.linked_peers(), vec![b]);
    }

    #[test]
    fn local_event_id_is_self_origin_and_monotonic() {
        let mut app = App::new_with_device(Config::default(), dev(7));
        let e0 = app.next_local_event_id();
        let e1 = app.next_local_event_id();
        assert_eq!(e0.origin, dev(7));
        assert_eq!(e0.seq, 0);
        assert_eq!(e1.seq, 1);
    }

    #[test]
    fn broadcast_local_fans_out_to_linked_only() {
        let mut app = App::new_with_device(Config::default(), dev(7));
        let (a, b, c) = (dev(1), dev(2), dev(3));
        link_to_linked(&mut app, a);
        link_to_linked(&mut app, b);
        app.handle_peer(c, &Event::ToggleOn); // c stays Discovering

        let (id, targets) = app.broadcast_local([1; 32], Kind::Text, b"hi", false);
        assert_eq!(id.origin, app.self_device());
        let dests: Vec<_> = targets.iter().map(|(d, _)| *d).collect();
        assert_eq!(dests, vec![a, b], "only Linked peers, sorted");
        assert!(!dests.contains(&c));
        assert!(targets
            .iter()
            .all(|(_, act)| matches!(act, Action::SendItem { hash, .. } if hash == &[1u8; 32])));
    }

    #[test]
    fn ingest_remote_applies_once_then_drops_replay() {
        let mut app = App::new_with_device(Config::default(), dev(7));
        let src = dev(1);
        let eid = EventId::new(dev(1), 5);
        assert_eq!(
            app.ingest_remote(src, eid),
            Ingest::Apply { forward_to: vec![] }
        );
        assert_eq!(app.ingest_remote(src, eid), Ingest::Dropped);
    }

    #[test]
    fn ingest_remote_forwards_to_others_not_source_or_origin() {
        let mut app = App::new_with_device(Config::default(), dev(9));
        let (a, b, c) = (dev(1), dev(2), dev(3));
        link_to_linked(&mut app, a);
        link_to_linked(&mut app, b);
        link_to_linked(&mut app, c);
        // item originated at `a` and arrives on link `a`.
        match app.ingest_remote(a, EventId::new(a, 1)) {
            Ingest::Apply { forward_to } => {
                assert_eq!(forward_to, vec![b, c], "exclude source/origin a");
            }
            Ingest::Dropped => panic!("first sight must apply"),
        }
    }

    /// Line topology A—B—C: an item from A reaches C exactly once and never
    /// loops back. Three independent `App` nodes wired by hand.
    #[test]
    fn three_node_relay_arrives_once_and_never_loops() {
        let mut a = App::new_with_device(Config::default(), dev(1));
        let mut b = App::new_with_device(Config::default(), dev(2));
        let mut c = App::new_with_device(Config::default(), dev(3));
        let (a_id, b_id, c_id) = (dev(1), dev(2), dev(3));
        link_to_linked(&mut a, b_id); // A ↔ B
        link_to_linked(&mut b, a_id);
        link_to_linked(&mut b, c_id); // B ↔ C
        link_to_linked(&mut c, b_id);

        // A originates → only neighbour is B.
        let (eid, t) = a.broadcast_local([0xAB; 32], Kind::Text, b"x", false);
        assert_eq!(eid.origin, a_id);
        assert_eq!(t.iter().map(|(d, _)| *d).collect::<Vec<_>>(), vec![b_id]);

        // B applies once, forwards to C (not back to A = source & origin).
        assert_eq!(
            b.ingest_remote(a_id, eid),
            Ingest::Apply {
                forward_to: vec![c_id]
            }
        );
        // C applies once, forwards nowhere (only neighbour is B = source).
        assert_eq!(
            c.ingest_remote(b_id, eid),
            Ingest::Apply { forward_to: vec![] }
        );
        // Any echo back is dropped — no loop.
        assert_eq!(b.ingest_remote(c_id, eid), Ingest::Dropped);
        assert_eq!(a.ingest_remote(b_id, eid), Ingest::Dropped);
    }

    /// DIR-P3-01: a valid rename updates both the live config (read by
    /// `Action::OpenSession` for the next `Msg::Hello`) and the state
    /// projection (read by `fluxctl status` / the tray / Android settings).
    #[test]
    fn set_device_name_updates_config_and_state() {
        let mut app = boot();
        assert!(app.set_device_name("  Dethie's MacBook  ").is_ok());
        assert_eq!(app.config().peer_name_self, "Dethie's MacBook");
        assert_eq!(app.snapshot().device_name, "Dethie's MacBook");
    }

    #[test]
    fn set_device_name_rejects_empty_or_whitespace_only() {
        let mut app = boot();
        assert!(matches!(
            app.set_device_name(""),
            Err(CoreError::InvalidDeviceName(_))
        ));
        assert!(matches!(
            app.set_device_name("   "),
            Err(CoreError::InvalidDeviceName(_))
        ));
    }

    #[test]
    fn set_device_name_rejects_over_wire_bound() {
        let mut app = boot();
        let too_long = "x".repeat(fluxsync_proto::MAX_HELLO_NAME + 1);
        assert!(matches!(
            app.set_device_name(&too_long),
            Err(CoreError::InvalidDeviceName(_))
        ));
    }

    #[test]
    fn set_device_name_rejects_control_characters() {
        let mut app = boot();
        assert!(matches!(
            app.set_device_name("bad\nname"),
            Err(CoreError::InvalidDeviceName(_))
        ));
    }

    #[test]
    fn set_device_name_rejects_do_not_mutate_prior_state() {
        let mut app = boot();
        assert!(app.set_device_name("Good Name").is_ok());
        assert!(app.set_device_name("").is_err());
        // A rejected rename must not clobber the last-accepted name.
        assert_eq!(app.config().peer_name_self, "Good Name");
        assert_eq!(app.snapshot().device_name, "Good Name");
    }
}
