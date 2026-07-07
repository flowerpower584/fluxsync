use fluxsync_proto::Kind;
use serde::{Deserialize, Serialize};

/// Things the daemon tells the FSM about.
///
/// All non-pure inputs come in here. The FSM's response is a list of
/// [`Action`]s the daemon then executes (send a frame, write the
/// clipboard, emit a log line, push a new state to subscribers, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    ToggleOn,
    ToggleOff,
    PeerSeen {
        peer_id: [u8; 32],
        name: String,
    },
    /// Peer's OS family, carried by `Msg::Hello` (after the handshake). Kept
    /// separate from `PeerSeen` so the discovery/handshake paths — which don't
    /// know the platform — stay untouched.
    PeerPlatform {
        platform: String,
    },
    /// Negotiated capability set from `Msg::Hello.caps` (DIR-P1-01) — the
    /// intersection of the peer's caps with what this build supports.
    /// Unknown caps are already filtered out by the time this event fires.
    PeerCaps {
        caps: Vec<String>,
    },
    /// The peer whose link just died. Threaded so peer-scoped state (e.g.
    /// `State.sas_peer`) only resets when the peer that dropped is the one
    /// it currently names — see the peer-scoping guard in `App::handle`.
    PeerLost {
        peer_id: [u8; 32],
    },
    HandshakeOk,
    HandshakeTimeout,
    SetTrustedPeer {
        name: String,
    },
    UntrustedPeerSeen {
        name: String,
    },
    GhostTimeout,
    ManualUnpair,
    NetworkChanged,
    BatteryChangedSelf {
        level: u8,
        charging: bool,
    },
    BatteryChangedPeer {
        level: u8,
        charging: bool,
    },
    LocalClipboardChange {
        hash: [u8; 32],
        kind: Kind,
        /// Raw clipboard bytes — UTF-8 for text/url/code, PNG for images.
        payload: Vec<u8>,
        /// Human-readable label for the history UI (truncated text, or an
        /// "Image 1280×720, 340 KB" descriptor). Never the wire payload.
        preview: String,
        sensitive: bool,
        lamport: u64,
    },
    FrameReceivedClipboard {
        hash: [u8; 32],
        kind: Kind,
        /// Raw clipboard bytes — UTF-8 for text/url/code, PNG for images.
        payload: Vec<u8>,
        /// Human-readable label for the history UI.
        preview: String,
        sensitive: bool,
        lamport: u64,
        /// resync-1: true when this item arrived because WE sent a
        /// `ResyncPull` for its hash (catching up on a peer's outbox after a
        /// reconnect), as opposed to a live/fresh copy from the peer. A
        /// resync delivery still enters history/vault/relay and is still
        /// acked — it just must never silently overwrite the user's current
        /// OS clipboard on their behalf. See `App::handle`'s post-transition
        /// `Action::WriteClipboard` strip.
        resync: bool,
        /// FIX1 (P0 parked-payload leak): the peer id of the session this
        /// frame arrived on. The driver knows this at every dispatch site —
        /// including the reassembled-chunk path, where it's the direct
        /// sender of this hop, not necessarily the item's mesh `origin`.
        /// Threaded through so a firewall `Ask` park (`apply_firewall`) can
        /// tag the parked item with the peer that sent it, letting a later
        /// `Event::PeerRevoked` drop only that peer's parked items instead of
        /// every pending item in the daemon (see `App::drop_pending_for`).
        peer_id: [u8; 32],
    },
    Reconnect,
    /// FluxMesh Phase 3: a non-primary mesh peer joined, left, or updated its
    /// Hello/Battery. Carries no payload — it only asks the FSM to re-emit
    /// State so the daemon can rebuild the `peers` list from the live session
    /// set. Never mutates the single-peer State fields (those stay the
    /// primary's projection).
    MeshPeersChanged,
    /// FluxMesh robustness: the primary peer's link died while a secondary
    /// mesh session is still live. The daemon has already promoted that
    /// secondary into the primary transport slot; this rebinds the
    /// single-peer State to the promoted peer so the link stays connected
    /// instead of dropping to Discovering. Unlike `PeerSeen`, it is accepted
    /// while Linked — the promoted peer is already authenticated and trusted,
    /// so it deliberately bypasses the anti-hijack `is_peer_mismatch` guard.
    PrimaryFailover {
        peer_id: [u8; 32],
        name: String,
        platform: String,
        caps: Vec<String>,
    },
    /// FluxVault: pin/unpin a history item (by its hex content hash) as a
    /// favorite. Favorites are exempt from the vault's TTL and disk cap, so a
    /// pinned item is never aged or capped out. Mutates only the matching
    /// `HistoryItem.favorite` flag(s) and re-emits State.
    SetFavorite {
        hash: String,
        favorite: bool,
    },
    /// "Clear clipboard history" (owner-requested, local-only — never
    /// propagated to the peer). `include_favorites = false` keeps favorited
    /// items; `true` drops everything. Also bumps `State.vault_wipe_gen` so
    /// the vault persister invalidates its cached favorites and rewrites the
    /// on-disk vault to match, the same mechanism the security wipes use.
    ClearHistory {
        include_favorites: bool,
    },
    /// Clipboard firewall (chantier A): the user approved (`allow=true`) or
    /// rejected (`allow=false`) an item the `Ask` rule had parked. Keyed by the
    /// pending item's hex content `hash`. On approval the FSM re-emits the held
    /// `SendItem`/`WriteClipboard`; either way the entry leaves `State.pending`.
    ResolvePending {
        hash: String,
        allow: bool,
    },
    /// Wire-level mutual SAS confirmation (`sas-confirm` capability): a
    /// fresh TOFU pairing just inserted a `PendingPair` (handshake
    /// completed, nobody has confirmed the 6 SAS words yet). Sets
    /// `State.sas_phase` to `"showing"` unconditionally — a new pairing
    /// always overwrites any leftover phase from a previous attempt.
    /// `peer_id`: the peer this pairing is with — recorded into
    /// `State.sas_peer` (L3 fix) so a later `SasPeerConfirmed`/
    /// `SasPeerRejected` from an unrelated peer can't stomp this one's
    /// verify UI.
    SasPairingStarted { peer_id: [u8; 32] },
    /// The local user confirmed the SAS words (`fluxctl pair confirm
    /// --accept`). Moves `sas_phase` to `"confirmed"` if the peer already
    /// confirmed (or is a legacy build treated as auto-confirmed), else to
    /// `"local_confirmed"`. `peer_id` must match `State.sas_peer` or the
    /// transition is ignored — same peer-scoping as `SasPeerConfirmed`/
    /// `SasPeerRejected` (L3 fix). Without this, confirming pairing with one
    /// peer while a second pairing with a different peer is also in flight
    /// could advance the WRONG peer's phase if `sas_peer` had since been
    /// overwritten by the second pairing's `SasPairingStarted`.
    SasLocalConfirmed { peer_id: [u8; 32] },
    /// The peer confirmed the SAS words — either via an inbound
    /// `Msg::PairConfirm { accept: true }`, or because its `Hello` did not
    /// advertise the `sas-confirm` capability (legacy build, auto-treated
    /// as confirmed so a new build never waits forever on an old one).
    /// Moves `sas_phase` to `"confirmed"` if the local side already
    /// confirmed, else to `"peer_confirmed"`. L3 fix: `peer_id` must match
    /// `State.sas_peer` or the transition is ignored — an unrelated peer's
    /// confirm must not advance a DIFFERENT peer's in-flight SAS phase.
    SasPeerConfirmed { peer_id: [u8; 32] },
    /// The peer explicitly rejected the pairing (inbound
    /// `Msg::PairConfirm { accept: false }`). Sets `sas_phase` to
    /// `"peer_rejected"` unconditionally. L3 fix: `peer_id` must match
    /// `State.sas_peer` or the transition is ignored — see
    /// `SasPeerConfirmed`.
    SasPeerRejected { peer_id: [u8; 32] },
    /// The pending reaper revoked an unconfirmed pair after the 90s
    /// pairing window expired. Resets `sas_phase` to `"idle"`.
    SasReset,
    /// FIX1 (P0 parked-payload leak): `peer_id` was revoked (explicit
    /// `CmdOp::Revoke`, primary or secondary) or timed out (silent-secondary
    /// heartbeat failure). Drops only THIS peer's parked `Ask` items via
    /// `App::drop_pending_for` — unlike `PeerLost` (a transient disconnect,
    /// which must leave pending Asks alone so a wifi blip doesn't destroy a
    /// user's in-flight decision), a revoke/timeout is permanent: nobody is
    /// left to deliver an inbound item to, or to receive an outbound one.
    PeerRevoked {
        peer_id: [u8; 32],
    },
}

/// Side-effect commands the daemon must execute. The FSM never performs
/// I/O; it only describes what should happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    StartDiscovery,
    StopDiscovery,
    SendHandshake {
        peer_id: [u8; 32],
    },
    DropPeer,
    OpenSession,
    CloseSession,
    SendItem {
        hash: [u8; 32],
        kind: Kind,
        /// Raw bytes to put on the wire as the `ClipboardItem` payload.
        payload: Vec<u8>,
        sensitive: bool,
    },
    AckItem {
        hash: [u8; 32],
    },
    WriteClipboard {
        kind: Kind,
        /// Raw bytes to write to the OS clipboard — decoded per `kind`.
        payload: Vec<u8>,
        /// L1 fix: propagates the item's firewall-sensitivity to the daemon
        /// so an Android `WriteClipboard{kind: Image, ..}` handler can skip
        /// the persistent `IMAGE_CACHE` for a sensitive image instead of
        /// silently caching it in RAM past a security wipe. A locally
        /// re-emitted write-back (e.g. `resolve_pending`) carries whatever
        /// sensitivity the parked item had; a fresh local copy is always
        /// `false` here since it never round-trips through `WriteClipboard`.
        sensitive: bool,
    },
    EmitState,
    EmitLog(LogEntry),
    BurstReplay,
    SendBattery {
        level: u8,
        charging: bool,
    },
    /// DIR-P1-09: the content-hash dedup ring suppressed this event (an
    /// echo of our own local copy, or a peer retransmit already applied).
    /// Emitted alongside whatever else `App::handle` returns from a
    /// `suppress_action` branch so the daemon can bump
    /// `ConnectionMetrics::dedup_drops` — the FSM stays pure, this is just
    /// a signal, no I/O.
    DuplicateDropped,
    /// resync-1 apply-suppression fix (DEFECT 1): emitted alongside the rest
    /// of a `FrameReceivedClipboard { resync: true, .. }` transition's
    /// actions, right where `Action::WriteClipboard` was stripped, so the
    /// daemon can bump `ConnectionMetrics::resync_applies_suppressed` — a
    /// test-visible, IPC-observable proof that a resync delivery did NOT
    /// touch the OS clipboard. History insertion, the vault persist it
    /// triggers, mesh relay, and the Ack are unaffected; see `App::handle`.
    ResyncApplySuppressed,
    /// FIX1 (P0 parked-payload leak): `Event::PeerRevoked` dropped these
    /// content hashes from the pending queues via `drop_pending_for`. Signal
    /// only — the FSM never touches I/O — so the daemon can also purge the
    /// matching `PendingOutboxStage` staged entries (see `driver.rs`'s
    /// `purge_dropped_pending_from_outbox_stage`); without this they would
    /// otherwise outlive the `state.pending` row they mirrored.
    PendingDropped { hashes: Vec<[u8; 32]> },
}

/// A friendly log entry. Routed both to `tracing` (structured) and to the
/// IPC `logs` channel (plain English).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub msg: String,
}

/// Five-level log severity. Names match the frontend's filter buttons
/// exactly (`OK`, `INFO`, `SYNC`, `WARN`, `ERR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Ok,
    Info,
    Sync,
    Warn,
    Err,
}

impl LogEntry {
    #[must_use]
    pub fn ok(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Ok,
            msg: msg.into(),
        }
    }
    #[must_use]
    pub fn info(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Info,
            msg: msg.into(),
        }
    }
    #[must_use]
    pub fn sync(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Sync,
            msg: msg.into(),
        }
    }
    #[must_use]
    pub fn warn(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Warn,
            msg: msg.into(),
        }
    }
    #[must_use]
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            level: LogLevel::Err,
            msg: msg.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_serializes_uppercase() {
        let v = serde_json::to_value(LogLevel::Sync).unwrap();
        assert_eq!(v, serde_json::json!("SYNC"));
        let v = serde_json::to_value(LogLevel::Err).unwrap();
        assert_eq!(v, serde_json::json!("ERR"));
    }

    #[test]
    fn log_entry_helpers() {
        assert_eq!(LogEntry::ok("hi").level, LogLevel::Ok);
        assert_eq!(LogEntry::info("hi").level, LogLevel::Info);
        assert_eq!(LogEntry::sync("hi").level, LogLevel::Sync);
        assert_eq!(LogEntry::warn("hi").level, LogLevel::Warn);
        assert_eq!(LogEntry::err("hi").level, LogLevel::Err);
    }
}
