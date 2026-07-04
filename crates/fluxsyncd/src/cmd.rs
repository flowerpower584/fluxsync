//! IPC command + response wire shapes (NDJSON over UNIX socket /
//! Named Pipe). One JSON object per line. See `docs/PROTOCOL.md` §5.

use fluxsync_core::{FirewallPolicy, HistoryItem, LogEntry, State};
use serde::{Deserialize, Serialize};

/// Default entry count for a `tail` request that omits `n`. Mirrors the
/// `fluxctl tail` CLI default so a bare IPC `{"op":"tail"}` behaves the same.
pub const DEFAULT_TAIL_N: usize = 20;

fn default_tail_n() -> usize {
    DEFAULT_TAIL_N
}

/// Opening line on every IPC connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct Subscribe {
    pub subscribe: Channel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Cmd,
    State,
    Logs,
}

/// Request envelope on the `cmd` channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdRequest {
    pub id: u64,
    #[serde(flatten)]
    pub op: CmdOp,
}

/// Every CLI verb. The `op` field selects the variant via serde tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CmdOp {
    Status,
    Peers,
    Push {
        text: String,
    },
    /// Inject an image clipboard item. `data` is the base64 of the raw
    /// PNG bytes — NDJSON is line-based, so binary payloads ride as
    /// base64. Fired by the Android FFI `push_item("image", …)` and
    /// `fluxctl push-image`.
    /// DIR-P2-05: `sensitive` mirrors the text `Push` path's classifier
    /// output — there is no image-content classifier, so the caller
    /// (fluxctl's `--sensitive`, or the mobile FFI) decides instead.
    /// `#[serde(default)]` keeps an older fluxctl/FFI caller (pre-DIR-P2-05,
    /// omitting the field entirely) decodable against a newer daemon: it
    /// simply defaults to `false`, the prior hardcoded behavior.
    PushImage {
        data: String,
        #[serde(default)]
        sensitive: bool,
    },
    /// Fetch a clipboard item's raw bytes by its hex content hash. Used
    /// by the Android client to pull an inbound image's PNG on demand —
    /// the state JSON only carries the hash + a label, never the bytes.
    FetchItem {
        hash: String,
    },
    Pull,
    Tail {
        #[serde(default = "default_tail_n")]
        n: usize,
    },
    SetThreshold {
        value: u8,
    },
    /// DIR-P3-01: rename this device. Validated + persisted by the daemon
    /// (see `App::set_device_name` + `keystore::save_device_name`); an
    /// already-linked peer sees the new name on the next session
    /// establishment (`Msg::Hello`), not immediately — no disruptive
    /// reconnect is forced just for this.
    SetDeviceName {
        name: String,
    },
    SetChargeOverride {
        value: bool,
    },
    /// FluxVault: pin/unpin a history item (by hex content hash) as a
    /// favorite, exempting it from the vault's TTL + disk cap.
    SetFavorite {
        hash: String,
        favorite: bool,
    },
    /// "Clear clipboard history": local-only, never propagated to the peer.
    /// Favorited items survive unless `include_favorites` is set. `#[serde(default)]`
    /// so an older client that omits the field defaults to the safer choice —
    /// favorites kept.
    ClearHistory {
        #[serde(default)]
        include_favorites: bool,
    },
    /// Clipboard firewall (chantier A): replace the whole policy. The client
    /// sends the full `FirewallPolicy` object; the daemon swaps it in and
    /// re-emits state so every subscriber sees the new rules.
    SetFirewall {
        policy: FirewallPolicy,
    },
    /// Clipboard firewall (chantier A): approve (`allow=true`) or reject an
    /// item the `Ask` rule parked in `State.pending`, keyed by its hex content
    /// `hash`. Approval finally sends/writes it; rejection drops it.
    ResolvePending {
        hash: String,
        allow: bool,
    },
    Revoke {
        peer_id: String,
    },
    /// Manually unpair from the current active peer and reset state.
    Unpair {},
    DebugCapture {},
    Shutdown {},
    /// Force a reconnection by dropping the current session and starting discovery.
    Reconnect {},
    /// Wake/sleep the FSM. `on=true` fires `Event::ToggleOn`, sending
    /// the daemon from `Idle` into `Discovering`. `on=false` returns
    /// to `Idle`.
    Toggle {
        on: bool,
    },
    /// Print this device's pair info (peer-id, base32 static pubkey,
    /// 6-word fingerprint, LAN address hint, and the QR-encodable
    /// `fluxsync://pair/...` URI).
    PairShow {},
    /// Trust the given remote pubkey + start the initiator handshake.
    /// `addr` is required when mDNS is unavailable (pre-discovery).
    PairAccept {
        pubkey_b32: String,
        name: String,
        addr: Option<String>,
    },
    /// Parse a `fluxsync://pair/...` URI and trust the embedded peer.
    /// Equivalent to a `PairAccept` with values pulled from the URI.
    /// `name` is supplied separately because the URI deliberately
    /// excludes it (one less field to URL-encode + the receiving user
    /// usually wants to nickname the peer at scan time).
    PairFromUri {
        uri: String,
        name: String,
    },
    /// PR2: trust + handshake using a 6-digit PIN advertised over mDNS
    /// by the peer's `PairShow`. The daemon looks up the live discovery
    /// cache for an entry whose `pair_pin` TXT matches and proceeds like
    /// `PairFromUri`. Verify-words (`pair_pending` + `pair_confirm`) is
    /// mandatory after a PIN-method pair — the UI gates it.
    PairFromPin {
        pin: String,
        name: String,
    },
    /// Push the host OS battery percentage + charging flag into the
    /// daemon. Fired by the Android `MainActivity` whenever the system
    /// `ACTION_BATTERY_CHANGED` broadcast arrives. Without this, the
    /// daemon reports a hardcoded 100% and the peer device sees stale
    /// battery info — which the FSM also feeds into the
    /// pause-on-low-battery policy.
    SetSelfBattery {
        level: u8,
        charging: bool,
    },
    SetLaunchAtLogin {
        value: bool,
    },
    /// FS-052: list peers that were auto-trusted under the TOFU window
    /// but have not yet been verbally confirmed by the user. Each entry
    /// carries the 6-word session-binding SAS so the user can match it
    /// against what the other end displays.
    PairPending {},
    /// FS-052: confirm or reject a pending pair. `accept = true` keeps
    /// the peer in the trusted set; `accept = false` revokes it (drops
    /// the live session and removes the entry from `peers.json`).
    PairConfirm {
        peer_id: String,
        accept: bool,
    },
    /// H2: list every entry in the trust store (peers.json), not just
    /// the one peer that is currently linked. The existing `Peers`
    /// op only reports the active session — a silent compromise that
    /// adds a trusted peer via `pair from-uri` was invisible until
    /// someone `cat`-ed `peers.json` by hand.
    TrustList {},
}

/// Response envelope on the `cmd` channel. `id` echoes the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdResponse {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<CmdData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

/// Tagged response payloads. Each variant matches the request that
/// produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CmdData {
    State(Box<State>),
    Peers(Vec<PeerEntry>),
    Tail(Vec<LogEntry>),
    Pull(Option<HistoryItem>),
    PairInfo {
        peer_id_hex: String,
        pubkey_b32: String,
        fingerprint_words: Vec<String>,
        /// Best-guess LAN socket address (`<ip>:<port>`) the daemon is
        /// reachable at. Falls back to `0.0.0.0:<port>` if no route is
        /// available — callers should treat that as "unknown" and ask
        /// the user for the IP.
        addr_hint: String,
        /// Self-contained URI suitable for QR encoding. Format:
        /// `fluxsync://pair/<pubkey_b32>?a=<ip:port>&f=<w1.w2.w3.w4.w5.w6>`
        uri: String,
        /// PR2: 6-digit pairing PIN advertised on mDNS for the duration
        /// of the pairing window. `None` while the daemon does not have
        /// an open pair window (i.e. nothing to pair against).
        #[serde(skip_serializing_if = "Option::is_none")]
        pin: Option<String>,
        /// PR2: unix-epoch ms when the current `pin` expires. UI uses
        /// this to render a countdown and trigger a fresh `pair_show`
        /// when the PIN rotates.
        #[serde(skip_serializing_if = "Option::is_none")]
        pin_expires_at_ms: Option<u64>,
        /// Tailnet (Tailscale, `100.64.0.0/10`) socket address, when a
        /// tailnet interface is present. `None` on machines without
        /// Tailscale. Informational only — it is already folded into `uri`
        /// (`a=lan,tailnet`), so a single QR works on the LAN and across a
        /// tailnet. Detected via a dependency-free routing probe, no
        /// Tailscale SDK. Surfaced so the UI can show "also reachable at …".
        #[serde(skip_serializing_if = "Option::is_none")]
        tailnet_addr_hint: Option<String>,
    },
    /// Raw bytes of a fetched clipboard item, base64-encoded. Reply to a
    /// `FetchItem` request.
    ItemBytes {
        bytes: String,
    },
    /// FS-052: pending-pair listing.
    PendingPairs(Vec<PendingPairEntry>),
    /// H2: every persisted trusted peer.
    TrustList(Vec<TrustedEntry>),
    Pong,
}

/// H2: one entry in the trust store (`peers.json`). Mirrors
/// `keystore::StoredPeer` but exposed on the IPC surface so the CLI
/// can render it without re-reading the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedEntry {
    pub peer_id_hex: String,
    pub static_pub_hex: String,
    pub name: String,
}

/// FS-052: one unconfirmed TOFU pair waiting on user verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPairEntry {
    /// Hex of the peer's `BLAKE3(static_pub)`.
    pub peer_id: String,
    /// Best-known name (typically the `New Peer` placeholder until the
    /// `Msg::Hello` lands the real device name).
    pub name: String,
    /// 6 verbal SAS words derived from the Noise handshake hash `h`.
    /// Identical on both peers; differs across handshakes (fresh
    /// ephemerals) and across MITM attempts.
    pub sas_words: Vec<String>,
    /// Last-seen UDP source for this pair. `None` if the entry was
    /// reloaded from disk and the live address is not yet known.
    pub addr: Option<String>,
    /// Milliseconds remaining until the daemon-side pending entry
    /// expires. `None` if the entry has no expiry (e.g. a peer that
    /// already landed in the trusted set but never got a user confirm).
    pub expires_in_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub peer_id: String, // hex of the 32-byte BLAKE3(static_pub)
    pub name: String,
    pub addr: String,
    pub link_latency_ms: u32,
    pub battery: u8,
    pub charging: bool,
    pub linked: bool,
}

impl CmdResponse {
    #[must_use]
    pub fn ok(id: u64, data: Option<CmdData>) -> Self {
        Self {
            id,
            ok: true,
            data,
            err: None,
        }
    }
    #[must_use]
    pub fn err(id: u64, msg: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            data: None,
            err: Some(msg.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CmdOp, CmdRequest, DEFAULT_TAIL_N};

    /// FS-027: a `tail` request that omits `n` must deserialize with the
    /// default count instead of failing — a bare `{"op":"tail"}` from a
    /// third-party IPC client should not be a hard error.
    #[test]
    fn fs027_tail_op_defaults_n_when_omitted() {
        let op: CmdOp =
            serde_json::from_str(r#"{"op":"tail"}"#).expect("tail without n must deserialize");
        match op {
            CmdOp::Tail { n } => assert_eq!(n, DEFAULT_TAIL_N),
            other => panic!("expected Tail, got {other:?}"),
        }

        let op: CmdOp = serde_json::from_str(r#"{"op":"tail","n":5}"#)
            .expect("explicit n must still deserialize");
        assert!(matches!(op, CmdOp::Tail { n: 5 }), "explicit n must win");
    }

    /// DIR-P2-05: an old-format `push_image` request (no `sensitive` field
    /// at all — how every pre-DIR-P2-05 fluxctl/mobile-FFI caller shapes
    /// it) must still decode, defaulting to non-sensitive rather than
    /// failing. This is the "old client -> new daemon" IPC compat
    /// direction: the extra `#[serde(default)]` on `PushImage::sensitive`
    /// is exactly what makes this a clean decode instead of a hard error.
    #[test]
    fn dir_p2_05_push_image_old_format_defaults_sensitive_false() {
        let op: CmdOp = serde_json::from_str(r#"{"op":"push_image","data":"AAAA"}"#)
            .expect("push_image without sensitive must still deserialize");
        match op {
            CmdOp::PushImage { data, sensitive } => {
                assert_eq!(data, "AAAA");
                assert!(!sensitive, "omitted sensitive must default to false");
            }
            other => panic!("expected PushImage, got {other:?}"),
        }
    }

    /// A `clear_history` request that omits `include_favorites` (an older
    /// fluxctl/tray/mobile client, or a bare hand-typed IPC line) must still
    /// deserialize, defaulting to keeping favorites rather than failing.
    #[test]
    fn clear_history_old_format_defaults_include_favorites_false() {
        let op: CmdOp = serde_json::from_str(r#"{"op":"clear_history"}"#)
            .expect("clear_history without include_favorites must still deserialize");
        match op {
            CmdOp::ClearHistory { include_favorites } => {
                assert!(!include_favorites, "omitted field must default to false");
            }
            other => panic!("expected ClearHistory, got {other:?}"),
        }
    }

    /// `clear_history` round-trips `include_favorites` both ways.
    #[test]
    fn clear_history_include_favorites_roundtrips() {
        for want in [true, false] {
            let json = serde_json::json!({
                "op": "clear_history",
                "include_favorites": want,
            });
            let op: CmdOp = serde_json::from_value(json.clone())
                .unwrap_or_else(|e| panic!("deserialize {json}: {e}"));
            match op {
                CmdOp::ClearHistory { include_favorites } => assert_eq!(include_favorites, want),
                other => panic!("expected ClearHistory, got {other:?}"),
            }
        }
    }

    /// DIR-P2-05: a `push_image` request that carries the `sensitive`
    /// flag round-trips both `true` and `false` through the same
    /// serde-tagged shape `fluxctl`/the mobile FFI actually send.
    #[test]
    fn dir_p2_05_push_image_sensitive_flag_roundtrips() {
        for want in [true, false] {
            let json = serde_json::json!({
                "op": "push_image",
                "data": "AAAA",
                "sensitive": want,
            });
            let op: CmdOp = serde_json::from_value(json.clone())
                .unwrap_or_else(|e| panic!("deserialize {json}: {e}"));
            match op {
                CmdOp::PushImage { sensitive, .. } => assert_eq!(sensitive, want),
                other => panic!("expected PushImage, got {other:?}"),
            }

            // Round-trip through serialize too — a `fluxctl`/daemon pair on
            // the same version must agree on the wire shape either way.
            let req = CmdRequest {
                id: 1,
                op: CmdOp::PushImage { data: "AAAA".into(), sensitive: want },
            };
            let s = serde_json::to_string(&req).expect("serialize");
            let back: CmdRequest = serde_json::from_str(&s).expect("deserialize own output");
            match back.op {
                CmdOp::PushImage { sensitive, .. } => assert_eq!(sensitive, want),
                other => panic!("expected PushImage, got {other:?}"),
            }
        }
    }
}
