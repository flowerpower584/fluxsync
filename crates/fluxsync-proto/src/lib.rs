//! FluxSync wire types + CBOR codec.
//!
//! Every byte that crosses the LAN is a [`Frame`] encoded with `ciborium` and
//! sealed inside a Noise IK ChaCha20-Poly1305 ciphertext. This crate is
//! deliberately small and depends on nothing else in the workspace so it can
//! be exercised in property tests without dragging in a runtime.
//!
//! See `docs/PROTOCOL.md` for the full wire-format specification.

mod codec;
mod error;
mod types;

pub use codec::{decode, encode};
pub use error::ProtoError;
pub use types::{
    Ack, BatteryStatus, Chunk, ClipboardItem, Frame, HandshakeInit, HandshakeResp, Heartbeat,
    Hello, Kind, Msg, Nak, PairConfirm, PeerInfo, ResyncOffer, ResyncPull,
};

/// Wire-format version. Bumped on any breaking change to the CBOR shapes.
///
/// 0x02 (FluxMesh): `ClipboardItem` gained `origin` + `event_seq`. The
/// codec rejects any other version on both encode and decode, so a v2
/// daemon does not interoperate with v1 — all devices must run v2.
pub const PROTOCOL_VERSION: u8 = 0x02;

/// Largest reassembled clipboard payload we accept (16 MiB) — sized for
/// Retina / S21-Ultra PNG screenshots, which run 8-12 MiB.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Largest data section inside a single [`Chunk`] frame (1 KiB). Held at 1 KiB
/// so the final datagram (CBOR + Noise overhead ≈ 1.1-1.2 KiB) stays under the
/// 1500 B Wi-Fi MTU — one lost IP fragment would kill the whole UDP datagram.
pub const MAX_CHUNK_DATA: usize = 1024;

/// Hard cap on chunk-count per item — bounds reassembly buffer and refuses
/// trivial DoS allocations from a malicious peer. 16384 × 1 KiB = 16 MiB,
/// matching [`MAX_PAYLOAD`] (u16 ceiling ≈ 64 MiB).
pub const MAX_CHUNKS: u16 = 16384;

/// Hard cap on the `missing` list inside a [`Nak`]. A receiver caps its own
/// list well below this (≈400) so the encoded Nak stays inside one datagram;
/// the decoder enforces this larger ceiling purely as a DoS guard against a
/// malicious peer claiming a giant missing set.
pub const MAX_NAK_MISSING: usize = 512;

/// Hard cap on `Hello.name` (M-PROTO-01). The post-handshake greeting carries
/// the peer's self-reported device name straight into the tray / Android UI;
/// without a bound a hostile peer could ship a ~datagram-sized name. 256 bytes
/// is far above any real device name.
pub const MAX_HELLO_NAME: usize = 256;

/// Hard cap on `Hello.platform`. Legitimate values come from a closed set
/// (`macos`/`windows`/`linux`/`android`/`ios`/`unknown`, longest 7 bytes);
/// the bound only guards against a hostile peer shipping a datagram-sized
/// blob that would be re-broadcast over IPC on every state emit.
pub const MAX_HELLO_PLATFORM: usize = 16;

/// Hard cap on the number of entries in `Hello.caps` (DIR-P1-01). Capability
/// negotiation is meant for a small, closed set of feature tags; the bound
/// guards against a hostile peer shipping a huge list to bloat the decoded
/// `Hello` / mesh peer-metadata map.
pub const MAX_HELLO_CAPS: usize = 32;

/// Hard cap on the byte length of a single `Hello.caps` entry. Real
/// capability tags are short ASCII identifiers (e.g. `"core-1"`); the bound
/// guards against a hostile peer shipping a datagram-sized tag string.
pub const MAX_CAP_LEN: usize = 64;

/// Hard cap on the number of hashes in a `resync-1` `ResyncOffer` /
/// `ResyncPull` message (§6.2). Mirrors [`MAX_HELLO_CAPS`]'s reasoning: a
/// hostile peer shouldn't be able to force a huge CBOR list onto the wire in
/// a message a fully-patched peer would only ever fill with a handful of
/// recently-seen item hashes.
pub const MAX_RESYNC_HASHES: usize = 32;

/// Exact length of a `resync-1` content hash string: hex-encoded
/// BLAKE3-256, two lowercase hex digits per byte. Matches the format
/// `hex32` (in `fluxsync-core`) uses to produce `HistoryItem.hash`.
pub const RESYNC_HASH_LEN: usize = 64;

/// `true` iff `s` is exactly [`RESYNC_HASH_LEN`] ASCII characters, all
/// lowercase hex digits (`0-9`, `a-f`). Uppercase hex, wrong length, or any
/// non-hex byte is rejected — there is exactly one valid textual encoding
/// for a `resync-1` hash.
fn is_valid_resync_hash(s: &str) -> bool {
    s.len() == RESYNC_HASH_LEN && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validate a `resync-1` hash list against the wire bounds: at most
/// [`MAX_RESYNC_HASHES`] entries, each exactly [`RESYNC_HASH_LEN`] lowercase
/// hex characters. This is the same check [`codec::validate`] applies on
/// every `encode`/`decode`; it's exported so a caller (e.g. the daemon) can
/// pre-validate a hash list before building a `ResyncOffer`/`ResyncPull`.
#[must_use]
pub fn validate_resync_hashes(hashes: &[String]) -> bool {
    hashes.len() <= MAX_RESYNC_HASHES && hashes.iter().all(|h| is_valid_resync_hash(h))
}

/// Capability tags this build understands. `Hello.caps` negotiation takes
/// the intersection of the peer's caps with this list — see
/// [`negotiate_caps`]; everything else is ignored (docs/PROTOCOL.md). Ships
/// with `core-1` (baseline), `resync-1` (resync-on-reconnect, §6.2 of
/// `docs/PROTOCOL.md`), and `sas-confirm` (wire-level mutual SAS
/// confirmation via `Msg::PairConfirm`).
pub const SUPPORTED_CAPS: &[&str] = &["core-1", "resync-1", "sas-confirm"];

/// Negotiate the working capability set with a peer: the intersection of
/// what they sent in `Hello.caps` and what this build understands
/// ([`SUPPORTED_CAPS`]). A tag the peer sent that we don't recognize is
/// silently dropped — that is the whole point of capability negotiation:
/// an unknown cap never fails the handshake, it is just not used.
#[must_use]
pub fn negotiate_caps(peer_caps: &[String]) -> Vec<String> {
    peer_caps
        .iter()
        .filter(|c| SUPPORTED_CAPS.contains(&c.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{negotiate_caps, validate_resync_hashes, MAX_RESYNC_HASHES, SUPPORTED_CAPS};

    #[test]
    fn negotiate_caps_keeps_only_known_tags() {
        let peer = vec!["core-1".to_string(), "x-future-test".to_string()];
        assert_eq!(negotiate_caps(&peer), vec!["core-1".to_string()]);
    }

    #[test]
    fn negotiate_caps_empty_peer_list_is_empty() {
        assert!(negotiate_caps(&[]).is_empty());
    }

    #[test]
    fn negotiate_caps_all_unknown_is_empty() {
        let peer = vec!["x-a".to_string(), "x-b".to_string()];
        assert!(negotiate_caps(&peer).is_empty());
    }

    #[test]
    fn supported_caps_includes_resync_1() {
        assert!(SUPPORTED_CAPS.contains(&"resync-1"));
    }

    /// A well-formed 64-char lowercase-hex `resync-1` hash for test fixtures.
    fn valid_hash() -> String {
        "ab".repeat(super::RESYNC_HASH_LEN / 2)
    }

    #[test]
    fn validate_resync_hashes_accepts_empty() {
        assert!(validate_resync_hashes(&[]));
    }

    #[test]
    fn validate_resync_hashes_accepts_at_max_count() {
        let hashes = vec![valid_hash(); MAX_RESYNC_HASHES];
        assert!(validate_resync_hashes(&hashes));
    }

    #[test]
    fn validate_resync_hashes_rejects_over_max_count() {
        let hashes = vec![valid_hash(); MAX_RESYNC_HASHES + 1];
        assert!(!validate_resync_hashes(&hashes));
    }

    #[test]
    fn validate_resync_hashes_rejects_wrong_length() {
        assert!(!validate_resync_hashes(&["ab".to_string()]));
        assert!(!validate_resync_hashes(&[valid_hash() + "0"]));
    }

    #[test]
    fn validate_resync_hashes_rejects_uppercase() {
        assert!(!validate_resync_hashes(&[valid_hash().to_uppercase()]));
    }

    #[test]
    fn validate_resync_hashes_rejects_non_hex() {
        let non_hex = "g".repeat(super::RESYNC_HASH_LEN);
        assert!(!validate_resync_hashes(&[non_hex]));
    }
}
