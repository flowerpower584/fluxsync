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
    Hello, Kind, Msg, Nak, PeerInfo,
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

/// Capability tags this build understands. `Hello.caps` negotiation takes
/// the intersection of the peer's caps with this list — see
/// [`negotiate_caps`]; everything else is ignored (docs/PROTOCOL.md). Ships
/// with a single baseline entry so the negotiation machinery has something
/// real to exercise end-to-end before any optional feature needs its own
/// flag.
pub const SUPPORTED_CAPS: &[&str] = &["core-1"];

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
    use super::negotiate_caps;

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
}
