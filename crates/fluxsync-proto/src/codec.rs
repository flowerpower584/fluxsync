use crate::error::ProtoError;
use crate::types::{Chunk, ClipboardItem, Frame, Msg, Nak};
use crate::{
    is_valid_resync_hash, MAX_CAP_LEN, MAX_CHUNKS, MAX_CHUNK_DATA, MAX_HELLO_CAPS, MAX_HELLO_NAME,
    MAX_HELLO_PLATFORM, MAX_NAK_MISSING, MAX_PAYLOAD, MAX_RESYNC_HASHES, PROTOCOL_VERSION,
};

/// Encode a [`Frame`] to CBOR bytes.
///
/// Validates the frame before encoding so we never put a malformed datagram
/// on the wire even by mistake.
///
/// # Errors
/// Returns [`ProtoError::Version`] if `frame.version != PROTOCOL_VERSION`,
/// [`ProtoError::PayloadTooLarge`] / [`ProtoError::ChunkDataTooLarge`] /
/// [`ProtoError::ChunkTotalTooLarge`] / [`ProtoError::ChunkIndexOutOfRange`] /
/// [`ProtoError::BatteryLevel`] when the corresponding field violates its
/// bound, or [`ProtoError::CborEncode`] if the underlying serializer fails.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, ProtoError> {
    if frame.version != PROTOCOL_VERSION {
        return Err(ProtoError::Version {
            got: frame.version,
            expected: PROTOCOL_VERSION,
        });
    }
    validate(frame)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(frame, &mut out)
        .map_err(|e| ProtoError::CborEncode(e.to_string()))?;
    Ok(out)
}

/// Decode CBOR bytes into a [`Frame`], validating the result.
///
/// Anything that fails validation is rejected here so higher layers can trust
/// the resulting [`Frame`] without re-checking field bounds.
///
/// # Errors
/// Returns [`ProtoError::Cbor`] for malformed CBOR, [`ProtoError::Version`]
/// for an unsupported wire version, or one of the field-bound errors when a
/// payload exceeds the v0.1 caps.
pub fn decode(bytes: &[u8]) -> Result<Frame, ProtoError> {
    let frame: Frame =
        ciborium::de::from_reader(bytes).map_err(|e| ProtoError::Cbor(e.to_string()))?;
    if frame.version != PROTOCOL_VERSION {
        return Err(ProtoError::Version {
            got: frame.version,
            expected: PROTOCOL_VERSION,
        });
    }
    validate(&frame)?;
    Ok(frame)
}

fn validate(frame: &Frame) -> Result<(), ProtoError> {
    match &frame.msg {
        Msg::ClipboardItem(item) => validate_item(item),
        Msg::Chunk(chunk) => validate_chunk(chunk),
        Msg::Nak(nak) => validate_nak(nak),
        Msg::BatteryStatus(b) if b.level > 100 => Err(ProtoError::BatteryLevel(b.level)),
        Msg::Hello(h) if h.name.len() > MAX_HELLO_NAME => {
            Err(ProtoError::HelloNameTooLong(h.name.len()))
        }
        Msg::Hello(h) if h.platform.len() > MAX_HELLO_PLATFORM => {
            Err(ProtoError::HelloPlatformTooLong(h.platform.len()))
        }
        Msg::Hello(h) if h.caps.len() > MAX_HELLO_CAPS => {
            Err(ProtoError::HelloCapsTooMany(h.caps.len()))
        }
        Msg::Hello(h) if h.caps.iter().any(|c| c.len() > MAX_CAP_LEN) => Err(
            ProtoError::HelloCapTooLong(h.caps.iter().map(String::len).max().unwrap_or(0)),
        ),
        Msg::Hello(h) if h.caps.iter().any(|c| !is_ascii_printable_cap(c)) => {
            Err(ProtoError::HelloCapNotAsciiPrintable)
        }
        Msg::ResyncOffer(r) => validate_resync_msg(&r.hashes),
        Msg::ResyncPull(r) => validate_resync_msg(&r.hashes),
        _ => Ok(()),
    }
}

/// Shared bound check for `ResyncOffer.hashes` / `ResyncPull.hashes`
/// (resync-1, §6.2): at most `MAX_RESYNC_HASHES` entries, each a
/// well-formed 64-char lowercase-hex hash. Mirrors the `Hello.caps`
/// enforcement above — checked on both `encode` and `decode`. Same rule as
/// [`crate::validate_resync_hashes`], applied inline so `validate` returns
/// the specific [`ProtoError`] variant instead of a bare bool.
fn validate_resync_msg(hashes: &[String]) -> Result<(), ProtoError> {
    if hashes.len() > MAX_RESYNC_HASHES {
        return Err(ProtoError::ResyncTooManyHashes(hashes.len()));
    }
    if hashes.iter().any(|h| !is_valid_resync_hash(h)) {
        return Err(ProtoError::ResyncHashMalformed);
    }
    Ok(())
}

/// ASCII-printable check for a single `Hello.caps` entry: bytes `0x20..=0x7E`
/// (space through `~`). Keeps capability tags renderable/loggable without
/// any charset ambiguity.
fn is_ascii_printable_cap(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

fn validate_nak(nak: &Nak) -> Result<(), ProtoError> {
    if nak.missing.len() > MAX_NAK_MISSING {
        return Err(ProtoError::NakMissingTooLarge(nak.missing.len()));
    }
    Ok(())
}

fn validate_item(item: &ClipboardItem) -> Result<(), ProtoError> {
    if item.payload.len() > MAX_PAYLOAD {
        return Err(ProtoError::PayloadTooLarge(item.payload.len()));
    }
    Ok(())
}

fn validate_chunk(chunk: &Chunk) -> Result<(), ProtoError> {
    if chunk.data.len() > MAX_CHUNK_DATA {
        return Err(ProtoError::ChunkDataTooLarge(chunk.data.len()));
    }
    if chunk.total == 0 {
        return Err(ProtoError::ChunkTotalZero);
    }
    if chunk.total > MAX_CHUNKS {
        return Err(ProtoError::ChunkTotalTooLarge(chunk.total));
    }
    if chunk.idx >= chunk.total {
        return Err(ProtoError::ChunkIndexOutOfRange {
            idx: chunk.idx,
            total: chunk.total,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ack, BatteryStatus, ClipboardItem, Heartbeat, Kind, Nak};

    fn frame(msg: Msg) -> Frame {
        Frame {
            version: PROTOCOL_VERSION,
            msg,
        }
    }

    #[test]
    fn round_trip_bye() {
        let f = frame(Msg::Bye);
        let bytes = encode(&f).unwrap();
        assert_eq!(decode(&bytes).unwrap(), f);
    }

    #[test]
    fn round_trip_ack() {
        let f = frame(Msg::Ack(Ack {
            lamport: 42,
            hash: [7; 32],
        }));
        let bytes = encode(&f).unwrap();
        assert_eq!(decode(&bytes).unwrap(), f);
    }

    #[test]
    fn round_trip_heartbeat() {
        let f = frame(Msg::Heartbeat(Heartbeat {
            lamport: 1,
            rtt_hint: Some(11),
        }));
        let bytes = encode(&f).unwrap();
        assert_eq!(decode(&bytes).unwrap(), f);
    }

    #[test]
    fn round_trip_clipboard_url() {
        let f = frame(Msg::ClipboardItem(ClipboardItem {
            lamport: 99,
            hash: [3; 32],
            kind: Kind::Url,
            payload: b"https://github.com".to_vec(),
            sensitive: false,
            wall_time_ms: 1_700_000_000_000,
            origin: [4; 32],
            event_seq: 12,
        }));
        let bytes = encode(&f).unwrap();
        assert_eq!(decode(&bytes).unwrap(), f);
    }

    #[test]
    fn rejects_oversized_hello_name() {
        let f = frame(Msg::Hello(crate::Hello {
            name: "x".repeat(MAX_HELLO_NAME + 1),
            platform: "linux".into(),
            caps: vec![],
        }));
        let bytes = encode(&f).unwrap_err();
        assert!(matches!(bytes, ProtoError::HelloNameTooLong(_)));
    }

    #[test]
    fn rejects_oversized_hello_platform() {
        let f = frame(Msg::Hello(crate::Hello {
            name: "A".into(),
            platform: "x".repeat(MAX_HELLO_PLATFORM + 1),
            caps: vec![],
        }));
        let bytes = encode(&f).unwrap_err();
        assert!(matches!(bytes, ProtoError::HelloPlatformTooLong(_)));
    }

    #[test]
    fn round_trip_hello_with_unknown_cap() {
        // AC(a): an unknown cap decodes fine and survives round-trip — the
        // codec never rejects a cap it doesn't recognize; only the daemon's
        // negotiation step (fluxsync_proto::negotiate_caps) filters it out.
        let f = frame(Msg::Hello(crate::Hello {
            name: "A".into(),
            platform: "linux".into(),
            caps: vec!["core-1".into(), "x-future-test".into()],
        }));
        let bytes = encode(&f).unwrap();
        assert_eq!(decode(&bytes).unwrap(), f);
    }

    #[test]
    fn accepts_hello_caps_at_max_count_and_len() {
        let f = frame(Msg::Hello(crate::Hello {
            name: "A".into(),
            platform: "linux".into(),
            caps: vec!["x".repeat(crate::MAX_CAP_LEN); crate::MAX_HELLO_CAPS],
        }));
        let bytes = encode(&f).unwrap();
        assert!(decode(&bytes).is_ok());
    }

    #[test]
    fn rejects_too_many_hello_caps() {
        let f = frame(Msg::Hello(crate::Hello {
            name: "A".into(),
            platform: "linux".into(),
            caps: vec!["x".into(); crate::MAX_HELLO_CAPS + 1],
        }));
        let err = encode(&f).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::HelloCapsTooMany(n) if n == crate::MAX_HELLO_CAPS + 1
        ));
    }

    #[test]
    fn rejects_oversized_hello_cap_entry() {
        let f = frame(Msg::Hello(crate::Hello {
            name: "A".into(),
            platform: "linux".into(),
            caps: vec!["x".repeat(crate::MAX_CAP_LEN + 1)],
        }));
        let err = encode(&f).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::HelloCapTooLong(n) if n == crate::MAX_CAP_LEN + 1
        ));
    }

    #[test]
    fn rejects_non_ascii_printable_hello_cap() {
        let f = frame(Msg::Hello(crate::Hello {
            name: "A".into(),
            platform: "linux".into(),
            caps: vec!["bad\ncap".into()],
        }));
        let err = encode(&f).unwrap_err();
        assert!(matches!(err, ProtoError::HelloCapNotAsciiPrintable));
    }

    #[test]
    fn rejects_unknown_version_on_decode() {
        // Build a frame with a bogus version byte by encoding under v1 then
        // mutating the leading version field. Easier: build directly.
        let bogus = Frame {
            version: 0x99,
            msg: Msg::Bye,
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&bogus, &mut bytes).unwrap();
        let err = decode(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                ProtoError::Version {
                    got: 0x99,
                    expected: 0x02
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_version_on_encode() {
        let bogus = Frame {
            version: 0x42,
            msg: Msg::Bye,
        };
        let err = encode(&bogus).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::Version {
                got: 0x42,
                expected: 0x02
            }
        ));
    }

    #[test]
    fn rejects_oversized_payload() {
        let item = ClipboardItem {
            lamport: 0,
            hash: [0; 32],
            kind: Kind::Text,
            payload: vec![0u8; MAX_PAYLOAD + 1],
            sensitive: false,
            wall_time_ms: 0,
            origin: [0; 32],
            event_seq: 0,
        };
        let err = encode(&frame(Msg::ClipboardItem(item))).unwrap_err();
        assert!(matches!(err, ProtoError::PayloadTooLarge(n) if n == MAX_PAYLOAD + 1));
    }

    #[test]
    fn rejects_chunk_data_too_large() {
        let chunk = Chunk {
            item_id: [0; 32],
            idx: 0,
            total: 1,
            data: vec![0u8; MAX_CHUNK_DATA + 1],
        };
        let err = encode(&frame(Msg::Chunk(chunk))).unwrap_err();
        assert!(matches!(err, ProtoError::ChunkDataTooLarge(n) if n == MAX_CHUNK_DATA + 1));
    }

    #[test]
    fn rejects_chunk_total_too_large() {
        let chunk = Chunk {
            item_id: [0; 32],
            idx: 0,
            total: MAX_CHUNKS + 1,
            data: vec![],
        };
        let err = encode(&frame(Msg::Chunk(chunk))).unwrap_err();
        assert!(matches!(err, ProtoError::ChunkTotalTooLarge(n) if n == MAX_CHUNKS + 1));
    }

    #[test]
    fn round_trip_clipboard_image() {
        // A few non-UTF8 bytes to prove the payload survives as raw binary.
        let f = frame(Msg::ClipboardItem(ClipboardItem {
            lamport: 7,
            hash: [9; 32],
            kind: Kind::Image,
            payload: vec![0x89, 0x50, 0x4E, 0x47, 0x00, 0xFF, 0xFE, 0x01],
            sensitive: false,
            wall_time_ms: 1_700_000_000_000,
            origin: [0xAB; 32],
            event_seq: 3,
        }));
        let bytes = encode(&f).unwrap();
        assert_eq!(decode(&bytes).unwrap(), f);
    }

    #[test]
    fn accepts_chunk_total_at_max() {
        let chunk = Chunk {
            item_id: [0; 32],
            idx: MAX_CHUNKS - 1,
            total: MAX_CHUNKS,
            data: vec![0u8; MAX_CHUNK_DATA],
        };
        let bytes = encode(&frame(Msg::Chunk(chunk))).unwrap();
        assert!(decode(&bytes).is_ok());
    }

    #[test]
    fn rejects_chunk_total_zero() {
        let chunk = Chunk {
            item_id: [0; 32],
            idx: 0,
            total: 0,
            data: vec![],
        };
        let err = encode(&frame(Msg::Chunk(chunk))).unwrap_err();
        assert!(matches!(err, ProtoError::ChunkTotalZero));
    }

    #[test]
    fn rejects_chunk_idx_out_of_range() {
        let chunk = Chunk {
            item_id: [0; 32],
            idx: 5,
            total: 5,
            data: vec![],
        };
        let err = encode(&frame(Msg::Chunk(chunk))).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::ChunkIndexOutOfRange { idx: 5, total: 5 }
        ));
    }

    #[test]
    fn rejects_battery_over_100() {
        let bs = BatteryStatus {
            lamport: 0,
            level: 101,
            charging: false,
        };
        let err = encode(&frame(Msg::BatteryStatus(bs))).unwrap_err();
        assert!(matches!(err, ProtoError::BatteryLevel(101)));
    }

    #[test]
    fn round_trip_nak() {
        let f = frame(Msg::Nak(Nak {
            item_id: [5; 32],
            want_header: true,
            missing: vec![1, 7, 9000, 16383],
        }));
        let bytes = encode(&f).unwrap();
        assert_eq!(decode(&bytes).unwrap(), f);
    }

    #[test]
    fn accepts_nak_missing_at_max() {
        let f = frame(Msg::Nak(Nak {
            item_id: [0; 32],
            want_header: false,
            missing: vec![0u16; MAX_NAK_MISSING],
        }));
        let bytes = encode(&f).unwrap();
        assert!(decode(&bytes).is_ok());
    }

    #[test]
    fn rejects_nak_missing_too_large() {
        let f = frame(Msg::Nak(Nak {
            item_id: [0; 32],
            want_header: false,
            missing: vec![0u16; MAX_NAK_MISSING + 1],
        }));
        let err = encode(&f).unwrap_err();
        assert!(matches!(err, ProtoError::NakMissingTooLarge(n) if n == MAX_NAK_MISSING + 1));
    }

    #[test]
    fn rejects_truncated_cbor() {
        let f = frame(Msg::Bye);
        let bytes = encode(&f).unwrap();
        let truncated = &bytes[..bytes.len() - 1];
        let err = decode(truncated).unwrap_err();
        assert!(matches!(err, ProtoError::Cbor(_)));
    }

    // SE-02 regression: every wire struct rejects unknown CBOR map keys.
    // Catches a peer that smuggles extra fields past the schema — either a
    // future-version mistake (forward-compat must be explicit) or an
    // attacker probing the parser. We build a shadow struct with an extra
    // `__attacker_field` and confirm `decode` errors.
    #[test]
    fn rejects_unknown_field_in_clipboard_item() {
        use serde::Serialize;

        #[derive(Serialize)]
        struct EvilItem {
            lamport: u64,
            hash: [u8; 32],
            kind: Kind,
            payload: Vec<u8>,
            sensitive: bool,
            wall_time_ms: u64,
            __attacker_field: u32,
        }

        #[derive(Serialize)]
        enum EvilMsg {
            ClipboardItem(EvilItem),
        }

        #[derive(Serialize)]
        struct EvilFrame {
            version: u8,
            msg: EvilMsg,
        }

        let evil = EvilFrame {
            version: PROTOCOL_VERSION,
            msg: EvilMsg::ClipboardItem(EvilItem {
                lamport: 1,
                hash: [0; 32],
                kind: Kind::Text,
                payload: b"hi".to_vec(),
                sensitive: false,
                wall_time_ms: 0,
                __attacker_field: 0xDEAD_BEEF,
            }),
        };

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&evil, &mut bytes).unwrap();
        let err = decode(&bytes).unwrap_err();
        assert!(
            matches!(err, ProtoError::Cbor(_)),
            "expected CBOR deserialization error from unknown field, got {err:?}"
        );
    }

    /// A well-formed 64-char lowercase-hex `resync-1` hash for test fixtures.
    fn valid_hash() -> String {
        "cd".repeat(crate::RESYNC_HASH_LEN / 2)
    }

    #[test]
    fn round_trip_resync_offer() {
        let f = frame(Msg::ResyncOffer(crate::ResyncOffer {
            hashes: vec![valid_hash(), valid_hash()],
        }));
        let bytes = encode(&f).unwrap();
        assert_eq!(decode(&bytes).unwrap(), f);
    }

    #[test]
    fn round_trip_resync_pull() {
        let f = frame(Msg::ResyncPull(crate::ResyncPull {
            hashes: vec![valid_hash()],
        }));
        let bytes = encode(&f).unwrap();
        assert_eq!(decode(&bytes).unwrap(), f);
    }

    #[test]
    fn accepts_resync_hashes_at_max_count() {
        let f = frame(Msg::ResyncOffer(crate::ResyncOffer {
            hashes: vec![valid_hash(); MAX_RESYNC_HASHES],
        }));
        let bytes = encode(&f).unwrap();
        assert!(decode(&bytes).is_ok());
    }

    #[test]
    fn rejects_too_many_resync_hashes() {
        let f = frame(Msg::ResyncOffer(crate::ResyncOffer {
            hashes: vec![valid_hash(); MAX_RESYNC_HASHES + 1],
        }));
        let err = encode(&f).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::ResyncTooManyHashes(n) if n == MAX_RESYNC_HASHES + 1
        ));
    }

    #[test]
    fn rejects_resync_hash_wrong_length() {
        let f = frame(Msg::ResyncPull(crate::ResyncPull {
            hashes: vec!["ab".into()],
        }));
        let err = encode(&f).unwrap_err();
        assert!(matches!(err, ProtoError::ResyncHashMalformed));
    }

    #[test]
    fn rejects_resync_hash_uppercase() {
        let f = frame(Msg::ResyncOffer(crate::ResyncOffer {
            hashes: vec![valid_hash().to_uppercase()],
        }));
        let err = encode(&f).unwrap_err();
        assert!(matches!(err, ProtoError::ResyncHashMalformed));
    }

    #[test]
    fn rejects_resync_hash_non_hex() {
        let f = frame(Msg::ResyncOffer(crate::ResyncOffer {
            hashes: vec!["g".repeat(crate::RESYNC_HASH_LEN)],
        }));
        let err = encode(&f).unwrap_err();
        assert!(matches!(err, ProtoError::ResyncHashMalformed));
    }

    #[test]
    fn rejects_unknown_field_in_frame() {
        use serde::Serialize;

        #[derive(Serialize)]
        struct EvilFrame {
            version: u8,
            msg: Msg,
            __attacker_field: u32,
        }

        let evil = EvilFrame {
            version: PROTOCOL_VERSION,
            msg: Msg::Bye,
            __attacker_field: 0xDEAD_BEEF,
        };

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&evil, &mut bytes).unwrap();
        let err = decode(&bytes).unwrap_err();
        assert!(
            matches!(err, ProtoError::Cbor(_)),
            "expected CBOR deserialization error from unknown field, got {err:?}"
        );
    }
}
