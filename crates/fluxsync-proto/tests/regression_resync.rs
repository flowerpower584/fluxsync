//! resync-1 (§6.2, docs/PROTOCOL.md): `ResyncOffer`/`ResyncPull` bounds are
//! enforced on the RECEIVE/decode path, not only on send/encode — mirrors
//! `regression_hello_caps.rs`'s raw-CBOR technique so a hostile peer that
//! crafts bytes bypassing our own `encode()` validation still gets rejected
//! by `decode()`, the real wire ingress.

use fluxsync_proto::{
    decode, encode, Frame, Msg, ProtoError, ResyncOffer, ResyncPull, MAX_RESYNC_HASHES,
    PROTOCOL_VERSION, RESYNC_HASH_LEN,
};

/// Serialize a Frame straight through ciborium, skipping `encode()`'s
/// `validate()` gate — exactly what an attacker's own (non-FluxSync)
/// encoder would put on the wire.
fn raw_cbor(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(frame, &mut out).expect("ciborium serialize");
    out
}

/// A well-formed 64-char lowercase-hex `resync-1` hash.
fn valid_hash() -> String {
    "ef".repeat(RESYNC_HASH_LEN / 2)
}

fn offer(hashes: Vec<String>) -> Frame {
    Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::ResyncOffer(ResyncOffer { hashes }),
    }
}

fn pull(hashes: Vec<String>) -> Frame {
    Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::ResyncPull(ResyncPull { hashes }),
    }
}

#[test]
fn hostile_too_many_hashes_rejected_on_decode() {
    let frame = offer(vec![valid_hash(); 10_000]);
    let bytes = raw_cbor(&frame);
    let result = decode(&bytes);
    assert!(
        matches!(result, Err(ProtoError::ResyncTooManyHashes(10_000))),
        "decode() must reject 10_000 resync hashes, got {result:?}"
    );
}

#[test]
fn boundary_hash_count_max_ok_over_rejected_on_decode() {
    let at_cap = offer(vec![valid_hash(); MAX_RESYNC_HASHES]);
    let ok = decode(&raw_cbor(&at_cap));
    assert!(
        ok.is_ok(),
        "{MAX_RESYNC_HASHES} resync hashes must decode, got {ok:?}"
    );

    let over = offer(vec![valid_hash(); MAX_RESYNC_HASHES + 1]);
    let err = decode(&raw_cbor(&over));
    assert!(
        matches!(err, Err(ProtoError::ResyncTooManyHashes(n)) if n == MAX_RESYNC_HASHES + 1),
        "{MAX_RESYNC_HASHES}+1 resync hashes must be rejected on decode, got {err:?}"
    );
}

#[test]
fn hostile_wrong_length_hash_rejected_on_decode() {
    let frame = pull(vec!["a".repeat(63)]);
    let bytes = raw_cbor(&frame);
    let result = decode(&bytes);
    assert!(
        matches!(result, Err(ProtoError::ResyncHashMalformed)),
        "decode() must reject a 63-char hash, got {result:?}"
    );
}

#[test]
fn hostile_uppercase_hash_rejected_on_decode() {
    let frame = pull(vec![valid_hash().to_uppercase()]);
    let bytes = raw_cbor(&frame);
    let result = decode(&bytes);
    assert!(
        matches!(result, Err(ProtoError::ResyncHashMalformed)),
        "decode() must reject an uppercase-hex hash, got {result:?}"
    );
}

#[test]
fn hostile_non_hex_hash_rejected_on_decode() {
    let frame = offer(vec!["z".repeat(RESYNC_HASH_LEN)]);
    let bytes = raw_cbor(&frame);
    let result = decode(&bytes);
    assert!(
        matches!(result, Err(ProtoError::ResyncHashMalformed)),
        "decode() must reject a non-hex hash, got {result:?}"
    );
}

#[test]
fn no_silent_truncation_send_path() {
    let frame = offer(vec![valid_hash(); MAX_RESYNC_HASHES + 1]);
    let err = encode(&frame);
    assert!(
        matches!(err, Err(ProtoError::ResyncTooManyHashes(n)) if n == MAX_RESYNC_HASHES + 1),
        "encode() must reject (not truncate), got {err:?}"
    );
}

#[test]
fn round_trip_resync_offer_and_pull_via_decode() {
    let hashes = vec![valid_hash(), "ab".repeat(RESYNC_HASH_LEN / 2)];
    let offer_frame = offer(hashes.clone());
    let decoded = decode(&raw_cbor(&offer_frame)).expect("well-formed ResyncOffer must decode");
    assert_eq!(decoded, offer_frame);

    let pull_frame = pull(hashes);
    let decoded = decode(&raw_cbor(&pull_frame)).expect("well-formed ResyncPull must decode");
    assert_eq!(decoded, pull_frame);
}
