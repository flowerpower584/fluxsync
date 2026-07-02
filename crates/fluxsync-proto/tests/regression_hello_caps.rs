//! DIR-P1-01: `Hello.caps` bounds are enforced on the RECEIVE/decode path,
//! not only on send/encode — mirrors `regression_hello_platform.rs`'s
//! raw-CBOR technique so a hostile peer that crafts bytes bypassing our own
//! `encode()` validation still gets rejected by `decode()`, the real wire
//! ingress.

use fluxsync_proto::{
    decode, encode, Frame, Hello, Msg, ProtoError, MAX_CAP_LEN, MAX_HELLO_CAPS, PROTOCOL_VERSION,
};

/// Serialize a Frame straight through ciborium, skipping `encode()`'s
/// `validate()` gate — exactly what an attacker's own (non-FluxSync)
/// encoder would put on the wire.
fn raw_cbor(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(frame, &mut out).expect("ciborium serialize");
    out
}

fn hello(caps: Vec<String>) -> Frame {
    Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Hello(Hello {
            name: "A".into(),
            platform: "linux".into(),
            caps,
        }),
    }
}

#[test]
fn hostile_too_many_caps_rejected_on_decode() {
    let frame = hello(vec!["x".into(); 10_000]);
    let bytes = raw_cbor(&frame);
    let result = decode(&bytes);
    assert!(
        matches!(result, Err(ProtoError::HelloCapsTooMany(10_000))),
        "decode() must reject 10_000 caps, got {result:?}"
    );
}

#[test]
fn boundary_caps_count_max_ok_over_rejected_on_decode() {
    let at_cap = hello(vec!["x".into(); MAX_HELLO_CAPS]);
    let ok = decode(&raw_cbor(&at_cap));
    assert!(ok.is_ok(), "{MAX_HELLO_CAPS} caps must decode, got {ok:?}");

    let over = hello(vec!["x".into(); MAX_HELLO_CAPS + 1]);
    let err = decode(&raw_cbor(&over));
    assert!(
        matches!(err, Err(ProtoError::HelloCapsTooMany(n)) if n == MAX_HELLO_CAPS + 1),
        "{MAX_HELLO_CAPS}+1 caps must be rejected on decode, got {err:?}"
    );
}

#[test]
fn hostile_oversized_cap_entry_rejected_on_decode() {
    let frame = hello(vec!["x".repeat(10_000)]);
    let bytes = raw_cbor(&frame);
    let result = decode(&bytes);
    assert!(
        matches!(result, Err(ProtoError::HelloCapTooLong(10_000))),
        "decode() must reject a 10_000-byte cap entry, got {result:?}"
    );
}

#[test]
fn boundary_cap_len_max_ok_over_rejected_on_decode() {
    let at_cap = hello(vec!["x".repeat(MAX_CAP_LEN)]);
    let ok = decode(&raw_cbor(&at_cap));
    assert!(ok.is_ok(), "cap len == {MAX_CAP_LEN} must decode, got {ok:?}");

    let over = hello(vec!["x".repeat(MAX_CAP_LEN + 1)]);
    let err = decode(&raw_cbor(&over));
    assert!(
        matches!(err, Err(ProtoError::HelloCapTooLong(n)) if n == MAX_CAP_LEN + 1),
        "cap len == {MAX_CAP_LEN}+1 must be rejected on decode, got {err:?}"
    );
}

#[test]
fn hostile_non_ascii_printable_cap_rejected_on_decode() {
    let frame = hello(vec!["évil\tcap".into()]);
    let bytes = raw_cbor(&frame);
    let result = decode(&bytes);
    assert!(
        matches!(result, Err(ProtoError::HelloCapNotAsciiPrintable)),
        "decode() must reject a non-ASCII-printable cap, got {result:?}"
    );
}

#[test]
fn no_silent_truncation_send_path() {
    let frame = hello(vec!["x".into(); MAX_HELLO_CAPS + 1]);
    let err = encode(&frame);
    assert!(
        matches!(err, Err(ProtoError::HelloCapsTooMany(n)) if n == MAX_HELLO_CAPS + 1),
        "encode() must reject (not truncate), got {err:?}"
    );
}

/// AC(a): a Hello carrying an unknown cap decodes fine — the wire layer
/// never rejects on capability content, only on the count/length/charset
/// bounds above. Filtering unknown caps is the daemon's negotiation step
/// (`fluxsync_proto::negotiate_caps`), exercised in `lib.rs`'s own tests.
#[test]
fn unknown_cap_decodes_fine_and_is_not_in_negotiated_set() {
    let frame = hello(vec!["core-1".into(), "x-future-test".into()]);
    let decoded = decode(&raw_cbor(&frame)).expect("unknown cap must not fail decode");
    let Msg::Hello(h) = &decoded.msg else {
        panic!("expected Hello");
    };
    let negotiated = fluxsync_proto::negotiate_caps(&h.caps);
    assert!(negotiated.contains(&"core-1".to_string()));
    assert!(!negotiated.contains(&"x-future-test".to_string()));
}
