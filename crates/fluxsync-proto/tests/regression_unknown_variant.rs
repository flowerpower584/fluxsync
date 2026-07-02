//! Regression: an unknown `Msg` variant tag must fail closed at `decode()`,
//! never panic. `Msg` uses serde's default externally-tagged representation
//! (`{"<VariantName>": <payload>}`), so a hostile peer — or simply a future
//! FluxSync build with a variant we don't know yet — can ship a tag that
//! doesn't exist in our `Msg` enum. No real `Msg` value can express that, so
//! (mirroring `regression_hello_platform.rs`'s raw-CBOR technique) we hand
//! -roll a shadow type with the same wire shape but a bogus tag and confirm
//! `decode()` rejects it as a `ProtoError`, not a crash, on the untrusted
//! UDP ingress path.

use fluxsync_proto::{decode, ProtoError, PROTOCOL_VERSION};
use serde::Serialize;

/// Same wire shape as the real `Frame { version, msg }`, but `msg`'s tag
/// ("TotallyUnknown") has no counterpart in the real `Msg` enum.
#[derive(Serialize)]
enum BogusMsg {
    TotallyUnknown(u8),
}

#[derive(Serialize)]
struct BogusFrame {
    version: u8,
    msg: BogusMsg,
}

fn raw_cbor(frame: &BogusFrame) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(frame, &mut out).expect("ciborium serialize");
    out
}

#[test]
fn unknown_variant_tag_rejected_not_panicking() {
    let bogus = BogusFrame {
        version: PROTOCOL_VERSION,
        msg: BogusMsg::TotallyUnknown(7),
    };

    // A hostile (or simply foreign/future) peer's own encoder could ship
    // this; our `encode()` could never produce it since `Msg` has no such
    // variant.
    let bytes = raw_cbor(&bogus);
    eprintln!("raw unknown-variant datagram = {} bytes", bytes.len());

    let result = decode(&bytes);
    eprintln!("decode() result = {result:?}");

    assert!(
        matches!(result, Err(ProtoError::Cbor(_))),
        "decode() must fail closed (ProtoError), not panic, on an unknown Msg variant tag, got {result:?}"
    );
}
