//! End-to-end handshake + transport tests using `pair_for_test`.

use fluxsync_crypto::test_util::pair_for_test;
use fluxsync_crypto::{fingerprint, Identity, FINGERPRINT_WORDS, WORDLIST};

#[test]
fn round_trip_handshake_and_message() {
    let a = Identity::generate();
    let b = Identity::generate();
    let (mut a_sess, mut b_sess) = pair_for_test(&a, &b).expect("pair");

    let ct = a_sess.encrypt(b"hello, world").expect("encrypt");
    assert_ne!(ct.as_slice(), b"hello, world");
    let pt = b_sess.decrypt(&ct).expect("decrypt");
    assert_eq!(pt.as_slice(), b"hello, world");
}

#[test]
fn bidirectional_messages() {
    let a = Identity::generate();
    let b = Identity::generate();
    let (mut a_sess, mut b_sess) = pair_for_test(&a, &b).expect("pair");

    let ct1 = a_sess.encrypt(b"a -> b").expect("encrypt");
    let pt1 = b_sess.decrypt(&ct1).expect("decrypt");
    assert_eq!(pt1.as_slice(), b"a -> b");

    let ct2 = b_sess.encrypt(b"b -> a").expect("encrypt");
    let pt2 = a_sess.decrypt(&ct2).expect("decrypt");
    assert_eq!(pt2.as_slice(), b"b -> a");
}

#[test]
fn dropped_frame_does_not_break_session() {
    // The clipboard "flap" bug: a single lost UDP datagram used to
    // desync the receiving nonce and kill the session. Each frame now
    // carries its own nonce, so skipping one must not break the rest.
    let a = Identity::generate();
    let b = Identity::generate();
    let (mut a_sess, mut b_sess) = pair_for_test(&a, &b).expect("pair");

    let f1 = a_sess.encrypt(b"frame-1").expect("encrypt");
    let _lost = a_sess.encrypt(b"frame-2").expect("encrypt"); // dropped in transit
    let f3 = a_sess.encrypt(b"frame-3").expect("encrypt");

    assert_eq!(b_sess.decrypt(&f1).expect("decrypt f1"), b"frame-1");
    assert_eq!(
        b_sess.decrypt(&f3).expect("decrypt f3 after a gap"),
        b"frame-3"
    );
}

#[test]
fn out_of_order_delivery_decrypts() {
    // UDP can reorder datagrams; every frame must decrypt regardless of
    // arrival order.
    let a = Identity::generate();
    let b = Identity::generate();
    let (mut a_sess, mut b_sess) = pair_for_test(&a, &b).expect("pair");

    let f1 = a_sess.encrypt(b"one").expect("encrypt");
    let f2 = a_sess.encrypt(b"two").expect("encrypt");
    let f3 = a_sess.encrypt(b"three").expect("encrypt");

    assert_eq!(b_sess.decrypt(&f3).expect("decrypt f3"), b"three");
    assert_eq!(b_sess.decrypt(&f1).expect("decrypt f1"), b"one");
    assert_eq!(b_sess.decrypt(&f2).expect("decrypt f2"), b"two");
}

#[test]
fn replayed_frame_is_rejected() {
    // Explicit per-frame nonces removed the implicit in-order replay
    // protection; the sliding window must put it back.
    let a = Identity::generate();
    let b = Identity::generate();
    let (mut a_sess, mut b_sess) = pair_for_test(&a, &b).expect("pair");

    let f = a_sess.encrypt(b"once").expect("encrypt");
    assert_eq!(b_sess.decrypt(&f).expect("first delivery"), b"once");
    assert!(
        b_sess.decrypt(&f).is_err(),
        "a replayed frame must be rejected"
    );
}

#[test]
fn tampered_ciphertext_fails_decrypt() {
    let a = Identity::generate();
    let b = Identity::generate();
    let (mut a_sess, mut b_sess) = pair_for_test(&a, &b).expect("pair");

    let mut ct = a_sess.encrypt(b"secret").expect("encrypt");
    let last = ct.len() - 1;
    ct[last] ^= 0x80; // flip a bit in the Poly1305 tag
    let res = b_sess.decrypt(&ct);
    assert!(res.is_err(), "tampered ciphertext should not decrypt");
}

#[test]
fn fingerprint_is_deterministic_and_six_words() {
    let id = Identity::generate();
    let pk = id.public_key();
    let fp1 = fingerprint(&pk);
    let fp2 = fingerprint(&pk);
    assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    assert_eq!(fp1.len(), FINGERPRINT_WORDS);
    for w in fp1 {
        assert!(WORDLIST.contains(&w), "{w} missing from WORDLIST");
    }
}

#[test]
fn fingerprint_changes_with_key() {
    let a = Identity::generate();
    let b = Identity::generate();
    assert_ne!(
        fingerprint(&a.public_key()),
        fingerprint(&b.public_key()),
        "different keys should yield different fingerprints w.h.p."
    );
}

#[test]
fn identity_round_trips_through_secret_bytes() {
    let id = Identity::generate();
    let bytes = id.secret_bytes();
    let restored = Identity::from_secret_bytes(bytes);
    assert_eq!(id.public_key(), restored.public_key());
    assert_eq!(id.peer_id(), restored.peer_id());
}

#[test]
fn wordlist_size_invariant() {
    assert_eq!(
        WORDLIST.len(),
        1024,
        "wordlist must be exactly 1024 entries"
    );
}
