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
