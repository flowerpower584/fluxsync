use crate::wordlist::WORDLIST;
use blake3::Hasher;

/// Number of words in a verbal fingerprint (10 bits per word).
pub const FINGERPRINT_WORDS: usize = 6;

/// Derive a 6-word verbal fingerprint from a 32-byte X25519 public key.
///
/// The hash is `BLAKE3(public_key)`. Six 10-bit indices are taken from the
/// low 60 bits of the first 8 bytes, in least-significant-first order, so
/// any two implementations that agree on this function and on `WORDLIST`
/// will always produce the same words for the same key.
#[must_use]
pub fn fingerprint(public_key: &[u8; 32]) -> [&'static str; FINGERPRINT_WORDS] {
    let mut h = Hasher::new();
    h.update(public_key);
    let hash = h.finalize();
    let bytes = hash.as_bytes();

    // Take 8 bytes as a little-endian u64, then chop into six 10-bit slots.
    let mut head = [0u8; 8];
    head.copy_from_slice(&bytes[..8]);
    let v = u64::from_le_bytes(head);

    let mut words: [&str; FINGERPRINT_WORDS] = [""; FINGERPRINT_WORDS];
    for (i, slot) in words.iter_mut().enumerate() {
        let idx = ((v >> (i * 10)) & 0x3FF) as usize;
        *slot = WORDLIST[idx];
    }
    words
}
