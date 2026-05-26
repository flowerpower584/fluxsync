use blake3::Hasher;
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Long-term identity keypair.
///
/// `StaticSecret` zeroizes its internal bytes when dropped (per
/// `x25519-dalek` semantics), so callers do not need to scrub the secret
/// themselves. The `Clone` derive is fine here — both halves are 32 bytes
/// and the secret is never written to disk by this crate.
///
/// FS-053: APIs that hand the raw secret out (`secret_bytes`,
/// `raw_secret`) return `Zeroizing<[u8; 32]>` so the bytes are wiped
/// when the caller's binding goes out of scope. Callers handing the
/// bytes to the OS keychain should do so directly from the
/// `Zeroizing` value rather than copying into a plain array.
#[derive(Clone)]
pub struct Identity {
    secret: StaticSecret,
    public: [u8; 32],
}

impl Identity {
    /// Generate a fresh keypair using the operating-system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// Reconstruct an `Identity` from a previously persisted 32-byte secret.
    ///
    /// The input is taken by `Zeroizing` so the caller cannot accidentally
    /// keep the unscrubbed copy on the stack after this returns. Bytes are
    /// clamped on the way in (X25519 convention).
    ///
    /// SE-03: rejects the all-zero key (and would be the right place to
    /// reject other small-subgroup points). A caller that hits
    /// `CryptoError::DegenerateKey` has almost certainly stumbled into a
    /// keystore-read-error fallback path and should regenerate, not paper
    /// over the failure.
    #[allow(clippy::needless_pass_by_value)] // intentional: consume + drop scrubs caller's copy
    pub fn from_secret_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self, CryptoError> {
        if bool::from(bytes.ct_eq(&[0u8; 32])) {
            return Err(CryptoError::DegenerateKey);
        }
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self { secret, public })
    }

    /// Owned copy of the secret for keychain storage.
    ///
    /// Returned as `Zeroizing<[u8; 32]>`; the bytes are wiped when the
    /// returned value is dropped, so callers cannot forget to scrub.
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// 32-byte X25519 public key. Safe to share over the wire.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Stable peer identifier = `BLAKE3(public_key)`. 32 bytes.
    #[must_use]
    pub fn peer_id(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(&self.public);
        *h.finalize().as_bytes()
    }

    pub(crate) fn raw_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }
}

/// Known small-order Curve25519 public keys.
///
/// Source: <https://cr.yp.to/ecdh.html> + RFC 7748 §6.1.  Any of these
/// as a peer static pubkey forces every Noise IK `ss`/`es`/`se` DH to
/// return either `[0; 32]` or another point in the same small subgroup,
/// trivially predictable by an off-path attacker.
const LOW_ORDER_POINTS: [[u8; 32]; 7] = [
    // order 1
    [0u8; 32],
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // order 2
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // order 4
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // order 8 — p-1
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // order 8 — p
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // order 8 — p+1
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// H1: validate a peer's *static public key* before persisting it as
/// trusted. Rejects the all-zero key and any of the seven known
/// low-order Curve25519 points. Constant-time comparison so this is
/// safe to call on attacker-supplied bytes without leaking the match
/// position via timing.
///
/// This is *not* a substitute for SAS / verify-words: a random pubkey
/// will pass this check yet still be the wrong peer. It only blocks
/// the cheap "I forged the URI" attacks where the attacker hands the
/// user a degenerate key that yields a predictable handshake.
pub fn validate_peer_pubkey(pubkey: &[u8; 32]) -> Result<(), CryptoError> {
    let mut bad = subtle::Choice::from(0u8);
    for p in &LOW_ORDER_POINTS {
        bad |= pubkey.ct_eq(p);
    }
    if bool::from(bad) {
        Err(CryptoError::InvalidPeerPubkey)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_peer_pubkey;

    #[test]
    fn all_zero_rejected() {
        assert!(validate_peer_pubkey(&[0u8; 32]).is_err());
    }

    #[test]
    fn low_order_points_rejected() {
        let mut p = [0u8; 32];
        p[0] = 0x01;
        assert!(validate_peer_pubkey(&p).is_err());
    }

    #[test]
    fn random_pubkey_accepted() {
        let mut p = [0u8; 32];
        for (i, b) in p.iter_mut().enumerate() {
            let i_u8 = u8::try_from(i & 0xff).unwrap_or(0);
            *b = i_u8.wrapping_mul(37).wrapping_add(11);
        }
        assert!(validate_peer_pubkey(&p).is_ok());
    }
}
