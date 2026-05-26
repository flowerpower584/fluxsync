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
