use blake3::Hasher;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// Long-term identity keypair.
///
/// `StaticSecret` zeroizes its internal bytes when dropped (per
/// `x25519-dalek` semantics), so callers do not need to scrub the secret
/// themselves. The `Clone` derive is fine here — both halves are 32 bytes
/// and the secret is never written to disk by this crate.
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
    /// Bytes are clamped on the way in (X25519 convention).
    #[must_use]
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// Owned copy of the secret for keychain storage.
    ///
    /// The caller is responsible for handing the bytes to the keychain
    /// quickly and zeroizing any intermediate buffer.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
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

    pub(crate) fn raw_secret(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}
