use crate::error::CryptoError;
use crate::identity::Identity;
use crate::session::{Session, HANDSHAKE_HASH_LEN};
use crate::NOISE_PATTERN;

/// Snapshot the Noise handshake hash `h` from a finished `HandshakeState`
/// before consuming it into transport mode. `Noise_IK_25519_ChaChaPoly_BLAKE2s`
/// guarantees `h` is exactly 32 bytes; anything else is a snow API break
/// and surfaces as `CryptoError::Handshake`.
fn snapshot_hash(state: &snow::HandshakeState) -> Result<[u8; HANDSHAKE_HASH_LEN], CryptoError> {
    let h = state.get_handshake_hash();
    h.try_into().map_err(|_| {
        CryptoError::Handshake(format!("handshake hash not {HANDSHAKE_HASH_LEN} bytes"))
    })
}

/// Buffer size for handshake messages. Noise IK messages are small (~96 B
/// for `Noise_IK_25519_ChaChaPoly_BLAKE2s`); 1 KiB is generous.
const HS_BUF: usize = 1024;

/// Initiator side of the Noise IK handshake. Used when this device wants to
/// talk to a peer whose static public key it already trusts (paired earlier).
pub struct Initiator {
    state: snow::HandshakeState,
}

impl Initiator {
    /// Build the initiator state and produce the first handshake message.
    /// Caller sends `msg1` to the peer over the wire.
    pub fn start(
        identity: &Identity,
        peer_static_pub: &[u8; 32],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let pattern = NOISE_PATTERN
            .parse()
            .map_err(|e: snow::Error| CryptoError::PatternParse(e.to_string()))?;
        let secret = identity.raw_secret();
        let mut state = snow::Builder::new(pattern)
            .local_private_key(&*secret)
            .remote_public_key(peer_static_pub)
            .build_initiator()
            .map_err(|e| CryptoError::Builder(e.to_string()))?;

        let mut buf = vec![0u8; HS_BUF];
        let n = state
            .write_message(&[], &mut buf)
            .map_err(|e| CryptoError::Handshake(e.to_string()))?;
        buf.truncate(n);
        Ok((Self { state }, buf))
    }

    /// Consume the responder's reply (`msg2`) to finalize the handshake.
    /// Returns the transport-mode [`Session`] ready for application bytes.
    pub fn finish(mut self, msg2: &[u8]) -> Result<Session, CryptoError> {
        let mut payload = vec![0u8; HS_BUF];
        self.state
            .read_message(msg2, &mut payload)
            .map_err(|e| CryptoError::Handshake(e.to_string()))?;
        let hash = snapshot_hash(&self.state)?;
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| CryptoError::Transport(e.to_string()))?;
        Ok(Session::new(transport, hash))
    }
}

/// Responder side of the Noise IK handshake.
pub struct Responder;

impl Responder {
    /// Read the initiator's first message and produce the responder's reply.
    ///
    /// On success returns:
    ///   * the established [`Session`],
    ///   * the responder's reply bytes (`msg2`) to send back to the initiator,
    ///   * the **initiator's** static public key, which the caller MUST verify
    ///     against the local peer registry before treating the session as
    ///     trusted.
    pub fn step(
        identity: &Identity,
        msg1: &[u8],
    ) -> Result<(Session, Vec<u8>, [u8; 32]), CryptoError> {
        let pattern = NOISE_PATTERN
            .parse()
            .map_err(|e: snow::Error| CryptoError::PatternParse(e.to_string()))?;
        let secret = identity.raw_secret();
        let mut state = snow::Builder::new(pattern)
            .local_private_key(&*secret)
            .build_responder()
            .map_err(|e| CryptoError::Builder(e.to_string()))?;

        let mut payload = vec![0u8; HS_BUF];
        state
            .read_message(msg1, &mut payload)
            .map_err(|e| CryptoError::Handshake(e.to_string()))?;

        let remote_static: [u8; 32] = state
            .get_remote_static()
            .ok_or(CryptoError::MissingRemoteStatic)?
            .try_into()
            .map_err(|_| CryptoError::Handshake("remote static not 32 bytes".into()))?;

        let mut buf = vec![0u8; HS_BUF];
        let n = state
            .write_message(&[], &mut buf)
            .map_err(|e| CryptoError::Handshake(e.to_string()))?;
        buf.truncate(n);

        let hash = snapshot_hash(&state)?;
        let transport = state
            .into_transport_mode()
            .map_err(|e| CryptoError::Transport(e.to_string()))?;

        Ok((Session::new(transport, hash), buf, remote_static))
    }
}
