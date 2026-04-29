use thiserror::Error;

/// Errors raised by the crypto crate.
///
/// `snow` errors are flattened to `String` to keep the API independent of the
/// underlying Noise implementation; we don't want to leak the dependency.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("noise pattern parse failed: {0}")]
    PatternParse(String),

    #[error("noise builder failed: {0}")]
    Builder(String),

    #[error("handshake step failed: {0}")]
    Handshake(String),

    #[error("transport mode failed: {0}")]
    Transport(String),

    #[error("encrypt failed: {0}")]
    Encrypt(String),

    #[error("decrypt failed: {0}")]
    Decrypt(String),

    #[error("remote static key not present after handshake")]
    MissingRemoteStatic,
}
