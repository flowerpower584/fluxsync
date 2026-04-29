use crate::error::CryptoError;

/// Established Noise IK transport session. Wraps `snow::TransportState`.
///
/// Each call to [`Session::encrypt`] / [`Session::decrypt`] increments the
/// internal nonce counter — never reuse a session across reconnects.
pub struct Session {
    transport: snow::TransportState,
}

impl Session {
    pub(crate) fn new(transport: snow::TransportState) -> Self {
        Self { transport }
    }

    /// Encrypt a single payload. Returns ciphertext concatenated with the
    /// 16-byte Poly1305 tag (`plaintext.len() + 16` bytes total).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt a single ciphertext+tag bundle. Authenticates the tag before
    /// returning; bit-flips anywhere in the input cause an `Err`.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::Decrypt(
                "ciphertext shorter than Poly1305 tag".into(),
            ));
        }
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(ciphertext, &mut buf)
            .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }
}
