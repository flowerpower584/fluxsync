use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("unsupported protocol version: got {got:#x}, expected {expected:#x}")]
    Version { got: u8, expected: u8 },

    #[error("payload too large: {0} bytes (max 16777216)")]
    PayloadTooLarge(usize),

    #[error("chunk data too large: {0} bytes (max 1024)")]
    ChunkDataTooLarge(usize),

    #[error("chunk total {0} exceeds hard cap of 16384")]
    ChunkTotalTooLarge(u16),

    #[error("chunk total must be at least 1")]
    ChunkTotalZero,

    #[error("chunk index {idx} >= total {total}")]
    ChunkIndexOutOfRange { idx: u16, total: u16 },

    #[error("nak missing list too large: {0} entries (max 512)")]
    NakMissingTooLarge(usize),

    #[error("battery level {0} > 100")]
    BatteryLevel(u8),

    #[error("hello name too long: {0} bytes (max 256)")]
    HelloNameTooLong(usize),

    #[error("CBOR decode failed: {0}")]
    Cbor(String),

    #[error("CBOR encode failed: {0}")]
    CborEncode(String),
}
