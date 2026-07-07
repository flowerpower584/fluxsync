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

    #[error("hello platform too long: {0} bytes (max 16)")]
    HelloPlatformTooLong(usize),

    #[error("hello name contains a control character")]
    HelloNameNotPrintable,

    #[error("hello platform is not ASCII printable")]
    HelloPlatformNotAsciiPrintable,

    #[error("too many hello caps: {0} entries (max 32)")]
    HelloCapsTooMany(usize),

    #[error("hello cap too long: {0} bytes (max 64)")]
    HelloCapTooLong(usize),

    #[error("hello cap is not ASCII printable")]
    HelloCapNotAsciiPrintable,

    #[error("too many resync hashes: {0} entries (max 32)")]
    ResyncTooManyHashes(usize),

    #[error("resync hash malformed: must be exactly 64 lowercase hex characters")]
    ResyncHashMalformed,

    #[error("CBOR decode failed: {0}")]
    Cbor(String),

    #[error("CBOR encode failed: {0}")]
    CborEncode(String),
}
