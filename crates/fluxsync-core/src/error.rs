use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("battery level {0} > 100")]
    BatteryLevel(u8),

    #[error("history retention must be one of 1h, 1d, 7d or forever, got {0}s")]
    InvalidRetention(u64),

    #[error("invalid device name: {0}")]
    InvalidDeviceName(String),
}
