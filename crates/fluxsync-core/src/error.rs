use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("threshold {0} outside allowed 5..=50")]
    ThresholdOutOfRange(u8),

    #[error("battery level {0} > 100")]
    BatteryLevel(u8),
}
