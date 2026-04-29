//! Concrete [`WallClock`] backed by `chrono::Local`.
//!
//! Lives outside `fluxsync-core` so the core stays time-source-free
//! and unit-testable with `StubWallClock`.

use chrono::Local;
use fluxsync_core::WallClock;

#[derive(Debug, Clone, Copy, Default)]
pub struct ChronoWallClock;

impl WallClock for ChronoWallClock {
    fn hhmm(&self) -> String {
        Local::now().format("%H:%M").to_string()
    }

    fn unix_millis(&self) -> u64 {
        Local::now().timestamp_millis().try_into().unwrap_or(0) // pre-1970 = no
    }
}
