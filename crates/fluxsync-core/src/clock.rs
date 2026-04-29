//! Injected clocks.
//!
//! The core crate never reads system time directly. Two traits cover the
//! two needs:
//!
//! * [`Clock`] — Lamport-style monotonic counter for ordering items across
//!   peers. `tick` is called when this device emits an item; `observe` is
//!   called when this device sees a peer's lamport value.
//! * [`WallClock`] — current time-of-day, in `HH:MM` form for the UI's
//!   history entries and as UNIX millis for wire frames.

/// Lamport-style logical clock.
pub trait Clock {
    /// Local event: bump the counter and return the new value.
    fn tick(&mut self) -> u64;
    /// Remote event observed: max(self, seen) + 1, return the new value.
    fn observe(&mut self, seen: u64) -> u64;
    /// Read the current value without bumping it.
    fn now(&self) -> u64;
}

/// Default in-process Lamport clock implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct LamportClock {
    counter: u64,
}

impl LamportClock {
    #[must_use]
    pub fn new() -> Self {
        Self { counter: 0 }
    }
}

impl Clock for LamportClock {
    fn tick(&mut self) -> u64 {
        self.counter = self.counter.saturating_add(1);
        self.counter
    }

    fn observe(&mut self, seen: u64) -> u64 {
        self.counter = self.counter.max(seen).saturating_add(1);
        self.counter
    }

    fn now(&self) -> u64 {
        self.counter
    }
}

/// Wall-clock provider for the UI's `HH:MM` and the wire's `wall_time_ms`.
pub trait WallClock {
    fn hhmm(&self) -> String;
    fn unix_millis(&self) -> u64;
}

/// Trivial stub useful in unit tests. Returns the values it was constructed
/// with on every call.
#[derive(Debug, Clone)]
pub struct StubWallClock {
    pub hhmm: String,
    pub unix_millis: u64,
}

impl StubWallClock {
    #[must_use]
    pub fn new(hhmm: impl Into<String>, unix_millis: u64) -> Self {
        Self {
            hhmm: hhmm.into(),
            unix_millis,
        }
    }
}

impl WallClock for StubWallClock {
    fn hhmm(&self) -> String {
        self.hhmm.clone()
    }
    fn unix_millis(&self) -> u64 {
        self.unix_millis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lamport_tick_is_monotonic() {
        let mut c = LamportClock::new();
        assert_eq!(c.tick(), 1);
        assert_eq!(c.tick(), 2);
        assert_eq!(c.tick(), 3);
        assert_eq!(c.now(), 3);
    }

    #[test]
    fn lamport_observe_advances_to_max_plus_one() {
        let mut c = LamportClock::new();
        c.tick(); // 1
        assert_eq!(c.observe(10), 11);
        assert_eq!(c.observe(5), 12); // smaller seen still bumps by 1
        assert_eq!(c.now(), 12);
    }

    #[test]
    fn lamport_saturates_at_u64_max() {
        let mut c = LamportClock { counter: u64::MAX };
        assert_eq!(c.tick(), u64::MAX);
        assert_eq!(c.observe(0), u64::MAX);
    }

    #[test]
    fn stub_wall_clock_returns_what_it_was_built_with() {
        let w = StubWallClock::new("14:32", 1_700_000_000_000);
        assert_eq!(w.hhmm(), "14:32");
        assert_eq!(w.unix_millis(), 1_700_000_000_000);
        assert_eq!(w.hhmm(), "14:32"); // not consumed
    }
}
