//! In-memory tail buffer for the `logs` IPC channel.
//!
//! Holds the last `CAPACITY` `LogEntry` values. Writers (the driver)
//! call `push`; readers (`fluxctl tail` / IPC subscribers) call
//! `snapshot`.

use fluxsync_core::LogEntry;
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

const CAPACITY: usize = 200;

#[derive(Debug, Default)]
pub struct LogTail {
    inner: Mutex<VecDeque<LogEntry>>,
}

impl LogTail {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(CAPACITY)),
        }
    }

    /// Lock the buffer, recovering from a poisoned mutex.
    ///
    /// A panic in any holder poisons the mutex. This is a best-effort log
    /// tail — losing data integrity past the latest entry is acceptable, so
    /// the poison is ignored rather than allowed to kill the daemon.
    fn guard(&self) -> MutexGuard<'_, VecDeque<LogEntry>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Push a log entry, evicting the oldest if at capacity.
    pub fn push(&self, entry: LogEntry) {
        let mut g = self.guard();
        if g.len() == CAPACITY {
            g.pop_front();
        }
        g.push_back(entry);
    }

    /// Return the last `n` entries (most-recent last).
    #[must_use]
    pub fn snapshot(&self, n: usize) -> Vec<LogEntry> {
        let g = self.guard();
        let take = n.min(g.len());
        g.iter().rev().take(take).rev().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::LogTail;
    use fluxsync_core::{LogEntry, LogLevel};
    use std::sync::Arc;

    fn entry(msg: &str) -> LogEntry {
        LogEntry {
            level: LogLevel::Info,
            msg: msg.to_string(),
        }
    }

    /// FS-014: a panic while holding the lock poisons the mutex; the tail
    /// must still accept pushes and snapshots instead of killing the daemon.
    #[test]
    fn survives_a_poisoned_mutex() {
        let tail = Arc::new(LogTail::new());
        tail.push(entry("before"));

        let poisoner = Arc::clone(&tail);
        let joined = std::thread::spawn(move || {
            let _g = poisoner.inner.lock().unwrap();
            panic!("poison the LogTail mutex");
        })
        .join();
        assert!(joined.is_err(), "poisoning thread must have panicked");

        // On main HEAD both calls would panic via `.expect(...)`.
        tail.push(entry("after"));
        let snap = tail.snapshot(10);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[1].msg, "after");
    }
}
