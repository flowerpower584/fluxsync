//! In-memory tail buffer for the `logs` IPC channel.
//!
//! Holds the last `CAPACITY` `LogEntry` values. Writers (the driver)
//! call `push`; readers (`fluxctl tail` / IPC subscribers) call
//! `snapshot`.

use fluxsync_core::LogEntry;
use std::collections::VecDeque;
use std::sync::Mutex;

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

    /// Push a log entry, evicting the oldest if at capacity.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn push(&self, entry: LogEntry) {
        let mut g = self.inner.lock().expect("LogTail mutex poisoned");
        if g.len() == CAPACITY {
            g.pop_front();
        }
        g.push_back(entry);
    }

    /// Return the last `n` entries (most-recent last).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn snapshot(&self, n: usize) -> Vec<LogEntry> {
        let g = self.inner.lock().expect("LogTail mutex poisoned");
        let take = n.min(g.len());
        g.iter().rev().take(take).rev().cloned().collect()
    }
}
