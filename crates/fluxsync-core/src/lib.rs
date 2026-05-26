//! FluxSync pure logic.
//!
//! No tokio, no I/O, no `std::time::Instant`. Wall-clock and Lamport-clock
//! are injected via traits so the whole FSM is exercisable in unit tests
//! with zero scheduler involvement.
//!
//! Layering:
//! ```text
//!     fluxsync-proto  →  fluxsync-core  →  fluxsyncd / fluxsync-mobile-ffi
//! ```
//! `fluxsync-core` may pull in `fluxsync-proto` (shared wire types) but
//! never the other direction.

pub mod app;
pub mod classify;
pub mod clock;
pub mod dedup;
pub mod error;
pub mod events;
pub mod fsm;
pub mod policy;
pub mod state;

pub use app::App;
pub use classify::{is_sensitive, kind_of};
pub use clock::{Clock, LamportClock, StubWallClock, WallClock};
pub use dedup::{ContentHash, DedupRing, DEDUP_CAPACITY};
pub use error::CoreError;
pub use events::{Action, Event, LogEntry, LogLevel};
pub use fsm::{transition, Phase};
pub use policy::status_for;
pub use state::{Config, HistoryItem, HistorySource, State, Status};

// Re-export Kind from proto so wire and IPC representations stay in sync.
pub use fluxsync_proto::Kind;
