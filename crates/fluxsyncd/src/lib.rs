//! FluxSync daemon library — wraps `fluxsync-core`'s `App` with the
//! tokio I/O it needs (IPC server, UDP transport, optional polling
//! tasks). The `main.rs` binary builds a [`DaemonConfig`] from CLI args
//! and calls [`run`].
//!
//! Integration tests construct `DaemonConfig` directly and inject a
//! pre-paired [`fluxsync_crypto::Session`] via [`config::TestPair`] to
//! skip the QR/handshake flow.

pub mod cmd;
pub mod config;
pub mod discovery;
pub mod driver;
pub mod handshake;
pub mod ipc;
pub mod logs;
pub mod transport;
pub mod wall;

pub use config::{DaemonConfig, TestPair};
pub use driver::run;
