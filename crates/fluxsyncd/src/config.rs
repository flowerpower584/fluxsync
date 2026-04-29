use crate::wall::ChronoWallClock;
use fluxsync_core::WallClock;
use fluxsync_crypto::{Identity, Session};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Daemon-side runtime configuration. Built by `main.rs` from CLI args
/// and the keychain-stored identity, or by integration tests directly.
pub struct DaemonConfig {
    pub identity: Identity,
    pub peer_name_self: String,
    pub udp_port: u16,
    pub udp_bind: String, // e.g. "127.0.0.1" or "0.0.0.0"
    pub ipc_path: PathBuf,
    /// Pre-trusted peer static pubkeys (32 B each) — typically empty at
    /// boot; gets populated at pair-time. Persistence to keychain lands
    /// in v0.1.2.
    pub trusted_peer_keys: Vec<[u8; 32]>,
    pub charge_override: bool,
    pub wall_clock: Arc<dyn WallClock + Send + Sync>,
    /// Skip mDNS service register + browse. Default false. Tests on
    /// loopback (where macOS multicast is unreliable) set this true and
    /// drive pairing with the `pair-accept --addr` manual address path.
    pub disable_mdns: bool,
    /// Test injection: skip discovery + handshake, jump straight to
    /// `Linked` using the pre-paired session below. Production binaries
    /// always set this to `None`. Integration tests use it with
    /// `fluxsync_crypto::test_util::pair_for_test` so sync-path bugs
    /// stay distinguishable from pairing-path bugs.
    pub test_pair: Option<TestPair>,
}

impl DaemonConfig {
    /// Defaults for a production-style boot. `identity`, `udp_port`,
    /// and `ipc_path` are required from the caller; everything else
    /// gets sensible defaults.
    #[must_use]
    pub fn new(identity: Identity, udp_port: u16, ipc_path: PathBuf) -> Self {
        Self {
            identity,
            peer_name_self: hostname_or("this device"),
            udp_port,
            udp_bind: String::from("0.0.0.0"),
            ipc_path,
            trusted_peer_keys: Vec::new(),
            charge_override: true,
            wall_clock: Arc::new(ChronoWallClock),
            disable_mdns: false,
            test_pair: None,
        }
    }
}

/// Test-only injection of a pre-paired peer session.
pub struct TestPair {
    pub session: Session,
    pub peer_addr: SocketAddr,
    pub peer_name: String,
    pub peer_id: [u8; 32],
}

fn hostname_or(default: &str) -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| default.to_string())
}
