use crate::wall::ChronoWallClock;
use fluxsync_core::WallClock;
use fluxsync_crypto::{Identity, Session};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Daemon-side runtime configuration. Built by `main.rs` from CLI args
/// and the keychain-stored identity, or by integration tests directly.
#[allow(clippy::struct_excessive_bools)]
pub struct DaemonConfig {
    pub identity: Identity,
    pub peer_name_self: String,
    pub udp_port: u16,
    pub udp_bind: String, // e.g. "127.0.0.1" or "0.0.0.0"
    pub ipc_path: PathBuf,
    /// Pre-trusted peer static pubkeys (32 B each) — typically empty at
    /// boot; gets populated at pair-time. Persistence to keychain lands
    /// in v0.1.3.
    pub trusted_peer_keys: Vec<[u8; 32]>,
    /// Directory used by [`crate::keystore`] for `identity.bin` and
    /// `peers.json`. `None` disables persistence (used by integration
    /// tests with `test_pair`).
    pub keystore_dir: Option<PathBuf>,
    pub charge_override: bool,
    pub disable_clipboard: bool,
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
    /// If true, the daemon fires `Event::ToggleOn` immediately at boot.
    /// Used by the "State-Aware Boot" logic: if the daemon finds
    /// existing peers in `peers.json`, it starts syncing automatically.
    pub start_on: bool,
    pub last_peer_addr: Option<SocketAddr>,
    pub test_pair: Option<TestPair>,
    /// Test injection: pre-populate the `PendingSet` so a test can drive
    /// `PairConfirm` without running the real handshake. Production
    /// binaries always set this to `None`.
    pub test_pending_pair: Option<TestPendingPair>,
    /// FS-059 + H2 (Phase 3 audit): reject EVERY UDP datagram whose
    /// source IP is not on a private / link-local / loopback range.
    /// Default `true` because the product is LAN clipboard sync —
    /// any routable WAN source is almost certainly hostile and would
    /// otherwise reach the Noise parser, the replay window, or the
    /// `mdns-sd` packet decoder.
    ///
    /// Despite the field name (kept for compat), the filter is no
    /// longer scoped to handshakes — see `driver::run`'s receive
    /// loop. Users who genuinely want public-internet pairing (VPN,
    /// IPv6 ULAs, etc.) can flip this off and accept that all four
    /// `RecvFrame` variants will then be processed from any source.
    pub lan_only_handshakes: bool,
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
            keystore_dir: None,
            charge_override: true,
            disable_clipboard: false,
            wall_clock: Arc::new(ChronoWallClock),
            disable_mdns: false,
            start_on: false,
            last_peer_addr: None,
            test_pair: None,
            test_pending_pair: None,
            lan_only_handshakes: true,
        }
    }
}

/// FS-059: classify a source `IpAddr` as "on a local network we should
/// accept handshakes from". Accepts:
/// * loopback (127.0.0.0/8, ::1)
/// * IPv4 private (RFC 1918) and link-local (169.254/16)
/// * IPv6 unique-local (fc00::/7) and link-local (fe80::/10)
#[must_use]
pub fn is_local_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            // L-DAEMON-10: a LAN IPv4 peer arriving on a dual-stack `::` socket
            // appears as `::ffff:a.b.c.d`. Unwrap the embedded IPv4 and classify
            // that, else a `bind = ::` daemon rejects every IPv4 LAN handshake.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_private() || v4.is_link_local();
            }
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
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

/// Test-only injection of an entry into the `PendingSet`.
pub struct TestPendingPair {
    pub peer_id: [u8; 32],
    pub static_pub: [u8; 32],
    pub name: String,
    pub sas_words: [String; 6],
    pub from: SocketAddr,
    pub expires_in: std::time::Duration,
}

fn hostname_or(default: &str) -> String {
    // A device name that parses as an IP address is useless to show a
    // peer. macOS in particular often sets the POSIX hostname to the
    // DHCP-assigned address, so reject anything that looks like an IP.
    fn usable(s: &str) -> bool {
        !s.is_empty() && s.parse::<std::net::IpAddr>().is_err()
    }

    // macOS: the POSIX hostname is frequently the DHCP IP. The
    // user-facing device name lives in SystemConfiguration — `scutil`
    // is the simplest reliable way to read it ("Dethie's MacBook Pro").
    #[cfg(target_os = "macos")]
    if let Ok(out) = std::process::Command::new("/usr/sbin/scutil")
        .args(["--get", "ComputerName"])
        .output()
    {
        if let Ok(s) = String::from_utf8(out.stdout) {
            let s = s.trim();
            if usable(s) {
                return s.to_string();
            }
        }
    }

    // The `HOSTNAME` / `COMPUTERNAME` env vars are often unset on macOS.
    if let Ok(name) = std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")) {
        if usable(&name) {
            return name;
        }
    }
    // Fall back to the POSIX gethostname() via the `nix` crate (safe wrapper).
    #[cfg(unix)]
    if let Ok(name) = nix::unistd::gethostname() {
        if let Some(s) = name.to_str() {
            if usable(s) {
                return s.to_string();
            }
        }
    }
    default.to_string()
}
