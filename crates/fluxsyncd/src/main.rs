//! `fluxsyncd` — the FluxSync daemon binary.
//!
//! v0.1 boots an unpaired daemon (Idle / Discovering, no peer) so the
//! IPC surface is reachable from `fluxctl` immediately. Pairing wires
//! up a peer in v0.1.1.

use anyhow::{Context, Result};
use clap::Parser;
use fluxsyncd::{keystore, run, DaemonConfig};
use std::path::PathBuf;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "fluxsyncd", version, about = "FluxSync daemon")]
struct Args {
    /// IPC socket path. Defaults to `~/.fluxsync/sock` on unix.
    #[arg(long)]
    ipc_path: Option<PathBuf>,

    /// UDP port to listen on for peer datagrams.
    #[arg(long, default_value_t = 41889)]
    udp_port: u16,

    /// UDP bind address.
    #[arg(long, default_value = "0.0.0.0")]
    udp_bind: String,

    /// Friendly name for this device (shown to the peer).
    #[arg(long)]
    peer_name: Option<String>,

    /// Keystore directory (`identity.bin`, `peers.json`). Defaults to
    /// `~/.fluxsync`.
    #[arg(long)]
    keystore_dir: Option<PathBuf>,

    /// Enable DEBUG-level logging.
    #[arg(long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = sentry::init(("https://9c9d519251cf44cc9149f318b383f4f5@o4511345219600384.ingest.de.sentry.io/4511345258659920", sentry::ClientOptions {
        release: sentry::release_name!(),
        send_default_pii: true,
        ..Default::default()
    }));

    let args = Args::parse();
    init_tracing(args.verbose);

    let ipc_path = args
        .ipc_path
        .unwrap_or_else(|| default_ipc_path().unwrap_or_else(|| PathBuf::from("./fluxsync.sock")));

    let keystore_dir = args
        .keystore_dir
        .or_else(default_keystore_dir)
        .unwrap_or_else(|| PathBuf::from("./fluxsync-keystore"));

    let identity = keystore::load_or_create_identity(&keystore_dir)
        .with_context(|| format!("init keystore at {}", keystore_dir.display()))?;
    tracing::info!(
        peer_id = %hex(&identity.peer_id()),
        keystore = %keystore_dir.display(),
        "fluxsyncd starting"
    );

    let mut cfg = DaemonConfig::new(identity, args.udp_port, ipc_path.clone());
    cfg.udp_bind = args.udp_bind;
    cfg.keystore_dir = Some(keystore_dir.clone());
    if let Some(name) = args.peer_name {
        cfg.peer_name_self = name;
    }

    // Load persisted peers from the keystore. If the daemon has previously
    // paired peers, populate `trusted_peer_keys` so the Noise handshake
    // recognises them on reconnect, and set `start_on = true` so the FSM
    // auto-starts into Discovering without requiring a manual toggle.
    match keystore::load_peers(&keystore_dir) {
        Ok(stored) => {
            for sp in &stored {
                if let Ok(bytes) = hex::decode(&sp.static_pub_hex) {
                    if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        cfg.trusted_peer_keys.push(arr);

                        // v0.1.1 Intelligence: if we have a last known address,
                        // seed the transport's roaming history so we can probe it immediately.
                        if let Some(addr_str) = &sp.last_addr {
                            if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
                                cfg.last_peer_addr = Some(addr);
                            }
                        }

                        tracing::info!(
                            peer = %sp.name,
                            peer_id = %sp.peer_id_hex,
                            last_addr = ?sp.last_addr,
                            "loaded trusted peer from keystore"
                        );
                    }
                }
            }
            if !stored.is_empty() {
                cfg.start_on = true;
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to load peers.json; starting unpaired"),
    }

    let shutdown = CancellationToken::new();
    let s2 = shutdown.clone();

    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!("ctrl-c received; shutting down");
                s2.cancel();
            }
            Err(e) => tracing::error!(error = %e, "ctrl-c handler failed"),
        }
    });

    run(cfg, shutdown).await.context("daemon main loop failed")
}

fn init_tracing(verbose: bool) {
    let default_filter = if verbose { "debug" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .json()
        .init();
}

fn default_ipc_path() -> Option<PathBuf> {
    if cfg!(windows) {
        return Some(PathBuf::from(r"\\.\pipe\fluxsync"));
    }
    let home = dirs::home_dir()?;
    Some(home.join(".fluxsync").join("sock"))
}

/// Default keystore directory: `$HOME/.fluxsync`. Returns `None` when
/// `HOME` is unset (very rare; mostly happens inside `cargo test`'s
/// sandbox or some CI runners), in which case `main` falls back to a
/// CWD-relative path so the daemon still boots.
fn default_keystore_dir() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".fluxsync"))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
