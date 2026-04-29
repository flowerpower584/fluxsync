//! `fluxsyncd` — the FluxSync daemon binary.
//!
//! v0.1 boots an unpaired daemon (Idle / Discovering, no peer) so the
//! IPC surface is reachable from `fluxctl` immediately. Pairing wires
//! up a peer in v0.1.1.

use anyhow::{Context, Result};
use clap::Parser;
use fluxsync_crypto::Identity;
use fluxsyncd::{run, DaemonConfig};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Notify;
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

    /// Enable DEBUG-level logging.
    #[arg(long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(args.verbose);

    let ipc_path = args
        .ipc_path
        .unwrap_or_else(|| default_ipc_path().unwrap_or_else(|| PathBuf::from("./fluxsync.sock")));

    // v0.1: identity is regenerated on every boot if the keystore isn't
    // wired up. Persistence (keychain or `~/.fluxsync/identity.bin` with
    // mode 0600) lands in v0.1.1 — the daemon does not crash without it.
    let identity = Identity::generate();
    tracing::info!(
        peer_id = %hex(&identity.peer_id()),
        "fluxsyncd starting (v0.1; unpaired)"
    );

    let mut cfg = DaemonConfig::new(identity, args.udp_port, ipc_path.clone());
    cfg.udp_bind = args.udp_bind;
    if let Some(name) = args.peer_name {
        cfg.peer_name_self = name;
    }

    let shutdown = Arc::new(Notify::new());
    let s2 = shutdown.clone();

    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!("ctrl-c received; shutting down");
                s2.notify_waiters();
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
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(home.join(".fluxsync").join("sock"))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
