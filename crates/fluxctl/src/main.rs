//! `fluxctl` — the FluxSync CLI.
//!
//! Talks to `fluxsyncd` over its IPC socket (UNIX socket on Linux/macOS;
//! Named Pipe on Windows in v0.1.1). Every subcommand supports `--json`
//! to emit machine-readable output suitable for scripting.

#![cfg_attr(windows, allow(dead_code))]

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Parser, Debug)]
#[command(name = "fluxctl", version, about = "FluxSync CLI")]
struct Args {
    /// Override the IPC socket path. Defaults to `~/.fluxsync/sock`.
    #[arg(long, global = true)]
    ipc_path: Option<PathBuf>,

    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print the current daemon state.
    Status,
    /// List paired peers + RTT + battery.
    Peers,
    /// Inject a clipboard item.
    Push { text: String },
    /// Print the most recent peer item.
    Pull,
    /// Show the last `n` log entries.
    Tail {
        #[arg(short = 'n', long, default_value_t = 20)]
        n: usize,
    },
    /// Set the battery threshold (5..=50).
    SetThreshold { value: u8 },
    /// Toggle the "resume while charging" override.
    SetChargeOverride { value: bool },
    /// Revoke a peer by hex peer-id.
    Revoke { peer_id: String },
    /// Generate a debug capture bundle (stub in v0.1).
    DebugCapture,
    /// QR-pair on the LAN (stub in v0.1).
    Pair {
        #[command(subcommand)]
        sub: PairSub,
    },
}

#[derive(Subcommand, Debug)]
enum PairSub {
    Qr,
    Accept,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let ipc_path = args.ipc_path.unwrap_or_else(default_ipc_path);

    let value = match args.cmd {
        Cmd::Status => one_shot(&ipc_path, json!({"id": 1, "op": "status"})).await?,
        Cmd::Peers => one_shot(&ipc_path, json!({"id": 1, "op": "peers"})).await?,
        Cmd::Push { text } => {
            one_shot(&ipc_path, json!({"id": 1, "op": "push", "text": text})).await?
        }
        Cmd::Pull => one_shot(&ipc_path, json!({"id": 1, "op": "pull"})).await?,
        Cmd::Tail { n } => one_shot(&ipc_path, json!({"id": 1, "op": "tail", "n": n})).await?,
        Cmd::SetThreshold { value } => {
            one_shot(
                &ipc_path,
                json!({"id": 1, "op": "set_threshold", "value": value}),
            )
            .await?
        }
        Cmd::SetChargeOverride { value } => {
            one_shot(
                &ipc_path,
                json!({"id": 1, "op": "set_charge_override", "value": value}),
            )
            .await?
        }
        Cmd::Revoke { peer_id } => {
            one_shot(
                &ipc_path,
                json!({"id": 1, "op": "revoke", "peer_id": peer_id}),
            )
            .await?
        }
        Cmd::DebugCapture => one_shot(&ipc_path, json!({"id": 1, "op": "debug_capture"})).await?,
        Cmd::Pair { sub: _ } => {
            return Err(anyhow!(
                "v0.1: pairing not yet implemented; use the test harness or wait for v0.1.1"
            ));
        }
    };

    print(&value, args.json);
    Ok(())
}

#[cfg(unix)]
async fn one_shot(path: &Path, request: Value) -> Result<Value> {
    use tokio::net::UnixStream;
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connect ipc {}", path.display()))?;
    let (read, mut write) = stream.into_split();
    write.write_all(b"{\"subscribe\":\"cmd\"}\n").await?;
    let line = format!("{}\n", request);
    write.write_all(line.as_bytes()).await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    reader.read_line(&mut buf).await?;
    let v: Value = serde_json::from_str(buf.trim())?;
    Ok(v)
}

#[cfg(windows)]
async fn one_shot(_path: &Path, _request: Value) -> Result<Value> {
    Err(anyhow!(
        "Windows IPC is not implemented in v0.1; v0.1.1 will land Named Pipes"
    ))
}

fn print(v: &Value, json: bool) {
    if json {
        match serde_json::to_string_pretty(v) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("json render error: {e}"),
        }
        return;
    }
    // Human-readable fallback: just pretty-print the response. The shape
    // is small enough that JSON is already readable.
    if let Ok(s) = serde_json::to_string_pretty(v) {
        println!("{s}");
    }
}

fn default_ipc_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".fluxsync").join("sock");
    }
    PathBuf::from("./fluxsync.sock")
}
