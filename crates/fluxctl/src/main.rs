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

mod render;

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
    /// Wake the daemon (Idle → Discovering).
    On,
    /// Sleep the daemon (any phase → Idle).
    Off,
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
    /// Force a reconnection by dropping the current session and starting discovery.
    Reconnect,
    /// Generate a debug capture bundle (stub).
    DebugCapture,
    /// Pair flow.
    Pair {
        #[command(subcommand)]
        sub: PairSub,
    },
}

#[derive(Subcommand, Debug)]
enum PairSub {
    /// Print this device's pair info (peer-id, base32 pubkey, 6 safe-words).
    Show,
    /// Render this device's pair URI as a terminal QR code (Unicode
    /// half-blocks). Also prints the URI and 6 safe-words underneath
    /// so a remote viewer can verify by voice.
    ShowQr,
    /// Trust a peer described by a `fluxsync://pair/...` URI (typically
    /// from a scanned QR). `--name` is required because the URI does
    /// not carry one.
    FromUri {
        #[arg(long)]
        uri: String,
        #[arg(long)]
        name: String,
    },
    /// Trust a remote pubkey + start the handshake.
    /// `--addr` is required when mDNS is unavailable (loopback / first-pair).
    Accept {
        /// Base32 (RFC 4648, no padding) of the peer's 32-byte X25519 pubkey.
        #[arg(long)]
        pubkey: String,
        /// Friendly peer name (shown in status).
        #[arg(long)]
        name: String,
        /// Optional UDP `IP:PORT` of the peer. When provided, the daemon
        /// kicks off the initiator handshake immediately (skips mDNS).
        #[arg(long)]
        addr: Option<String>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let ipc_path = args.ipc_path.unwrap_or_else(default_ipc_path);

    enum Kind {
        Status,
        Peers,
        Tail,
        Pull,
        PairShow,
        PairQr,
        Ack(&'static str),
    }

    let (value, kind) = match args.cmd {
        Cmd::Status => (
            one_shot(&ipc_path, json!({"id": 1, "op": "status"})).await?,
            Kind::Status,
        ),
        Cmd::Peers => (
            one_shot(&ipc_path, json!({"id": 1, "op": "peers"})).await?,
            Kind::Peers,
        ),
        Cmd::Push { text } => (
            one_shot(&ipc_path, json!({"id": 1, "op": "push", "text": text})).await?,
            Kind::Ack("pushed"),
        ),
        Cmd::Pull => (
            one_shot(&ipc_path, json!({"id": 1, "op": "pull"})).await?,
            Kind::Pull,
        ),
        Cmd::Tail { n } => (
            one_shot(&ipc_path, json!({"id": 1, "op": "tail", "n": n})).await?,
            Kind::Tail,
        ),
        Cmd::SetThreshold { value } => (
            one_shot(
                &ipc_path,
                json!({"id": 1, "op": "set_threshold", "value": value}),
            )
            .await?,
            Kind::Ack("threshold updated"),
        ),
        Cmd::SetChargeOverride { value } => (
            one_shot(
                &ipc_path,
                json!({"id": 1, "op": "set_charge_override", "value": value}),
            )
            .await?,
            Kind::Ack("charge override updated"),
        ),
        Cmd::Revoke { peer_id } => (
            one_shot(
                &ipc_path,
                json!({"id": 1, "op": "revoke", "peer_id": peer_id}),
            )
            .await?,
            Kind::Ack("peer revoked"),
        ),
        Cmd::Reconnect => (
            one_shot(&ipc_path, json!({"id": 1, "op": "reconnect"})).await?,
            Kind::Ack("reconnect requested"),
        ),
        Cmd::DebugCapture => (
            one_shot(&ipc_path, json!({"id": 1, "op": "debug_capture"})).await?,
            Kind::Ack("debug capture written"),
        ),
        Cmd::On => (
            one_shot(&ipc_path, json!({"id": 1, "op": "toggle", "on": true})).await?,
            Kind::Ack("daemon ON"),
        ),
        Cmd::Off => (
            one_shot(&ipc_path, json!({"id": 1, "op": "toggle", "on": false})).await?,
            Kind::Ack("daemon OFF"),
        ),
        Cmd::Pair { sub } => match sub {
            PairSub::Show => (
                one_shot(&ipc_path, json!({"id": 1, "op": "pair_show"})).await?,
                Kind::PairShow,
            ),
            PairSub::ShowQr => (
                one_shot(&ipc_path, json!({"id": 1, "op": "pair_show"})).await?,
                Kind::PairQr,
            ),
            PairSub::FromUri { uri, name } => (
                one_shot(
                    &ipc_path,
                    json!({"id": 1, "op": "pair_from_uri", "uri": uri, "name": name}),
                )
                .await?,
                Kind::Ack("pairing accepted"),
            ),
            PairSub::Accept { pubkey, name, addr } => {
                let mut req = json!({
                    "id": 1,
                    "op": "pair_accept",
                    "pubkey_b32": pubkey,
                    "name": name,
                });
                if let Some(a) = addr {
                    req["addr"] = json!(a);
                }
                (one_shot(&ipc_path, req).await?, Kind::Ack("peer trusted"))
            }
        },
    };

    if args.json {
        if let Ok(s) = serde_json::to_string_pretty(&value) {
            println!("{s}");
        }
        return Ok(());
    }

    match kind {
        Kind::Status => render::render_status(&value),
        Kind::Peers => render::render_peers(&value),
        Kind::Tail => render::render_tail(&value),
        Kind::Pull => render::render_pull(&value),
        Kind::PairShow => render::render_pair_show(&value)?,
        Kind::PairQr => render_pair_qr(&value)?,
        Kind::Ack(action) => render::render_ack(&value, action),
    }
    Ok(())
}

/// Render the pair URI as a terminal-friendly QR (Unicode half-blocks)
/// followed by the 6 safe-words and the URI text. The CmdResponse is
/// expected to wrap a `PairInfo` payload.
fn render_pair_qr(resp: &Value) -> Result<()> {
    use qrcode::render::unicode::Dense1x2;
    use qrcode::QrCode;

    let data = resp
        .get("data")
        .ok_or_else(|| anyhow!("response missing data"))?;
    let uri = data
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("response data missing uri"))?;
    let words = data
        .get("fingerprint_words")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let addr = data.get("addr_hint").and_then(Value::as_str).unwrap_or("");

    let code = QrCode::new(uri).map_err(|e| anyhow!("encode qr: {e}"))?;
    let rendered = code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build();

    println!("{rendered}");
    println!("Scan from the peer device, or paste this URI:");
    println!("  {uri}");
    println!("Reachable at: {addr}");
    println!("Verify these words match on both sides:");
    println!("  {words}");
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
    let line = format!("{request}\n");
    write.write_all(line.as_bytes()).await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    reader.read_line(&mut buf).await?;
    let v: Value = serde_json::from_str(buf.trim())?;
    Ok(v)
}

#[cfg(windows)]
async fn one_shot(path: &Path, request: Value) -> Result<Value> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let stream = ClientOptions::new()
        .open(path)
        .with_context(|| format!("connect ipc {}", path.display()))?;
    let (read, mut write) = tokio::io::split(stream);
    write.write_all(b"{\"subscribe\":\"cmd\"}\n").await?;
    let line = format!("{request}\n");
    write.write_all(line.as_bytes()).await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    reader.read_line(&mut buf).await?;
    let v: Value = serde_json::from_str(buf.trim())?;
    Ok(v)
}

fn default_ipc_path() -> PathBuf {
    if cfg!(windows) {
        return PathBuf::from(r"\\.\pipe\fluxsync");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".fluxsync").join("sock");
    }
    PathBuf::from("./fluxsync.sock")
}
