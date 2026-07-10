//! `fluxctl` — the FluxSync CLI.
//!
//! Talks to `fluxsyncd` over its IPC socket (UNIX socket on Linux/macOS;
//! Named Pipe on Windows in v0.1.1). Every subcommand supports `--json`
//! to emit machine-readable output suitable for scripting.

#![cfg_attr(windows, allow(dead_code))]

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

mod doctor;
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
    /// Inject an image clipboard item read from a PNG file on disk.
    PushImage {
        /// Path to a PNG file.
        path: PathBuf,
        /// Mark this image as sensitive: it still syncs to the peer, but is
        /// excluded from history, the on-disk vault, and the resync outbox
        /// on both ends — same treatment as a detected-secret text item.
        /// There is no image-content classifier, so this is the only way
        /// to flag a pushed image as sensitive.
        #[arg(long)]
        sensitive: bool,
    },
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
    /// Rename this device. An already-linked peer sees the new name on the
    /// next session establishment, not immediately.
    SetName { name: String },
    /// Revoke a peer by hex peer-id.
    Revoke { peer_id: String },
    /// Force a reconnection by dropping the current session and starting discovery.
    Reconnect,
    /// Pin (or unpin) a history item as a favorite, by its hex content hash
    /// (from `status`/history). Favorites are exempt from the vault's TTL
    /// and disk cap.
    Favorite {
        /// Hex content hash (from `status`/history).
        hash: String,
        /// Unpin instead of pinning.
        #[arg(long)]
        remove: bool,
    },
    /// Drop EVERY trusted peer and reset local state. Global — unlike
    /// `revoke`, which targets one peer-id, this clears the whole trust
    /// store. Requires `--yes` to confirm.
    Unpair {
        #[arg(long)]
        yes: bool,
    },
    /// Cleanly stop the daemon process.
    Shutdown,
    /// Pair flow.
    Pair {
        #[command(subcommand)]
        sub: PairSub,
    },
    /// Trust-store inspection (everything the daemon will *talk to*, not
    /// just the active session). H2: `fluxctl peers` only shows the
    /// active link; this surfaces the rest of `peers.json` so a silent
    /// `pair from-uri` cannot hide.
    Trust {
        #[command(subcommand)]
        sub: TrustSub,
    },
    /// Clipboard firewall: per-content-type Always/Ask/Never policy.
    Firewall {
        #[command(subcommand)]
        sub: FirewallSub,
    },
    /// Clipboard history management.
    History {
        #[command(subcommand)]
        sub: HistorySub,
    },
    /// One-shot diagnostic: why isn't sync working? Exits 0 unless a check
    /// FAILs (WARNs are allowed).
    Doctor,
}

#[derive(Subcommand, Debug)]
enum FirewallSub {
    /// Show the current policy and any items awaiting approval.
    Show,
    /// Turn the firewall on (rules take effect).
    Enable,
    /// Turn the firewall off (everything syncs, as before).
    Disable,
    /// Set one rule, e.g. `fluxctl firewall set sensitive never`.
    Set {
        /// Which content type (or `sensitive` for detected secrets).
        field: FwField,
        /// always = sync silently, ask = hold for approval, never = drop.
        rule: FwRule,
    },
    /// List items the Ask rule is currently holding.
    Pending,
    /// Approve a held item by its hex hash (from `firewall pending`).
    Allow { hash: String },
    /// Reject a held item by its hex hash.
    Deny { hash: String },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum FwField {
    Text,
    Url,
    Code,
    Image,
    Sensitive,
}

impl FwField {
    fn key(self) -> &'static str {
        match self {
            FwField::Text => "text",
            FwField::Url => "url",
            FwField::Code => "code",
            FwField::Image => "image",
            FwField::Sensitive => "sensitive",
        }
    }
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum FwRule {
    Always,
    Ask,
    Never,
}

impl FwRule {
    /// Wire value of the rule (matches `core::policy::Rule`'s serde).
    fn wire(self) -> &'static str {
        match self {
            FwRule::Always => "allow",
            FwRule::Ask => "ask",
            FwRule::Never => "deny",
        }
    }
}

#[derive(Subcommand, Debug)]
enum HistorySub {
    /// Clear clipboard history. Local-only — never propagated to the peer.
    /// Favorited items are kept unless `--all` is passed.
    Clear {
        /// Also delete favorited items.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand, Debug)]
enum TrustSub {
    /// Print every peer the daemon trusts (peer-id, name, base32 pubkey).
    List,
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
    /// Trust a peer by the 6-digit PIN its `pair show` advertises over
    /// mDNS. The daemon matches it against the live discovery cache and
    /// pairs like `pair from-uri`. A verify-words confirm (`pair pending`
    /// + `pair confirm`) is mandatory afterwards.
    FromPin {
        #[arg(long)]
        pin: String,
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
    /// FS-052: list peers that landed in the trusted set via the TOFU
    /// window but have not yet been verbally confirmed. Each row carries
    /// the 6-word SAS to compare with the peer device.
    Pending,
    /// FS-052: confirm or reject a pending pair by peer-id.
    Confirm {
        /// Hex peer-id from `pair pending`.
        peer_id: String,
        /// Keep the peer in the trusted set.
        #[arg(long, conflicts_with = "reject")]
        accept: bool,
        /// Revoke the peer (drops live session + removes from peers.json).
        #[arg(long, conflicts_with = "accept")]
        reject: bool,
    },
}

#[tokio::main(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    enum Kind {
        Status,
        Peers,
        Tail,
        Pull,
        PairShow,
        PairQr,
        PairPending,
        TrustList,
        Firewall,
        FirewallPending,
        Ack(&'static str),
    }

    let args = Args::parse();
    let ipc_path = args.ipc_path.unwrap_or_else(default_ipc_path);

    let (value, kind) = match args.cmd {
        // `doctor` has no daemon-side counterpart and its own exit-code
        // contract (0 unless a check FAILs), so it bypasses the shared
        // one_shot/render pipeline entirely.
        Cmd::Doctor => {
            let ok = doctor::run(&ipc_path, args.json).await?;
            std::process::exit(i32::from(!ok));
        }
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
        Cmd::PushImage { path, sensitive } => {
            let bytes = tokio::fs::read(&path)
                .await
                .with_context(|| format!("reading image file {}", path.display()))?;
            (
                one_shot(
                    &ipc_path,
                    json!({
                        "id": 1,
                        "op": "push_image",
                        "data": B64.encode(&bytes),
                        "sensitive": sensitive,
                    }),
                )
                .await?,
                Kind::Ack("image pushed"),
            )
        }
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
        Cmd::SetName { name } => (
            one_shot(
                &ipc_path,
                json!({"id": 1, "op": "set_device_name", "name": name}),
            )
            .await?,
            Kind::Ack("device renamed"),
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
        Cmd::Favorite { hash, remove } => {
            let favorite = !remove;
            (
                one_shot(
                    &ipc_path,
                    json!({"id": 1, "op": "set_favorite", "hash": hash, "favorite": favorite}),
                )
                .await?,
                Kind::Ack(if favorite { "favorited" } else { "unfavorited" }),
            )
        }
        Cmd::Unpair { yes } => {
            if !yes {
                return Err(anyhow!(
                    "this drops EVERY trusted peer; pass --yes to confirm"
                ));
            }
            (
                one_shot(&ipc_path, json!({"id": 1, "op": "unpair"})).await?,
                Kind::Ack("unpaired (all trusted peers dropped)"),
            )
        }
        Cmd::Shutdown => (
            one_shot(&ipc_path, json!({"id": 1, "op": "shutdown"})).await?,
            Kind::Ack("shutdown requested"),
        ),
        Cmd::On => (
            one_shot(&ipc_path, json!({"id": 1, "op": "toggle", "on": true})).await?,
            Kind::Ack("daemon ON"),
        ),
        Cmd::Off => (
            one_shot(&ipc_path, json!({"id": 1, "op": "toggle", "on": false})).await?,
            Kind::Ack("daemon OFF"),
        ),
        Cmd::Trust { sub } => match sub {
            TrustSub::List => (
                one_shot(&ipc_path, json!({"id": 1, "op": "trust_list"})).await?,
                Kind::TrustList,
            ),
        },
        Cmd::Firewall { sub } => match sub {
            FirewallSub::Show => (
                one_shot(&ipc_path, json!({"id": 1, "op": "status"})).await?,
                Kind::Firewall,
            ),
            FirewallSub::Pending => (
                one_shot(&ipc_path, json!({"id": 1, "op": "status"})).await?,
                Kind::FirewallPending,
            ),
            FirewallSub::Allow { hash } => (
                one_shot(
                    &ipc_path,
                    json!({"id": 1, "op": "resolve_pending", "hash": hash, "allow": true}),
                )
                .await?,
                Kind::Ack("approved"),
            ),
            FirewallSub::Deny { hash } => (
                one_shot(
                    &ipc_path,
                    json!({"id": 1, "op": "resolve_pending", "hash": hash, "allow": false}),
                )
                .await?,
                Kind::Ack("rejected"),
            ),
            FirewallSub::Enable => {
                let mut fw = fetch_firewall(&ipc_path).await?;
                fw["enabled"] = json!(true);
                (
                    one_shot(
                        &ipc_path,
                        json!({"id": 1, "op": "set_firewall", "policy": fw}),
                    )
                    .await?,
                    Kind::Ack("firewall enabled"),
                )
            }
            FirewallSub::Disable => {
                let mut fw = fetch_firewall(&ipc_path).await?;
                fw["enabled"] = json!(false);
                (
                    one_shot(
                        &ipc_path,
                        json!({"id": 1, "op": "set_firewall", "policy": fw}),
                    )
                    .await?,
                    Kind::Ack("firewall disabled"),
                )
            }
            FirewallSub::Set { field, rule } => {
                let mut fw = fetch_firewall(&ipc_path).await?;
                fw[field.key()] = json!(rule.wire());
                (
                    one_shot(
                        &ipc_path,
                        json!({"id": 1, "op": "set_firewall", "policy": fw}),
                    )
                    .await?,
                    Kind::Ack("rule updated"),
                )
            }
        },
        Cmd::History { sub } => match sub {
            HistorySub::Clear { all } => (
                one_shot(
                    &ipc_path,
                    json!({"id": 1, "op": "clear_history", "include_favorites": all}),
                )
                .await?,
                Kind::Ack("history cleared"),
            ),
        },
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
            PairSub::FromPin { pin, name } => (
                one_shot(
                    &ipc_path,
                    json!({"id": 1, "op": "pair_from_pin", "pin": pin, "name": name}),
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
            PairSub::Pending => (
                one_shot(&ipc_path, json!({"id": 1, "op": "pair_pending"})).await?,
                Kind::PairPending,
            ),
            PairSub::Confirm {
                peer_id,
                accept,
                reject,
            } => {
                if !accept && !reject {
                    return Err(anyhow!("must pass --accept or --reject"));
                }
                let label = if accept {
                    "pair confirmed"
                } else {
                    "pair rejected"
                };
                (
                    one_shot(
                        &ipc_path,
                        json!({
                            "id": 1,
                            "op": "pair_confirm",
                            "peer_id": peer_id,
                            "accept": accept,
                        }),
                    )
                    .await?,
                    Kind::Ack(label),
                )
            }
        },
    };

    // Every subcommand above shares one response shape (`CmdResponse`:
    // `{id, ok, data, err}`), so the exit-code decision lives here once
    // instead of in each renderer. A daemon-side rejection (oversized
    // push, bad firewall rule, etc.) must make the process exit non-zero
    // so scripts piping `fluxctl` don't see false success.
    let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(false);

    if args.json {
        if let Ok(s) = serde_json::to_string_pretty(&value) {
            println!("{s}");
        }
        return if ok {
            Ok(())
        } else {
            Err(anyhow!(daemon_err(&value)))
        };
    }

    match kind {
        Kind::Status => render::render_status(&value),
        Kind::Peers => render::render_peers(&value),
        Kind::Tail => render::render_tail(&value),
        Kind::Pull => render::render_pull(&value),
        Kind::PairShow => render::render_pair_show(&value)?,
        Kind::PairQr => render_pair_qr(&value)?,
        Kind::PairPending => render_pair_pending(&value),
        Kind::TrustList => render_trust_list(&value),
        Kind::Firewall => render_firewall(&value),
        Kind::FirewallPending => render_firewall_pending(&value),
        Kind::Ack(action) => render::render_ack(&value, action),
    }
    if ok {
        Ok(())
    } else {
        Err(anyhow!(daemon_err(&value)))
    }
}

/// Pull the daemon's error string out of an `ok: false` `CmdResponse`,
/// falling back to a generic message if the response is malformed.
fn daemon_err(resp: &Value) -> String {
    resp.get("err")
        .and_then(Value::as_str)
        .unwrap_or("daemon rejected request")
        .to_string()
}

/// Fetch the current firewall policy object from the daemon's State, so a
/// single-rule change (enable/disable/set) is a read-modify-write that leaves
/// the other rules untouched. Falls back to the disabled default shape if the
/// daemon predates the firewall.
async fn fetch_firewall(ipc: &Path) -> Result<Value> {
    let resp = one_shot(ipc, json!({"id": 1, "op": "status"})).await?;
    let fw = resp
        .get("data")
        .and_then(|d| d.get("firewall"))
        .cloned()
        .unwrap_or(Value::Null);
    if fw.is_object() {
        Ok(fw)
    } else {
        Ok(json!({
            "enabled": false,
            "text": "allow",
            "url": "allow",
            "code": "allow",
            "image": "allow",
            "sensitive": "ask",
        }))
    }
}

/// Map a wire rule (`allow`/`ask`/`deny`) to the UI word.
fn rule_word(wire: &str) -> &str {
    match wire {
        "ask" => "Ask",
        "deny" => "Never",
        _ => "Always",
    }
}

/// Render `firewall show`: the on/off state + each content-type rule.
fn render_firewall(resp: &Value) {
    if resp.get("ok").and_then(Value::as_bool) != Some(true) {
        let err = resp.get("err").and_then(Value::as_str).unwrap_or("unknown");
        eprintln!("error: {err}");
        return;
    }
    let fw = resp.get("data").and_then(|d| d.get("firewall"));
    let Some(fw) = fw else {
        println!("Firewall: unavailable (daemon predates the firewall).");
        return;
    };
    let enabled = fw.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    println!("Firewall: {}", if enabled { "ON" } else { "off" });
    for field in ["text", "url", "code", "image", "sensitive"] {
        let wire = fw.get(field).and_then(Value::as_str).unwrap_or("allow");
        println!("  {field:<10} {}", rule_word(wire));
    }
    let pending = resp
        .get("data")
        .and_then(|d| d.get("pending"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if pending > 0 {
        println!("\n{pending} item(s) awaiting approval — `fluxctl firewall pending`.");
    }
}

/// Render `firewall pending`: items the Ask rule is holding.
fn render_firewall_pending(resp: &Value) {
    if resp.get("ok").and_then(Value::as_bool) != Some(true) {
        let err = resp.get("err").and_then(Value::as_str).unwrap_or("unknown");
        eprintln!("error: {err}");
        return;
    }
    let items = resp
        .get("data")
        .and_then(|d| d.get("pending"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        println!("Nothing awaiting approval.");
        return;
    }
    println!("Awaiting approval ({n}):", n = items.len());
    for it in &items {
        let dir = it.get("direction").and_then(Value::as_str).unwrap_or("?");
        let arrow = if dir == "outbound" {
            "→ out"
        } else {
            "← in "
        };
        let kind = it.get("kind").and_then(Value::as_str).unwrap_or("?");
        let preview = it.get("preview").and_then(Value::as_str).unwrap_or("");
        let hash = it.get("hash").and_then(Value::as_str).unwrap_or("");
        let short = hash.get(..12).unwrap_or(hash);
        println!("  {arrow}  {kind:<5} {short}  {preview}");
    }
    println!("\nApprove: `fluxctl firewall allow <hash>`   Reject: `fluxctl firewall deny <hash>`");
}

/// H2: render the trust-store listing. One entry per persisted peer,
/// with peer-id (full hex, suitable for `fluxctl revoke`), name, and
/// the base32 pubkey for cross-checking against the peer's
/// `fluxctl pair show`. Sensitive fields stay on disk only; this view
/// is the user's primary defence against silent extra-trust.
fn render_trust_list(resp: &Value) {
    if resp.get("ok").and_then(Value::as_bool) != Some(true) {
        let err = resp.get("err").and_then(Value::as_str).unwrap_or("unknown");
        eprintln!("error: {err}");
        return;
    }
    let entries = resp
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        println!("Trust store empty. Pair a device with `fluxctl pair show-qr`.");
        return;
    }
    println!("Trusted peers ({n}):", n = entries.len());
    println!();
    for e in entries {
        let id = e.get("peer_id_hex").and_then(Value::as_str).unwrap_or("?");
        let name = e.get("name").and_then(Value::as_str).unwrap_or("");
        let pk = e
            .get("static_pub_hex")
            .and_then(Value::as_str)
            .unwrap_or("?");
        println!("name    : {name}");
        println!("peer-id : {id}");
        println!("pubkey  : {pk}");
        println!();
    }
    println!("To remove an entry: fluxctl revoke <peer-id>");
}

/// Render FS-052 pending-pair listing: one row per unconfirmed peer with
/// the SAS the user must compare against the other device.
fn render_pair_pending(resp: &Value) {
    if resp.get("ok").and_then(Value::as_bool) != Some(true) {
        let err = resp.get("err").and_then(Value::as_str).unwrap_or("unknown");
        eprintln!("error: {err}");
        return;
    }
    let entries = resp
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        println!("No pending pairs.");
        return;
    }
    println!("Pending pairs — verify the SAS matches on the OTHER device,");
    println!("then run: fluxctl pair confirm <peer-id> --accept | --reject");
    println!();
    for e in entries {
        let id = e.get("peer_id").and_then(Value::as_str).unwrap_or("?");
        let name = e.get("name").and_then(Value::as_str).unwrap_or("");
        let addr = e.get("addr").and_then(Value::as_str).unwrap_or("(unknown)");
        let words = e
            .get("sas_words")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let ttl_ms = e.get("expires_in_ms").and_then(Value::as_u64).unwrap_or(0);
        println!("peer-id : {id}");
        println!("name    : {name}");
        println!("addr    : {addr}");
        println!("sas     : {words}");
        println!("expires : {}s", ttl_ms / 1000);
        println!();
    }
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

/// C2: validate the IPC socket path before we hand it any data.
///
/// Original exploit: `fluxctl --ipc-path /tmp/evil.sock push <secret>`
/// would happily ship the secret to anyone listening on that socket
/// because fluxctl never authenticated the other end. Worse: any local
/// account that races a fake socket into `~/.fluxsync/sock` (or symlinks
/// the path elsewhere) could harvest every `push` text in clear.
///
/// Defense-in-depth applied here:
/// 1. `symlink_metadata` — refuse to traverse a symlink. The default
///    path is `$HOME/.fluxsync/sock`; if it became a symlink someone
///    is staging an attack.
/// 2. File type must be a UNIX socket.
/// 3. Socket owner UID must equal the caller's UID. Stops a different
///    user on a shared machine impersonating the daemon.
///
/// This does *not* defend against same-UID malware that bound a fake
/// socket and replaced the real path before fluxctl ran — that needs a
/// daemon-side authentication challenge (separate fix).
#[cfg(unix)]
fn validate_ipc_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat ipc socket {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "ipc path {} is a symlink; refusing to follow (potential redirect attack). \
             Remove the link or pass the canonical path.",
            path.display()
        ));
    }
    if !meta.file_type().is_socket() {
        return Err(anyhow!(
            "ipc path {} is not a UNIX socket (type {:?})",
            path.display(),
            meta.file_type()
        ));
    }
    let me = u64::from(nix::unistd::Uid::current().as_raw());
    let owner = u64::from(meta.uid());
    if owner != me {
        return Err(anyhow!(
            "ipc socket {} owned by uid {} but caller is uid {}; refusing to send. \
             Either run as the daemon's user or fix the socket ownership.",
            path.display(),
            owner,
            me
        ));
    }
    Ok(())
}

/// The daemon caps inbound IPC lines at 64 MiB (`fluxsyncd`'s `MAX_IPC_LINE`
/// in `driver.rs`). Mirror that cap on the client side of the same
/// connection so a wedged or hostile daemon can't grow our read buffer
/// unbounded while we wait for a newline.
const MAX_IPC_LINE: usize = 64 * 1024 * 1024;

/// Capped line read, mirroring `fluxsyncd`'s own `read_line_capped`: reads
/// up to `max` bytes looking for a newline, erroring out instead of growing
/// `out` forever if the peer never sends one.
async fn read_line_capped<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    out: &mut String,
    max: usize,
) -> std::io::Result<usize> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            break; // EOF
        }
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if bytes.len() + take > max {
            reader.consume(take);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IPC response line exceeds max length",
            ));
        }
        bytes.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        if done {
            break;
        }
    }
    out.push_str(&String::from_utf8_lossy(&bytes));
    Ok(bytes.len())
}

#[cfg(unix)]
async fn one_shot(path: &Path, request: Value) -> Result<Value> {
    use tokio::net::UnixStream;
    validate_ipc_socket(path)?;
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
    read_line_capped(&mut reader, &mut buf, MAX_IPC_LINE).await?;
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
    read_line_capped(&mut reader, &mut buf, MAX_IPC_LINE).await?;
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

#[cfg(test)]
mod ipc_read_tests {
    use super::{read_line_capped, MAX_IPC_LINE};
    use tokio::io::BufReader;

    #[tokio::test]
    async fn reads_a_normal_line() {
        let mut reader = BufReader::new(std::io::Cursor::new(b"hello\n".to_vec()));
        let mut buf = String::new();
        let n = read_line_capped(&mut reader, &mut buf, MAX_IPC_LINE)
            .await
            .unwrap();
        assert_eq!(n, 6);
        assert_eq!(buf, "hello\n");
    }

    #[tokio::test]
    async fn errors_when_line_exceeds_cap() {
        let mut reader = BufReader::new(std::io::Cursor::new(b"0123456789\n".to_vec()));
        let mut buf = String::new();
        let err = read_line_capped(&mut reader, &mut buf, 5)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn eof_without_newline_returns_partial_line() {
        let mut reader = BufReader::new(std::io::Cursor::new(b"no newline".to_vec()));
        let mut buf = String::new();
        let n = read_line_capped(&mut reader, &mut buf, MAX_IPC_LINE)
            .await
            .unwrap();
        assert_eq!(n, 10);
        assert_eq!(buf, "no newline");
    }
}

/// DIR-P3-09: parse-level coverage for the new/changed subcommands. These
/// only exercise clap's own parsing (arity, flags, conflicts) — the
/// dispatch match itself needs a live daemon and is covered by the
/// integration tests instead.
#[cfg(test)]
mod cli_parse_tests {
    use super::{Args, Cmd, PairSub};
    use clap::Parser;

    fn parse(args: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once(&"fluxctl").chain(args))
            .unwrap_or_else(|e| panic!("failed to parse {args:?}: {e}"))
    }

    #[test]
    fn favorite_defaults_to_pinning() {
        let a = parse(&["favorite", "abc123"]);
        match a.cmd {
            Cmd::Favorite { hash, remove } => {
                assert_eq!(hash, "abc123");
                assert!(!remove, "no --remove must default to pinning");
            }
            other => panic!("expected Cmd::Favorite, got {other:?}"),
        }
    }

    #[test]
    fn favorite_remove_flag_parses() {
        let a = parse(&["favorite", "abc123", "--remove"]);
        match a.cmd {
            Cmd::Favorite { remove, .. } => assert!(remove),
            other => panic!("expected Cmd::Favorite, got {other:?}"),
        }
    }

    #[test]
    fn unpair_without_yes_still_parses() {
        // The --yes confirmation gate is a runtime check (main's dispatch),
        // not a clap requirement — `unpair` alone must parse fine so the
        // gate can produce a clear error message instead of a clap usage
        // error.
        let a = parse(&["unpair"]);
        match a.cmd {
            Cmd::Unpair { yes } => assert!(!yes),
            other => panic!("expected Cmd::Unpair, got {other:?}"),
        }
    }

    #[test]
    fn unpair_yes_flag_parses() {
        let a = parse(&["unpair", "--yes"]);
        match a.cmd {
            Cmd::Unpair { yes } => assert!(yes),
            other => panic!("expected Cmd::Unpair, got {other:?}"),
        }
    }

    #[test]
    fn shutdown_parses() {
        let a = parse(&["shutdown"]);
        assert!(matches!(a.cmd, Cmd::Shutdown));
    }

    #[test]
    fn pair_from_pin_parses_required_flags() {
        let a = parse(&["pair", "from-pin", "--pin", "123456", "--name", "Phone"]);
        match a.cmd {
            Cmd::Pair {
                sub: PairSub::FromPin { pin, name },
            } => {
                assert_eq!(pin, "123456");
                assert_eq!(name, "Phone");
            }
            other => panic!("expected Pair(FromPin), got {other:?}"),
        }
    }

    #[test]
    fn pair_from_pin_requires_pin_and_name() {
        assert!(Args::try_parse_from(["fluxctl", "pair", "from-pin", "--name", "Phone"]).is_err());
        assert!(Args::try_parse_from(["fluxctl", "pair", "from-pin", "--pin", "123456"]).is_err());
    }

    #[test]
    fn debug_capture_is_gone() {
        // DIR-P3-09: the stub was removed entirely, not just hidden —
        // `fluxctl debug-capture` must now be an unrecognized subcommand.
        assert!(Args::try_parse_from(["fluxctl", "debug-capture"]).is_err());
    }
}
