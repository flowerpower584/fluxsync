//! Human-readable terminal rendering for `fluxctl` responses.
//!
//! All renderers receive the raw daemon response (`{"data": ..., "id": ..., "ok": bool}`)
//! and produce a colored, structured view. The `--json` path bypasses this module
//! entirely, so script consumers see exact daemon output.

use anyhow::{anyhow, Result};
use comfy_table::{
    presets::UTF8_FULL_CONDENSED, Cell, Color as TableColor, ContentArrangement, Table,
};
use owo_colors::OwoColorize;
use serde_json::Value;

const BOX_W: usize = 60;

#[allow(clippy::too_many_lines)]
pub fn render_status(v: &Value) {
    let Some(data) = v.get("data") else {
        render_err(v, "status");
        return;
    };
    let on = data.get("on").and_then(Value::as_bool).unwrap_or(false);
    let status = data.get("status").and_then(Value::as_str).unwrap_or("?");
    // Real link state for gating the peer readout (a dropped peer keeps its
    // name for reconnect UX, but its battery must not read as live).
    let phase = data.get("phase").and_then(Value::as_str).unwrap_or("");
    let peer_connected = matches!(phase, "linked" | "paused" | "halted");
    let cipher = data.get("cipher").and_then(Value::as_str).unwrap_or("?");
    let version = data.get("version").and_then(Value::as_str).unwrap_or("?");
    let battery = data
        .get("battery_level")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let threshold = data
        .get("battery_threshold")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let charging = data
        .get("charging")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let latency = data
        .get("link_latency_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let device_name = data.get("device_name").and_then(Value::as_str).unwrap_or("");
    let peer_name = data.get("peer_name").and_then(Value::as_str).unwrap_or("");
    let peer_batt = data
        .get("peer_battery")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let peer_charging = data
        .get("peer_charging")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let history_count = data
        .get("history")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);

    let title = format!(" FluxSync v{version} · {cipher} ");
    let bar = "─".repeat(BOX_W);
    let pad = BOX_W.saturating_sub(title.chars().count());
    let lpad = pad / 2;
    let rpad = pad - lpad;
    println!(
        "{}{}{}",
        "─".repeat(lpad).dimmed(),
        title.bold().cyan(),
        "─".repeat(rpad).dimmed()
    );

    let daemon_dot = if on {
        "●".green().to_string()
    } else {
        "●".bright_black().to_string()
    };
    let daemon_label = if on {
        "ON".green().bold().to_string()
    } else {
        "OFF".bright_black().to_string()
    };
    let status_color = match status {
        "syncing" | "linked" => status.green().to_string(),
        "discovering" | "pairing" => status.yellow().to_string(),
        "idle" => status.bright_black().to_string(),
        _ => status.white().to_string(),
    };
    println!(
        "  {}    {} {:<14}  status: {}",
        "daemon".dimmed(),
        daemon_dot,
        daemon_label,
        status_color
    );

    if !device_name.is_empty() {
        println!("  {}      {}", "name".dimmed(), device_name.white());
    }

    let bolt = if charging {
        "⚡".yellow().to_string()
    } else {
        " ".to_string()
    };
    // 255 (or any >100) = not read yet / no battery (desktop) → "—".
    let battery_color = if battery > 100 {
        "—".bright_black().to_string()
    } else if charging || battery > threshold {
        format!("{battery}%").green().to_string()
    } else {
        format!("{battery}%").red().bold().to_string()
    };
    println!(
        "  {}   {} {:<14}  threshold {}%",
        "battery".dimmed(),
        bolt,
        battery_color,
        threshold
    );

    let lat_color = if latency == 0 {
        "—".bright_black().to_string()
    } else if latency < 50 {
        format!("{latency} ms").green().to_string()
    } else {
        format!("{latency} ms").yellow().to_string()
    };
    println!("  {}      {:<16}  UDP 41889", "link".dimmed(), lat_color);

    let peer_line = if peer_name.is_empty() {
        "— (no peer)".bright_black().to_string()
    } else if !peer_connected {
        // Name retained for reconnect, but the link is down.
        format!(
            "{} {}",
            peer_name.cyan().bold(),
            "(reconnecting)".bright_black()
        )
    } else if peer_batt > 100 {
        // Connected but no reading yet (or a battery-less peer).
        format!("{} {}", peer_name.cyan().bold(), "—".bright_black())
    } else {
        let bolt = if peer_charging {
            "⚡".yellow().to_string()
        } else {
            String::new()
        };
        let batt_str = if peer_charging || peer_batt > threshold {
            format!("{peer_batt}%").green().to_string()
        } else {
            format!("{peer_batt}%").red().bold().to_string()
        };
        format!("{} {}{}", peer_name.cyan().bold(), batt_str, bolt)
    };
    println!("  {}      {peer_line}", "peer".dimmed());

    // FluxMesh Phase 3: when more than one peer is linked, list the full mesh
    // (the `peer` line above stays the primary). Star marks the primary.
    if let Some(peers) = data.get("peers").and_then(Value::as_array) {
        if peers.len() > 1 {
            println!("  {}      {} devices", "mesh".dimmed(), peers.len());
            for p in peers {
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                let plat = p.get("platform").and_then(Value::as_str).unwrap_or("");
                let batt = p.get("battery").and_then(Value::as_u64).unwrap_or(255);
                let charging = p.get("charging").and_then(Value::as_bool).unwrap_or(false);
                let primary = p.get("primary").and_then(Value::as_bool).unwrap_or(false);
                let bolt = if charging {
                    "⚡".yellow().to_string()
                } else {
                    String::new()
                };
                let star = if primary {
                    "★".yellow().to_string()
                } else {
                    " ".to_string()
                };
                let label = if name.is_empty() { "(unknown)" } else { name };
                let plat_s = if plat.is_empty() {
                    String::new()
                } else {
                    format!(" [{plat}]")
                };
                let batt_s = if batt > 100 {
                    "—".bright_black().to_string()
                } else {
                    format!("{batt}%").green().to_string()
                };
                println!(
                    "    {star} {}{}  {}{}",
                    label.cyan(),
                    plat_s.dimmed(),
                    batt_s,
                    bolt
                );
            }
        }
    }

    let hist_color = if history_count == 0 {
        "0 items".bright_black().to_string()
    } else {
        format!("{history_count} items").white().to_string()
    };
    println!("  {}   {hist_color}", "history".dimmed());

    // DIR-P1-09: compact reliability counters, one line. `--json` carries
    // the full `ConnectionMetrics` object for scripting; this is the
    // human-glance summary.
    if let Some(m) = data.get("metrics").filter(|v| !v.is_null()) {
        let sent = m.get("items_sent").and_then(Value::as_u64).unwrap_or(0);
        let received = m
            .get("items_received")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let dups = m.get("dedup_drops").and_then(Value::as_u64).unwrap_or(0);
        let reconnects = m.get("reconnects").and_then(Value::as_u64).unwrap_or(0);
        let hs_failed = m
            .get("handshakes_failed")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        println!(
            "  {} sent {sent} · recv {received} · dups {dups} · reconnects {reconnects} · hs-fail {hs_failed}",
            "counters".dimmed()
        );
    }

    println!("{}", bar.dimmed());
}

pub fn render_peers(v: &Value) {
    let Some(arr) = v.get("data").and_then(Value::as_array) else {
        render_err(v, "peers");
        return;
    };
    if arr.is_empty() {
        println!("{} no paired peers yet.", "·".bright_black());
        println!(
            "  run {} on this device, then scan from the peer.",
            "fluxctl pair show-qr".cyan().bold()
        );
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("name").fg(TableColor::Cyan),
            Cell::new("peer-id").fg(TableColor::Cyan),
            Cell::new("addr").fg(TableColor::Cyan),
            Cell::new("rtt").fg(TableColor::Cyan),
            Cell::new("battery").fg(TableColor::Cyan),
        ]);
    for p in arr {
        let name = p.get("name").and_then(Value::as_str).unwrap_or("?");
        let pid = p.get("peer_id").and_then(Value::as_str).unwrap_or("");
        let pid_short: String = pid.chars().take(10).collect();
        let addr = p.get("addr").and_then(Value::as_str).unwrap_or("—");
        let rtt = p.get("link_latency_ms").and_then(Value::as_u64);
        let batt = p.get("battery").and_then(Value::as_u64);
        let charging = p.get("charging").and_then(Value::as_bool).unwrap_or(false);
        let rtt_cell = match rtt {
            Some(r) => format!("{r} ms"),
            None => "—".to_string(),
        };
        let batt_cell = match batt {
            Some(b) => {
                let bolt = if charging { "⚡" } else { "" };
                format!("{b}%{bolt}")
            }
            None => "—".to_string(),
        };
        table.add_row(vec![
            Cell::new(name),
            Cell::new(format!("{pid_short}…")),
            Cell::new(addr),
            Cell::new(rtt_cell),
            Cell::new(batt_cell),
        ]);
    }
    println!("{table}");
}

pub fn render_tail(v: &Value) {
    let Some(arr) = v.get("data").and_then(Value::as_array) else {
        render_err(v, "tail");
        return;
    };
    if arr.is_empty() {
        println!("{}", "(no log entries)".bright_black());
        return;
    }
    for entry in arr {
        let level = entry.get("level").and_then(Value::as_str).unwrap_or("INFO");
        let msg = entry.get("msg").and_then(Value::as_str).unwrap_or("");
        // LogLevel serializes UPPERCASE: OK / INFO / SYNC / WARN / ERR.
        // LogEntry carries no timestamp.
        let level_str = match level {
            "ERR" => format!("{level:<4}").red().bold().to_string(),
            "WARN" => format!("{level:<4}").yellow().bold().to_string(),
            "SYNC" => format!("{level:<4}").cyan().to_string(),
            "OK" => format!("{level:<4}").green().to_string(),
            _ => format!("{level:<4}").bright_black().to_string(),
        };
        println!("{level_str}  {msg}");
    }
}

pub fn render_pull(v: &Value) {
    let data = v.get("data");
    if data.is_none() || data == Some(&Value::Null) {
        println!(
            "{}",
            "(clipboard empty — nothing pulled yet)".bright_black()
        );
        return;
    }
    let item = data.unwrap();
    let text = item.get("preview").and_then(Value::as_str);
    let from = item.get("source").and_then(Value::as_str).unwrap_or("?");
    let kind = item.get("kind").and_then(Value::as_str).unwrap_or("text");
    let ts = item.get("time").and_then(Value::as_str).unwrap_or("");
    println!(
        "{} from {} {} {}",
        "▼".cyan().bold(),
        from.cyan().bold(),
        format!("[{kind}]").bright_black(),
        ts.dimmed()
    );
    println!("{}", "─".repeat(BOX_W).dimmed());
    if let Some(t) = text {
        println!("{t}");
    } else {
        println!("{}", serde_json::to_string_pretty(item).unwrap_or_default());
    }
    println!("{}", "─".repeat(BOX_W).dimmed());
}

pub fn render_pair_show(v: &Value) -> Result<()> {
    let data = v
        .get("data")
        .ok_or_else(|| anyhow!("response missing data"))?;
    let uri = data.get("uri").and_then(Value::as_str).unwrap_or("");
    let pid = data
        .get("peer_id_hex")
        .and_then(Value::as_str)
        .unwrap_or("");
    let pubkey = data.get("pubkey_b32").and_then(Value::as_str).unwrap_or("");
    let addr = data.get("addr_hint").and_then(Value::as_str).unwrap_or("");
    let words: Vec<&str> = data
        .get("fingerprint_words")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    println!("{}", "─── pair info ─────────────────────".cyan().bold());
    println!("  {}     {}", "peer-id".dimmed(), pid);
    println!("  {}      {}", "pubkey".dimmed(), pubkey);
    println!("  {}    {}", "addr hint".dimmed(), addr.green());
    println!(
        "  {}  {}",
        "fingerprint".dimmed(),
        words.join("  ").yellow().bold()
    );
    println!("  {}        {}", "uri".dimmed(), uri.bright_black());
    let tailnet = data
        .get("tailnet_addr_hint")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !tailnet.is_empty() {
        // The uri above already carries this (a=lan,tailnet); shown so the
        // user knows the QR also works across their tailnet.
        println!("  {}    {}", "tailnet".dimmed(), tailnet.green());
    }
    println!("{}", "─".repeat(40).dimmed());
    println!(
        "  Render the QR with: {}",
        "fluxctl pair show-qr".cyan().bold()
    );
    Ok(())
}

pub fn render_ack(v: &Value, action: &str) {
    let ok = v.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let err = v.get("err").and_then(Value::as_str);
    if ok {
        let detail = v.get("data").and_then(Value::as_str);
        match detail {
            Some(s) if !s.is_empty() => println!("{} {action}: {}", "✓".green().bold(), s),
            _ => println!("{} {action}", "✓".green().bold()),
        }
    } else {
        let msg = err.unwrap_or("unknown error");
        println!("{} {action}: {}", "✗".red().bold(), msg.red());
    }
}

fn render_err(v: &Value, action: &str) {
    let err = v
        .get("err")
        .and_then(Value::as_str)
        .unwrap_or("malformed response");
    println!("{} {action}: {}", "✗".red().bold(), err.red());
}

#[cfg(test)]
mod tests {
    use super::render_status;
    use serde_json::json;

    /// DIR-P1-09: `fluxctl status --json` is a raw passthrough of the
    /// daemon's response (`main.rs` just `serde_json::to_string_pretty`s
    /// the `Value` it already has) — so the contract to protect is that
    /// the shape survives that round-trip with every key a scripting
    /// consumer would look for, including the DIR-P3-01 device name and
    /// the DIR-P1-09 KPI counters.
    fn sample_status_response() -> serde_json::Value {
        json!({
            "id": 1,
            "ok": true,
            "data": {
                "phase": "linked",
                "on": true,
                "status": "syncing",
                "device_name": "Dethie's MacBook",
                "peer_name": "Galaxy S21",
                "peer_platform": "android",
                "battery_level": 80,
                "battery_threshold": 20,
                "charging": false,
                "peer_battery": 55,
                "peer_charging": true,
                "link_latency_ms": 12,
                "cipher": "chacha20-poly1305",
                "version": "0.7.0",
                "history": [],
                "metrics": {
                    "handshakes_total": 1,
                    "handshakes_failed": 0,
                    "heartbeats_sent": 10,
                    "heartbeats_received": 10,
                    "heartbeats_missed_consecutive": 0,
                    "last_rtt_ms": 5,
                    "rtt_p99_ms": 5,
                    "network_changes": 0,
                    "reconnects": 1,
                    "decrypt_failures": 0,
                    "dedup_drops": 2,
                    "last_disconnect_reason": null,
                    "uptime_session_secs": 42,
                    "items_sent": 7,
                    "items_received": 5,
                },
            },
        })
    }

    #[test]
    fn json_passthrough_round_trips_expected_keys() {
        let v = sample_status_response();
        let s = serde_json::to_string_pretty(&v).expect("serialize");
        let back: serde_json::Value = serde_json::from_str(&s).expect("must parse as valid JSON");

        let data = back.get("data").expect("data object");
        for key in [
            "phase",
            "device_name",
            "peer_name",
            "peer_platform",
            "battery_level",
            "link_latency_ms",
        ] {
            assert!(data.get(key).is_some(), "missing top-level key {key}");
        }
        let metrics = data.get("metrics").expect("metrics object");
        for key in [
            "items_sent",
            "items_received",
            "dedup_drops",
            "reconnects",
            "handshakes_failed",
        ] {
            assert!(metrics.get(key).is_some(), "missing metrics key {key}");
        }
    }

    /// Smoke test: the human renderer must not panic on a payload carrying
    /// the new `device_name` + KPI fields (or when they're absent, e.g. an
    /// older daemon / a fresh boot with `metrics: null`).
    #[test]
    fn render_status_does_not_panic_with_or_without_new_fields() {
        render_status(&sample_status_response());

        let minimal = json!({"id": 1, "ok": true, "data": {"phase": "idle", "on": false}});
        render_status(&minimal);
    }
}
