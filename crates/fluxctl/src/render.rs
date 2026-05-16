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

    let bolt = if charging {
        "⚡".yellow().to_string()
    } else {
        " ".to_string()
    };
    let battery_color = if charging || battery > threshold {
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
    } else {
        let bolt = if peer_charging {
            "⚡".yellow().to_string()
        } else {
            String::new()
        };
        format!(
            "{} {}{}",
            peer_name.cyan().bold(),
            format!("{peer_batt}%").green(),
            bolt
        )
    };
    println!("  {}      {peer_line}", "peer".dimmed());

    let hist_color = if history_count == 0 {
        "0 items".bright_black().to_string()
    } else {
        format!("{history_count} items").white().to_string()
    };
    println!("  {}   {hist_color}", "history".dimmed());

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
        let rtt = p.get("rtt_ms").and_then(Value::as_u64);
        let batt = p.get("battery_level").and_then(Value::as_u64);
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
        let ts = entry.get("ts").and_then(Value::as_str).unwrap_or("");
        let level_str = match level {
            "ERROR" => format!("{level:<5}").red().bold().to_string(),
            "WARN" => format!("{level:<5}").yellow().bold().to_string(),
            "INFO" => format!("{level:<5}").cyan().to_string(),
            "DEBUG" => format!("{level:<5}").bright_black().to_string(),
            _ => format!("{level:<5}").white().to_string(),
        };
        if ts.is_empty() {
            println!("{level_str}  {msg}");
        } else {
            println!("{level_str}  {}  {msg}", ts.dimmed());
        }
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
    let text = item.get("text").and_then(Value::as_str);
    let from = item.get("from").and_then(Value::as_str).unwrap_or("?");
    let kind = item.get("kind").and_then(Value::as_str).unwrap_or("text");
    let ts = item.get("ts").and_then(Value::as_str).unwrap_or("");
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
    println!("{}", "─".repeat(40).dimmed());
    println!(
        "  Render the QR with: {}",
        "fluxctl pair show-qr".cyan().bold()
    );
    Ok(())
}

pub fn render_ack(v: &Value, action: &str) {
    let ok = v.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let err = v.get("error").and_then(Value::as_str);
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
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("malformed response");
    println!("{} {action}: {}", "✗".red().bold(), err.red());
}
