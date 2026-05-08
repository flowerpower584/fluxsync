use fluxsync_core::events::Event;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};

/// Polls macOS battery status via `pmset -g batt`.
pub async fn battery_watcher_loop(
    event_tx: mpsc::UnboundedSender<Event>,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
    tracing::info!("macOS battery watcher started");
    loop {
        if let Ok((level, charging)) = get_macos_battery() {
            let _ = event_tx.send(Event::BatteryChangedSelf { level, charging });
        }

        tokio::select! {
            () = shutdown.notified() => break,
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
    }
    Ok(())
}

fn get_macos_battery() -> anyhow::Result<(u8, bool)> {
    let output = Command::new("pmset").arg("-g").arg("batt").output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Typical output:
    // Now drawing from 'Battery Power'
    // -InternalBattery-0 (id=1234567)	85%; discharging; 10:00 remaining present: true

    let mut level = 0;
    let mut charging = false;

    for line in stdout.lines() {
        if line.contains("InternalBattery") {
            // Find percentage
            if let Some(pct_idx) = line.find('%') {
                let start = line[..pct_idx]
                    .rfind(|c: char| !c.is_digit(10))
                    .map(|i| i + 1)
                    .unwrap_or(0);
                if let Ok(val) = line[start..pct_idx].parse::<u8>() {
                    level = val;
                }
            }
            // Find charging status
            if line.contains("charging") || line.contains("AC Power") {
                charging = true;
            }
        }
    }

    Ok((level, charging))
}
