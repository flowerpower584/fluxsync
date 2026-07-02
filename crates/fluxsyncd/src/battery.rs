use fluxsync_core::events::Event;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Cross-platform self-battery watcher. Polls the OS and emits
/// `BatteryChangedSelf` only when the reading actually changes, so the
/// peer's display tracks charge / drain / plug live without redundant
/// traffic. `charging` means "on external power" (plugged in) — a single
/// truthful binary signal, identical in meaning on every platform. Devices
/// with no battery (desktops) read `None` and never emit, so the peer keeps
/// the 255 "not read" sentinel and renders "—" instead of a fake percentage.
///
/// Polls every 5s so a plug / unplug is reflected to the peer within a few
/// seconds; Android stays event-driven (`ACTION_BATTERY_CHANGED` →
/// `set_self_battery`) and never runs this loop.
pub async fn battery_watcher_loop(
    event_tx: mpsc::Sender<Event>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    tracing::info!("battery watcher started");
    let mut last: Option<(u8, bool)> = None;
    loop {
        if let Some((level, charging)) = read_battery() {
            if last != Some((level, charging)) {
                last = Some((level, charging));
                let _ = event_tx.try_send(Event::BatteryChangedSelf { level, charging });
            }
        }

        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
    Ok(())
}

/// Reads `(level 0-100, on_external_power)`. `None` when the device has no
/// battery (desktop) or the reading is unavailable — the caller then skips
/// emitting, leaving the peer's "—" placeholder intact.
fn read_battery() -> Option<(u8, bool)> {
    #[cfg(target_os = "macos")]
    {
        read_macos()
    }
    #[cfg(target_os = "linux")]
    {
        read_linux()
    }
    #[cfg(target_os = "windows")]
    {
        read_windows()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn read_macos() -> Option<(u8, bool)> {
    use std::process::Command;
    let output = Command::new("pmset").arg("-g").arg("batt").output().ok()?;
    parse_pmset(&String::from_utf8_lossy(&output.stdout))
}

/// Parses `pmset -g batt`. Charging is read from the *power-source header*
/// line (`Now drawing from 'AC Power'` vs `'Battery Power'`), NOT from the
/// status word: the old `line.contains("charging")` matched the substring
/// inside `discharging`, so an unplugged Mac always reported charging=true.
/// The header is unambiguous and covers every plugged sub-state (charging,
/// charged, finishing charge, not charging). Returns `None` on a desktop
/// with no `-InternalBattery-` line so the peer shows "—", not 0%.
#[cfg(target_os = "macos")]
fn parse_pmset(stdout: &str) -> Option<(u8, bool)> {
    let on_ac = stdout.contains("'AC Power'");
    let mut level: Option<u8> = None;
    for line in stdout.lines() {
        if line.contains("InternalBattery") {
            if let Some(pct_idx) = line.find('%') {
                let start = line[..pct_idx]
                    .rfind(|c: char| !c.is_ascii_digit())
                    .map_or(0, |i| i + 1);
                if let Ok(val) = line[start..pct_idx].parse::<u8>() {
                    level = Some(val.min(100));
                }
            }
        }
    }
    level.map(|l| (l, on_ac))
}

#[cfg(target_os = "linux")]
fn read_linux() -> Option<(u8, bool)> {
    use std::fs;
    // First real battery under /sys/class/power_supply (BAT0, BAT1, ...).
    // Desktops (e.g. an iMac on Arch) have none → None → peer shows "—".
    for entry in fs::read_dir("/sys/class/power_supply").ok()?.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("BAT") {
            continue;
        }
        let p = entry.path();
        let level = fs::read_to_string(p.join("capacity"))
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()?
            .min(100) as u8;
        let status = fs::read_to_string(p.join("status")).unwrap_or_default();
        // Anything but a draining/unknown battery is "on power": Charging,
        // Full, and "Not charging" (plugged, held at threshold) all count.
        let charging = !matches!(status.trim(), "Discharging" | "Unknown" | "");
        return Some((level, charging));
    }
    None
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)] // GetSystemPowerStatus: read-only FFI into a stack struct, reviewed here.
fn read_windows() -> Option<(u8, bool)> {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    let mut st: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { GetSystemPowerStatus(&mut st) } == 0 {
        return None;
    }
    // BatteryFlag bit 7 (128) = no system battery → desktop.
    if st.BatteryFlag & 128 != 0 || st.BatteryLifePercent == 255 {
        return None;
    }
    let level = st.BatteryLifePercent.min(100);
    let charging = st.ACLineStatus == 1; // 1 = AC online (plugged)
    Some((level, charging))
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::parse_pmset;

    #[test]
    fn discharging_reports_not_charging() {
        // The exact case the old substring check got wrong.
        let s = "Now drawing from 'Battery Power'\n \
                 -InternalBattery-0 (id=1234567)\t85%; discharging; 10:00 remaining present: true";
        assert_eq!(parse_pmset(s), Some((85, false)));
    }

    #[test]
    fn charging_on_ac_reports_charging() {
        let s = "Now drawing from 'AC Power'\n \
                 -InternalBattery-0 (id=1234567)\t42%; charging; 1:30 remaining present: true";
        assert_eq!(parse_pmset(s), Some((42, true)));
    }

    #[test]
    fn charged_on_ac_reports_on_power() {
        let s = "Now drawing from 'AC Power'\n \
                 -InternalBattery-0 (id=1234567)\t100%; charged; 0:00 remaining present: true";
        assert_eq!(parse_pmset(s), Some((100, true)));
    }

    #[test]
    fn not_charging_on_ac_reports_on_power() {
        // "not charging" contains "charging" — the second substring trap.
        let s = "Now drawing from 'AC Power'\n \
                 -InternalBattery-0 (id=1234567)\t80%; not charging; (no estimate) present: true";
        assert_eq!(parse_pmset(s), Some((80, true)));
    }

    #[test]
    fn desktop_without_internal_battery_is_none() {
        assert_eq!(parse_pmset("Now drawing from 'AC Power'"), None);
    }
}
