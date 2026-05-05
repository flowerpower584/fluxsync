// Single-line entry shim — `lib.rs` carries the actual logic so the
// same code can power desktop + (eventually) iOS / Android targets if
// we ever want to share the IPC client.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    fluxsync_macos_tray_lib::run();
}
