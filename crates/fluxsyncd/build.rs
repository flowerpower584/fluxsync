//! Stamps the daemon with a short build identifier so a launcher (the
//! macOS tray) can detect it spawned — or is talking to — a stale
//! `fluxsyncd` binary and refresh it. Exposed at runtime via
//! `env!("FLUXSYNCD_BUILD_ID")` and surfaced in the IPC `State`.

use std::process::Command;

fn main() {
    println!("cargo:rustc-env=FLUXSYNCD_BUILD_ID={}", build_id());
    // Re-run when HEAD moves: `.git/HEAD` flips on checkout, `.git/logs/HEAD`
    // appends on every commit/checkout (the symref file itself stays put on
    // a plain commit, so the logs file is the reliable trigger).
    for p in ["../../.git/HEAD", "../../.git/logs/HEAD"] {
        println!("cargo:rerun-if-changed={p}");
    }
}

/// `<short-hash>` or `<short-hash>-dirty`, falling back to `unknown` when
/// git is unavailable (e.g. a packaged-source build outside a checkout).
fn build_id() -> String {
    let hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = Command::new("git")
        .args(["diff", "--quiet", "--ignore-submodules"])
        .status()
        .is_ok_and(|s| !s.success());

    if dirty {
        format!("{hash}-dirty")
    } else {
        hash
    }
}
