use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Re-run this script (and therefore rebuild + recopy the sidecar)
    // whenever any daemon-side source changes. Without these, build.rs
    // only re-executes when build.rs itself changes, so a daemon code
    // edit would leave a stale `binaries/fluxsyncd-<target>` in place.
    for p in [
        "../../../crates/fluxsyncd/src",
        "../../../crates/fluxsyncd/build.rs",
        "../../../crates/fluxsyncd/Cargo.toml",
        "../../../crates/fluxsync-core/src",
        "../../../crates/fluxsync-core/Cargo.toml",
        "../../../crates/fluxsync-proto/src",
        "../../../crates/fluxsync-proto/Cargo.toml",
        "../../../crates/fluxsync-crypto/src",
        "../../../crates/fluxsync-crypto/Cargo.toml",
        // HEAD movement → the daemon's compiled-in build id changes.
        "../../../.git/HEAD",
        "../../../.git/logs/HEAD",
    ] {
        println!("cargo:rerun-if-changed={p}");
    }

    // Stamp the tray with the same kind of build id the daemon carries,
    // so the runtime version guard can compare them. Same git HEAD →
    // same hash, so a fresh co-built pair always matches.
    println!("cargo:rustc-env=FLUXSYNC_TRAY_BUILD_ID={}", tray_build_id());

    // Generate placeholder PNGs once if the artist hasn't already
    // dropped real assets in `icons/`. macOS uses these as template
    // images, so the design is intentionally a flat black-on-transparent
    // glyph that adapts to menu-bar tint automatically.
    let icons_dir = PathBuf::from("icons");
    fs::create_dir_all(&icons_dir).expect("create icons/");

    // Filenames Tauri's bundler expects. Order largest-first so a
    // future icns-generator can pick the highest-resolution source.
    for &(filename, size) in &[
        ("icon.png", 32),
        ("32x32.png", 32),
        ("128x128.png", 128),
        ("128x128@2x.png", 256),
    ] {
        let path = icons_dir.join(filename);
        if !path.exists() {
            generate_glyph_png(&path, size);
        }
    }

    // Windows resource compiler needs an `.ico`; the macOS/Linux builds
    // never exercise this path so the file was previously absent.
    let ico_path = icons_dir.join("icon.ico");
    if !ico_path.exists() {
        generate_ico(&ico_path, 256);
    }

    prepare_sidecar();

    tauri_build::build();
}

/// Wrap the rendered glyph as a single-image `.ico` (PNG-encoded entry,
/// the Vista+ icon format). `tauri-build` embeds this as the Windows
/// executable resource.
fn generate_ico(path: &Path, size: u32) {
    let pixels = render_tray_glyph(size);
    let mut png_buf: Vec<u8> = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png_buf, size, size);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut w = encoder.write_header().expect("ico png header");
        w.write_image_data(&pixels).expect("ico png data");
    }

    let mut ico: Vec<u8> = Vec::new();
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]); // reserved, type=icon, count=1
    let dim = if size >= 256 { 0u8 } else { size as u8 };
    ico.push(dim); // width  (0 == 256)
    ico.push(dim); // height (0 == 256)
    ico.push(0); // color palette
    ico.push(0); // reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // color planes
    ico.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    ico.extend_from_slice(&(png_buf.len() as u32).to_le_bytes()); // image byte size
    ico.extend_from_slice(&22u32.to_le_bytes()); // offset: 6-byte dir + 16-byte entry
    ico.extend_from_slice(&png_buf);
    fs::write(path, ico).expect("write icon.ico");
}

/// Builds the `fluxsyncd` daemon and drops it in `binaries/` under the
/// triple-suffixed name Tauri's `externalBin` expects. Runs here, before
/// `tauri_build::build()`, so the sidecar always exists no matter how the
/// crate is compiled (`cargo`, `tauri dev`, an IDE button — not just the
/// npm scripts). `binaries/` is gitignored, so a fresh clone has nothing.
fn prepare_sidecar() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .join("../../..")
        .canonicalize()
        .expect("locate repo root from src-tauri");
    let target = std::env::var("TARGET").expect("TARGET");
    let exe = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };

    let sidecar = manifest_dir
        .join("binaries")
        .join(format!("fluxsyncd-{target}{exe}"));

    // Tell the runtime which `binaries/fluxsyncd-<triple>` name to look
    // for — `locate_daemon` reads this so the dev-mode managed-sidecar
    // path works on whatever target we built for.
    println!("cargo:rustc-env=FLUXSYNC_SIDECAR_FILE=fluxsyncd-{target}{exe}");

    // Always rebuild — never trust an existing `binaries/fluxsyncd-*` to
    // be current. `cargo build` is incremental, so this is near-free when
    // nothing changed; build.rs's `rerun-if-changed` set (see `main`)
    // keeps the script itself from re-executing needlessly.
    //
    // Always pass `--target` so a cross-compile (cargo-xwin → Windows)
    // produces a sidecar for the *target*, not the build host.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = std::process::Command::new(&cargo)
        .args([
            "build",
            "--release",
            "-p",
            "fluxsyncd",
            "--target",
            &target,
            "--manifest-path",
        ])
        .arg(repo_root.join("Cargo.toml"))
        .status()
        .expect("spawn cargo build for fluxsyncd");
    assert!(status.success(), "failed to build the fluxsyncd sidecar");

    let built = repo_root
        .join("target")
        .join(&target)
        .join("release")
        .join(format!("fluxsyncd{exe}"));
    fs::create_dir_all(sidecar.parent().unwrap()).expect("create binaries/");
    fs::copy(&built, &sidecar).expect("copy fluxsyncd sidecar into binaries/");
}

/// `<short-hash>` or `<short-hash>-dirty` for the current checkout —
/// identical to `fluxsyncd`'s own build-id logic so a co-built tray and
/// daemon compare equal. Falls back to `unknown` outside a git checkout.
fn tray_build_id() -> String {
    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = std::process::Command::new("git")
        .args(["diff", "--quiet", "--ignore-submodules"])
        .status()
        .map(|s| !s.success())
        .unwrap_or(false);

    if dirty {
        format!("{hash}-dirty")
    } else {
        hash
    }
}

fn generate_glyph_png(path: &Path, size: u32) {
    let pixels = render_tray_glyph(size);
    let file = File::create(path).expect("create png");
    let writer = BufWriter::new(file);
    let mut encoder = png::Encoder::new(writer, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut w = encoder.write_header().expect("png header");
    w.write_image_data(&pixels).expect("png data");
}

/// Re-renders the `TrayGlyph` from `design/frame-macos.jsx` (16x16
/// viewBox, two stacked clipboard-style rounded rects) at the
/// requested size. Pure black-on-transparent.
fn render_tray_glyph(size: u32) -> Vec<u8> {
    let mut buf = vec![0u8; (size as usize) * (size as usize) * 4];
    let scale = size as f32 / 16.0;
    let stroke = ((1.3 * scale).round() as i32).max(1);
    let black = [0u8, 0u8, 0u8, 255u8];
    let clear = [0u8, 0u8, 0u8, 0u8];

    // Back layer: x=2.5, y=3, w=8, h=9 → corners (2.5,3) → (10.5,12).
    let bx1 = (2.5 * scale) as i32;
    let by1 = (3.0 * scale) as i32;
    let bx2 = (10.5 * scale) as i32;
    let by2 = (12.0 * scale) as i32;
    rect_outline(&mut buf, size, bx1, by1, bx2, by2, stroke, black);

    // Front layer: x=5.5, y=6, w=8, h=9. First clear any back-rect
    // pixels that fall under the front rect's interior so the two
    // outlines stay legible (matches the SVG's white fill on the
    // front rect).
    let fx1 = (5.5 * scale) as i32;
    let fy1 = (6.0 * scale) as i32;
    let fx2 = (13.5 * scale) as i32;
    let fy2 = (15.0 * scale) as i32;
    rect_fill(&mut buf, size, fx1, fy1, fx2, fy2, clear);
    rect_outline(&mut buf, size, fx1, fy1, fx2, fy2, stroke, black);

    buf
}

fn set_pixel(buf: &mut [u8], size: u32, x: i32, y: i32, rgba: [u8; 4]) {
    if x < 0 || y < 0 || x >= size as i32 || y >= size as i32 {
        return;
    }
    let idx = ((y as u32 * size + x as u32) * 4) as usize;
    buf[idx..idx + 4].copy_from_slice(&rgba);
}

fn rect_fill(buf: &mut [u8], size: u32, x1: i32, y1: i32, x2: i32, y2: i32, rgba: [u8; 4]) {
    for y in y1..=y2 {
        for x in x1..=x2 {
            set_pixel(buf, size, x, y, rgba);
        }
    }
}

/// Draws an `thickness`-pixel-wide outline along the inside of the
/// rect. Concentric loops shrink the rectangle inward by 1px on each
/// iteration, which matches an SVG stroke with `stroke-alignment:
/// inside` better than centred strokes do.
#[allow(clippy::too_many_arguments)]
fn rect_outline(
    buf: &mut [u8],
    size: u32,
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
    thickness: i32,
    rgba: [u8; 4],
) {
    for t in 0..thickness {
        for x in (x1 + t)..=(x2 - t) {
            set_pixel(buf, size, x, y1 + t, rgba);
            set_pixel(buf, size, x, y2 - t, rgba);
        }
        for y in (y1 + t)..=(y2 - t) {
            set_pixel(buf, size, x1 + t, y, rgba);
            set_pixel(buf, size, x2 - t, y, rgba);
        }
    }
}
