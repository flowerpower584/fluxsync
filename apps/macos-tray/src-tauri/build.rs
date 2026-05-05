use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

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

    tauri_build::build();
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
