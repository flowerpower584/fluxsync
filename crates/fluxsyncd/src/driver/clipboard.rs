//! OS clipboard watcher, dedup hashing and the recent-image cache.

use super::*;

/// Dedup hash over the *trimmed* clipboard text, so the write side and
/// the watcher (which trims before hashing) agree — see FS-026.
pub(super) fn clipboard_dedup_hash(text: &str) -> [u8; 32] {
    // CRLF-canonicalize (not just trim) so a Windows `\r\n` copy and a
    // Unix `\n` copy of the same text — or an app that LF-normalizes the
    // clipboard on read-back — dedup against each other instead of
    // ping-ponging. Mirrors the core's inbound hashing (app.rs).
    DedupRing::hash(fluxsync_core::canon_text(text).as_bytes()).into_bytes()
}

/// Build the history label for a clipboard payload. Text-like kinds show
/// the (lossy) UTF-8 text; images show a byte-size descriptor since their
/// payload is binary PNG.
pub(super) fn preview_label(kind: Kind, payload: &[u8]) -> String {
    match kind {
        Kind::Image => format!("Image, {} KB", payload.len().div_ceil(1024)),
        _ => String::from_utf8_lossy(payload).to_string(),
    }
}

/// Dedup hash over an image's raw RGBA pixels (prefixed with its
/// dimensions). Hashing the decoded pixels — not the PNG bytes — keeps the
/// hash stable across a PNG encode/decode round-trip, so a write followed
/// by the watcher's read-back is recognised as our own and not echoed back
/// to the peer.
pub(super) fn image_rgba_hash(width: u32, height: u32, rgba: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + rgba.len());
    buf.extend_from_slice(&width.to_le_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(rgba);
    DedupRing::hash(&buf).into_bytes()
}

/// Process-global cache of recently-received image payloads, keyed by hex
/// content hash. The daemon never puts binary in the state JSON; every
/// client pulls an inbound image's PNG bytes on demand via the `fetch_item`
/// IPC op, which reads this map (Android needs it to apply the bytes at all;
/// desktop uses it for tray history thumbnails + image re-copy, in addition
/// to writing straight to the OS clipboard). Bounded to the last few images
/// so a 16 MiB cap can't grow memory without limit.
pub(super) type ImageCache = std::sync::Mutex<VecDeque<(String, Vec<u8>)>>;
pub(super) static IMAGE_CACHE: std::sync::OnceLock<ImageCache> = std::sync::OnceLock::new();

/// Max image payloads retained in [`IMAGE_CACHE`]. 4 × 16 MiB worst case.
pub(super) const IMAGE_CACHE_CAP: usize = 4;

pub(super) fn image_cache() -> &'static ImageCache {
    IMAGE_CACHE.get_or_init(|| std::sync::Mutex::new(VecDeque::with_capacity(IMAGE_CACHE_CAP)))
}

/// Store an inbound image's PNG bytes under its hex hash. No-op if the
/// hash is already cached. Cross-platform: both Android (which has no other
/// way to apply the bytes) and desktop (tray thumbnails/re-copy via
/// `fetch_item`, alongside its direct OS-clipboard write) populate this.
pub(super) fn cache_image(hash_hex: String, png: Vec<u8>) {
    if let Ok(mut g) = image_cache().lock() {
        if g.iter().any(|(h, _)| *h == hash_hex) {
            return;
        }
        g.push_back((hash_hex, png));
        while g.len() > IMAGE_CACHE_CAP {
            g.pop_front();
        }
    }
}

/// Look up a cached image's PNG bytes by hex hash. `None` if evicted or
/// never received.
pub(super) fn lookup_cached_image(hash_hex: &str) -> Option<Vec<u8>> {
    let g = image_cache().lock().ok()?;
    g.iter()
        .find(|(h, _)| h == hash_hex)
        .map(|(_, png)| png.clone())
}

/// "Clear clipboard history": drop every cached image payload whose hex hash
/// is in `hashes_hex` so a cleared image can't still be fetched via
/// `FetchItem` after the history entry that pointed at it is gone.
pub(super) fn purge_cached_images(hashes_hex: &[String]) {
    if let Ok(mut g) = image_cache().lock() {
        g.retain(|(h, _)| !hashes_hex.iter().any(|c| c == h));
    }
}

/// Decode PNG bytes to `(width, height, rgba)`. `None` on any decode error.
pub(super) fn decode_png_to_rgba(png: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let img = image::load_from_memory_with_format(png, image::ImageFormat::Png).ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = (rgba.width(), rgba.height());
    Some((w, h, rgba.into_raw()))
}

/// Encode RGBA pixels to PNG bytes. `None` on failure (e.g. the buffer
/// length doesn't match `width * height * 4`).
#[cfg(not(target_os = "android"))]
pub(super) fn encode_png(width: u32, height: u32, rgba: Vec<u8>) -> Option<Vec<u8>> {
    let img = image::RgbaImage::from_raw(width, height, rgba)?;
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut out, image::ImageFormat::Png)
        .ok()?;
    Some(out.into_inner())
}

/// Polls the OS clipboard every 200ms and forwards new payloads through
/// the same `DriverCmd::Run { op: Push }` path the IPC `push` op uses.
/// Routing through the cmd channel (instead of firing
/// `Event::LocalClipboardChange` directly) lets us reuse the existing
/// lamport allocation, dedup, and SendItem dispatch — the watcher only
/// has to detect "the OS clipboard changed."
///
/// Dedup happens twice:
///   * `last_seen_hash` filters consecutive polls of the same payload.
///   * `last_written_hashes` (shared with `Action::WriteClipboard`)
///     filters out the immediate read-back of a payload we just wrote
///     ourselves after receiving it from the peer — without it, every
///     inbound item would ping-pong back to the sender.
///
/// Gated on `transport.session.is_some()` so we don't spam the FSM
/// before pairing completes.
///
/// Compiled out on Android — `arboard` doesn't ship an Android backend
/// and the platform forbids background clipboard reads anyway. The
/// Android `MainActivity` does the equivalent work in its
/// `ClipboardManager.OnPrimaryClipChangedListener`.
#[cfg(not(target_os = "android"))]
pub(super) async fn clipboard_watcher_loop(sh: Arc<Shared>) -> Result<()> {
    let Shared {
        transport,
        cmd_tx,
        last_written_hashes,
        shutdown,
        ..
    } = &*sh;
    let mut last_seen_hash: Option<[u8; 32]> = None;
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    let mut last_session_est = 0u64;
    loop {
        // FS-048: while unpaired there is nothing to poll. Sleep on the
        // session-install pulse instead of waking every 200ms only to
        // observe `session.is_none()` and `continue`.
        if !transport.has_session().await {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                () = transport.session_notify.notified() => {}
            }
            continue;
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let est = transport.session_established_at();
                let session_active = transport.has_session().await;

                if !session_active {
                    continue;
                }

                // [REMEDIATION] Session Seeding: If this is a fresh session, seed last_seen_hash
                // with the current OS clipboard to avoid blasting disconnected-state copies to the peer.
                if est != last_session_est {
                    last_session_est = est;
                    // Image-first, mirroring the poll below: a clipboard
                    // holding image/png means an image was copied, even
                    // when text/html is attached alongside.
                    let img_res = tokio::task::spawn_blocking(|| {
                        arboard::Clipboard::new().and_then(|mut cb| cb.get_image())
                    })
                    .await;
                    if let Ok(Ok(img)) = img_res {
                        last_seen_hash = Some(image_rgba_hash(
                            img.width as u32,
                            img.height as u32,
                            &img.bytes,
                        ));
                        tracing::debug!("Clipboard watcher seeded (image) for new session");
                    } else {
                        let text_res = tokio::task::spawn_blocking(|| {
                            arboard::Clipboard::new().and_then(|mut cb| cb.get_text())
                        })
                        .await;
                        if let Ok(Ok(raw_text)) = text_res {
                            last_seen_hash = Some(clipboard_dedup_hash(&raw_text));
                            tracing::debug!("Clipboard watcher seeded for new session");
                        }
                    }
                }
                // ── Image (takes priority) ───────────────────────────
                // image/png on the clipboard means the user copied an
                // image. Browsers attach text/html + text/x-moz-url
                // alongside it; probing text first would let that URL
                // shadow the image (FS: "sometimes it yields the URL"). So
                // probe the image first and, when present, skip text.
                let img_res = tokio::task::spawn_blocking(|| {
                    arboard::Clipboard::new().and_then(|mut cb| cb.get_image())
                })
                .await;
                if let Ok(Ok(img)) = img_res {
                    let w = img.width as u32;
                    let h = img.height as u32;
                    let rgba = img.bytes.into_owned();
                    let hash = image_rgba_hash(w, h, &rgba);
                    if last_seen_hash != Some(hash) {
                        let already = last_written_hashes.lock().await.is_echo(&hash);
                        last_seen_hash = Some(hash);
                        if !already {
                            match encode_png(w, h, rgba) {
                                Some(png) if png.len() <= MAX_PAYLOAD => {
                                    let preview = format!(
                                        "Image {w}×{h}, {} KB",
                                        png.len().div_ceil(1024)
                                    );
                                    if cmd_tx
                                        .send(DriverCmd::PushImage { hash, png, preview })
                                        .is_err()
                                    {
                                        tracing::error!("clipboard_watcher_loop: failed to send PushImage command");
                                        return Ok(());
                                    }
                                    tracing::debug!("clipboard_watcher_loop: PushImage command sent");
                                }
                                Some(png) => tracing::warn!(
                                    size = png.len(),
                                    "clipboard image exceeds 16 MiB cap; skipped"
                                ),
                                None => tracing::warn!("clipboard image PNG encode failed"),
                            }
                        }
                    }
                    // Had an image this tick — skip the text probe.
                    continue;
                }

                // ── Text (only when the clipboard holds no image) ────
                let text_res = tokio::task::spawn_blocking(|| {
                    arboard::Clipboard::new().and_then(|mut cb| cb.get_text())
                })
                .await;
                if let Ok(Ok(raw_text)) = text_res {
                    let text = raw_text.trim().to_string();
                    if !text.is_empty() {
                        let hash = clipboard_dedup_hash(&raw_text);
                        if last_seen_hash != Some(hash) {
                            let already =
                                last_written_hashes.lock().await.is_echo(&hash);
                            last_seen_hash = Some(hash);
                            if !already {
                                if text.len() > MAX_PAYLOAD {
                                    tracing::warn!(
                                        size = text.len(),
                                        "clipboard text exceeds 16 MiB cap; skipped"
                                    );
                                } else {
                                    let (reply_tx, _reply_rx) = oneshot::channel();
                                    if cmd_tx
                                        .send(DriverCmd::Run {
                                            op: CmdOp::Push { text },
                                            reply: reply_tx,
                                            req_id: 0,
                                        })
                                        .is_err()
                                    {
                                        tracing::error!("clipboard_watcher_loop: failed to send Push command");
                                        return Ok(());
                                    }
                                    tracing::debug!("clipboard_watcher_loop: Push command sent");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Heartbeat & Timeout loop
// ─────────────────────────────────────────────────────────────────
