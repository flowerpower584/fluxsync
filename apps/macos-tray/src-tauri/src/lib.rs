//! FluxSync macOS menu-bar app.
//!
//! The tray itself is the entire UX: clicking the tray icon pops a
//! small (360 × 540) borderless window pinned just under the icon.
//! The window is HTML/CSS reusing the design-system tokens; everything
//! the user can do (toggle, change threshold, pair, view history) hits
//! a `#[tauri::command]` function declared here, which forwards JSON
//! to `fluxsyncd` over its UNIX socket and returns the response.
//!
//! The daemon is **not** linked into this binary — the tray spawns
//! `fluxsyncd` detached at boot (see `ipc::ensure_daemon_running`), or
//! it can be launched manually. The tray app is a pure client.

mod ipc;

use serde_json::{json, Value};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

#[tauri::command]
async fn fluxsync_status() -> Result<Value, String> {
    ipc::one_shot(json!({"id": 1, "op": "status"})).await
}

#[tauri::command]
async fn fluxsync_toggle(on: bool) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "toggle", "on": on}))
        .await
        .map(|_| ())
}

#[tauri::command]
async fn fluxsync_set_threshold(value: u8) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "set_threshold", "value": value}))
        .await
        .map(|_| ())
}

#[tauri::command]
async fn fluxsync_set_charge_override(value: bool) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "set_charge_override", "value": value}))
        .await
        .map(|_| ())
}

/// DIR-P3-01: rename this device. Validation (non-empty, wire-length
/// bound, printable) happens daemon-side; a rejected name comes back as
/// an `Err(String)` the settings UI can show inline. An already-linked
/// peer sees the new name on the next session establishment, not
/// immediately.
#[tauri::command]
async fn fluxsync_set_device_name(name: String) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "set_device_name", "name": name}))
        .await
        .map(|_| ())
}

#[tauri::command]
fn fluxsync_set_launch_at_login(app: tauri::AppHandle, value: bool) -> Result<(), String> {
    // Real OS-level autostart via tauri-plugin-autostart: a LaunchAgent
    // on macOS, a registry Run key on Windows, an XDG .desktop entry on
    // Linux. Launching the tray also spawns the daemon (see setup()), so
    // this is the "start daemon at login" the settings hint promises.
    use tauri_plugin_autostart::ManagerExt;
    let mgr = app.autolaunch();
    if value {
        mgr.enable().map_err(|e| e.to_string())
    } else {
        mgr.disable().map_err(|e| e.to_string())
    }
}

/// Report whether OS autostart is currently enabled, so the settings
/// toggle can show the real state instead of a cached guess.
#[tauri::command]
fn fluxsync_get_launch_at_login(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

#[tauri::command]
async fn fluxsync_unpair() -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "unpair"}))
        .await
        .map(|_| ())
}

/// FluxMesh: revoke one specific peer by hex peer-id (drops its session +
/// removes it from the trust store), leaving every other paired device
/// linked. Drives the daemon `revoke` op behind the per-secondary unpair
/// button in the mesh peer list. `unpair` (above) still tears down the
/// active primary; this is the surgical single-peer version.
#[tauri::command]
async fn fluxsync_revoke_peer(peer_id: String) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "revoke", "peer_id": peer_id}))
        .await
        .map(|_| ())
}

/// FluxFirewall: replace the whole clipboard firewall policy. `policy` is the
/// JS-built object (`enabled` + per-kind allow/ask/deny rules); the daemon
/// swaps it in and re-emits state so the toggles reflect immediately.
#[tauri::command]
async fn fluxsync_set_firewall(policy: serde_json::Value) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "set_firewall", "policy": policy}))
        .await
        .map(|_| ())
}

/// FluxFirewall: approve (`allow = true`) or reject an item parked under an
/// Ask rule, keyed by its hex content hash from `State.pending`.
#[tauri::command]
async fn fluxsync_resolve_pending(hash: String, allow: bool) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "resolve_pending", "hash": hash, "allow": allow}))
        .await
        .map(|_| ())
}

/// FluxVault: pin/unpin a history item by hex content hash. Pinned items
/// survive the vault TTL + disk cap.
#[tauri::command]
async fn fluxsync_set_favorite(hash: String, favorite: bool) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "set_favorite", "hash": hash, "favorite": favorite}))
        .await
        .map(|_| ())
}

/// "Clear clipboard history" (owner-requested, local-only — never
/// propagated to the peer). Favorited items always survive from the tray:
/// `include_favorites` is hardcoded `false` here. Deleting favorites too is
/// CLI-only (`fluxctl history clear --all`), not exposed in this UI.
#[tauri::command]
async fn fluxsync_clear_history() -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "clear_history", "include_favorites": false}))
        .await
        .map(|_| ())
}

#[tauri::command]
fn fluxsync_open_url(url: String) {
    // Defense-in-depth (H-TRAY-01): only ever hand http(s) URLs to the OS
    // opener, so even a stray `invoke` can't launch arbitrary schemes or
    // commands. Cross-platform (L-TRAY-04): `open` is macOS-only.
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return;
    }
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", &url])
        .spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
}

#[tauri::command]
async fn fluxsync_pair_show() -> Result<Value, String> {
    let resp = ipc::one_shot(json!({"id": 1, "op": "pair_show"})).await?;
    let mut data = resp
        .get("data")
        .cloned()
        .ok_or_else(|| "pair_show missing `data`".to_string())?;
    // Inline-render the URI as SVG so the pair window can show it
    // without pulling a JS QR library at runtime. Failure here is
    // non-fatal: the window falls back to the URI as monospace text.
    if let Some(uri) = data.get("uri").and_then(Value::as_str).map(str::to_string) {
        if let Some(svg) = render_qr_svg(&uri) {
            if let Some(obj) = data.as_object_mut() {
                obj.insert("qr_svg".into(), Value::String(svg));
            }
        }
    }
    Ok(data)
}

fn render_qr_svg(uri: &str) -> Option<String> {
    use qrcode::render::svg;
    use qrcode::QrCode;
    let code = QrCode::new(uri.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color<'static>>()
            .min_dimensions(320, 320)
            .dark_color(svg::Color("#0A0A0A"))
            .light_color(svg::Color("#FFFFFF"))
            .quiet_zone(true)
            .build(),
    )
}

#[tauri::command]
async fn fluxsync_pair_from_uri(uri: String, name: String) -> Result<(), String> {
    ipc::one_shot(json!({
        "id": 1,
        "op": "pair_from_uri",
        "uri": uri,
        "name": name,
    }))
    .await
    .map(|_| ())
}

/// PR2: PIN-method pair. Daemon resolves the peer by matching the PIN
/// against its mDNS discovery cache, then runs the same trust + handshake
/// path as `pair_from_uri`. The pair window UI follows up with
/// `pair_pending` + `pair_confirm` for SAS-words verification.
#[tauri::command]
async fn fluxsync_pair_from_pin(pin: String, name: String) -> Result<(), String> {
    ipc::one_shot(json!({
        "id": 1,
        "op": "pair_from_pin",
        "pin": pin,
        "name": name,
    }))
    .await
    .map(|_| ())
}

/// PR2: list peers waiting on verify-words confirmation. UI uses this
/// after a PIN-method pair to render the SAS screen.
#[tauri::command]
async fn fluxsync_pair_pending() -> Result<Value, String> {
    let resp = ipc::one_shot(json!({"id": 1, "op": "pair_pending"})).await?;
    Ok(resp.get("data").cloned().unwrap_or(Value::Null))
}

/// PR2: confirm or reject a pending pair after the user has matched
/// SAS words. `accept = false` revokes the peer (drops session +
/// `peers.json` row).
#[tauri::command]
async fn fluxsync_pair_confirm(peer_id: String, accept: bool) -> Result<(), String> {
    ipc::one_shot(json!({
        "id": 1,
        "op": "pair_confirm",
        "peer_id": peer_id,
        "accept": accept,
    }))
    .await
    .map(|_| ())
}

/// Open (or focus) the dedicated pair window. The popup-side JS calls
/// this when the user clicks the Pair CTA, so the flow doesn't depend
/// on the right-click menu item.
#[tauri::command]
fn fluxsync_open_pair(app: tauri::AppHandle) {
    open_pair_window(&app);
}

#[tauri::command]
fn fluxsync_open_settings(app: tauri::AppHandle) {
    open_settings_window(&app);
}

/// Public entry — called by `main.rs`. Builds the Tauri app, the
/// menu-bar tray icon, and a hidden popup window. The tray icon's
/// left-click toggles the popup; right-click shows a tiny native menu
/// (Preferences / Pair / Quit) so the app remains usable even if the
/// HTML window fails to load.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        // Window-close policy. The main "menu" window is the app's primary
        // window: FluxSync is menu-bar-only (no Dock icon), so its close
        // button never quits. The auxiliary "settings"/"pair" windows just
        // hide so they can be reopened (they are pre-declared once at boot).
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // The close button never quits. The primary "menu" window
                // hides via `hide_menu` (NSApp hide keeps the WKWebView
                // painted so re-show is instant, not white); the auxiliary
                // windows just hide. Quit via Cmd-Q or the tray menu.
                if window.label() == "menu" {
                    hide_menu(window.app_handle());
                } else {
                    let _ = window.hide();
                }
                api.prevent_close();
            }
        })
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_menu(app);
        }))
        .invoke_handler(tauri::generate_handler![
            fluxsync_status,
            fluxsync_toggle,
            fluxsync_set_threshold,
            fluxsync_set_charge_override,
            fluxsync_set_device_name,
            fluxsync_pair_show,
            fluxsync_pair_from_uri,
            fluxsync_pair_from_pin,
            fluxsync_pair_pending,
            fluxsync_pair_confirm,
            fluxsync_open_pair,
            fluxsync_open_settings,
            fluxsync_set_launch_at_login,
            fluxsync_get_launch_at_login,
            fluxsync_unpair,
            fluxsync_revoke_peer,
            fluxsync_set_firewall,
            fluxsync_resolve_pending,
            fluxsync_set_favorite,
            fluxsync_clear_history,
            fluxsync_open_url,
        ])
        .setup(|app| {
            // Menu-bar-only app: FluxSync never shows a Dock icon. Force
            // Accessory explicitly at boot — depending on how the bundle is
            // launched (LaunchAgent autostart, stale activation-policy
            // state) the OS can otherwise default to Regular. This is not
            // a user preference; it's a fixed product decision (2026-07-03).
            // The bundled release .app also sets `LSUIElement` in its
            // `Info.plist` (see `src-tauri/Info.plist`) so this holds even
            // before Tauri's own setup runs.
            #[cfg(target_os = "macos")]
            {
                use tauri::ActivationPolicy;
                let _ = app.handle().set_activation_policy(ActivationPolicy::Accessory);
            }

            // Make the tray app self-sufficient: probe the daemon's
            // UNIX socket and, if missing, spawn `fluxsyncd` detached
            // before the rest of `setup()` runs. Synchronous (≤ 8s) so
            // the first popup the user opens already sees a live
            // daemon. Failures are logged but never fatal — the tray
            // still boots and the popup can surface "daemon offline".
            ipc::ensure_daemon_running();

            // Bridge daemon state → Tauri events. The pair window listens
            // for `pairing-success` to swap the QR for a "Paired" badge;
            // without this the WebView has no way to know the Noise
            // handshake completed (the daemon runs in a separate process).
            //
            // Reconnect loop: the daemon can disappear (manual kill, crash)
            // and `subscribe_state` returns when the socket
            // closes. A short backoff keeps the bridge alive without spinning
            // when the daemon is genuinely gone. `last_name` lives across
            // reconnects so a stale snapshot replayed on the new connection
            // does not re-fire `pairing-success` for a peer we already saw.
            // Ensure notifications are allowed on macOS
            let ah_notif = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                use tauri_plugin_notification::NotificationExt;
                match ah_notif.notification().request_permission() {
                    Ok(perm) => eprintln!("[fluxsync-tray] notification permission: {:?}", perm),
                    Err(e) => eprintln!("[fluxsync-tray] notification permission request failed: {}", e),
                }
            });

            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                use std::sync::{Arc, Mutex};
                use std::time::Instant;
                let last_name: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
                let last_history_hash: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
                // Throttle `state-update` emits so a handshake burst can't
                // saturate the WebView IPC. 100 ms ≈ one paint frame.
                let last_emit: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

                loop {
                    let ah = app_handle.clone();
                    let ln = last_name.clone();
                    let lh = last_history_hash.clone();
                    let le = last_emit.clone();

                    let result = ipc::subscribe_state(move |state| {
                        // 0. Forward the full state to any window listening
                        //    on `state-update`. Replaces the per-window 1s
                        //    polling loops in app.js / settings.js.
                        {
                            let mut guard = le.lock().unwrap();
                            let now = Instant::now();
                            let allow = match *guard {
                                None => true,
                                Some(prev) => now.duration_since(prev).as_millis() >= 100,
                            };
                            if allow {
                                *guard = Some(now);
                                drop(guard);
                                let _ = ah.emit("state-update", state.clone());
                            }
                        }

                        // 1. Check for pairing success
                        let name = state
                            .get("peer_name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();

                        // 1a. Fire `pairing-success` only on a real
                        // unpaired→paired transition. `last_name` is reset to
                        // None whenever the daemon reports no peer, so the SAME
                        // device re-pairing after an unpair still counts as a
                        // fresh transition (fixes "can't scan after reset").
                        // Emitting on every name *change* caused the premature
                        // "Successfully paired" with no scan.
                        //
                        // TOFU_PLACEHOLDER: the daemon projects `peer_name` as
                        // the literal "New Peer" placeholder (see
                        // `fluxsyncd::handshake::TOFU_PLACEHOLDER_NAME`) the
                        // instant the handshake completes — before the peer's
                        // `Msg::Hello` lands with its real device name. That
                        // placeholder is NOT a confirmed identity, so it must
                        // not get "locked in" as the final paired name: keep
                        // it in the same bucket as empty/"pending" so the
                        // follow-up transition (placeholder → real name) is
                        // still treated as fresh and re-fires with the
                        // correct name once Hello lands.
                        const TOFU_PLACEHOLDER: &str = "New Peer";
                        {
                            let mut guard = ln.lock().unwrap();
                            if name.is_empty() {
                                // Unpaired / session reset → re-arm.
                                *guard = None;
                            } else if name == "pending" || name == TOFU_PLACEHOLDER {
                                *guard = Some(name.clone());
                            } else {
                                let was_unpaired = match &*guard {
                                    None => true,
                                    Some(p) => p.is_empty() || p == "pending" || p == TOFU_PLACEHOLDER,
                                };
                                *guard = Some(name.clone());
                                if was_unpaired {
                                    drop(guard);
                                    eprintln!("[fluxsync-tray] pairing-success emitted: {name}");
                                    let _ = ah.emit("pairing-success", name.clone());
                                    // Pair window closes itself on success; bring the
                                    // menu back so the user lands on the dashboard
                                    // (single-window: never leave zero windows).
                                    show_menu(&ah);
                                }
                            }
                        }

                        {
                            let first = state
                                .get("history")
                                .and_then(|h| h.as_array())
                                .and_then(|h| h.first());
                            let preview = first
                                .and_then(|f| f.get("preview"))
                                .and_then(|p| p.as_str())
                                .unwrap_or("");
                            let mut h_guard = lh.lock().unwrap();

                            // [FIX] RAM Protection: hash the preview instead of storing it raw.
                            // Protects the tray app from 10MB+ clipboard payloads.
                            let current_hash = blake3::hash(preview.as_bytes()).to_hex().to_string();

                            if h_guard.is_none() {
                                // First snapshot after launch: seed the dedup
                                // hash silently. The daemon restores persisted
                                // history (FluxVault), so history[0] may already
                                // be a remote item from a previous session.
                                *h_guard = Some(current_hash);
                            } else if !preview.is_empty() && h_guard.as_deref() != Some(current_hash.as_str()) {
                                *h_guard = Some(current_hash.clone());

                                // ❌ BUG FIX: Only notify if it came from the peer (remote)
                                let source = first.and_then(|f| f.get("source")).and_then(|s| s.as_str()).unwrap_or("local");
                                if source == "remote" {
                                    eprintln!("[fluxsync-tray] showing notification for remote clipboard change: hash={current_hash} len={}", preview.len());
                                    drop(h_guard);
                                    let kind = first.and_then(|f| f.get("kind")).and_then(|k| k.as_str());
                                    let peer = if name.is_empty() || name == "pending" || name == "New Peer" {
                                        state
                                            .get("trusted_peer_name")
                                            .and_then(|x| x.as_str())
                                            .filter(|s| !s.is_empty())
                                    } else {
                                        Some(name.as_str())
                                    };
                                    let body = match (kind, peer) {
                                        (Some(kind), Some(peer)) => {
                                            let noun = match kind {
                                                "image" => "image",
                                                "url" => "link",
                                                "code" => "code",
                                                _ => "text",
                                            };
                                            format!("Received {noun} from {peer}")
                                        }
                                        _ => "Clipboard received".to_string(),
                                    };
                                    // Show notification
                                    use tauri_plugin_notification::NotificationExt;
                                    match ah.notification()
                                        .builder()
                                        .title("FluxSync")
                                        .body(body)
                                        .show() {
                                            Ok(_) => eprintln!("[fluxsync-tray] notification .show() returned Ok"),
                                            Err(e) => eprintln!("[fluxsync-tray] notification .show() failed: {e}"),
                                        }
                                }
                            }
                        }
                    })
                    .await;
                    match result {
                        Ok(()) => eprintln!("[fluxsync-tray] state stream closed; reconnecting"),
                        Err(e) => eprintln!("[fluxsync-tray] state stream error: {e:#}"),
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            });

            // Native fallback menu on right-click.
            let open_item =
                MenuItem::with_id(app, "open", "Open FluxSync", true, None::<&str>)?;
            let pair_item = MenuItem::with_id(app, "pair", "Pair a device…", true, None::<&str>)?;
            let prefs_item =
                MenuItem::with_id(app, "prefs", "Preferences…", true, None::<&str>)?;
            let unpair_item =
                MenuItem::with_id(app, "unpair", "Unpair all devices…", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit FluxSync", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &open_item,
                    &PredefinedMenuItem::separator(app)?,
                    &pair_item,
                    &prefs_item,
                    &PredefinedMenuItem::separator(app)?,
                    &unpair_item,
                    &PredefinedMenuItem::separator(app)?,
                    &quit_item,
                ],
            )?;

            // macOS uses the 32×32 template PNG (matches menu-bar tint).
            // Windows needs an .ico — PNG → HICON conversion in Tauri v2
            // fails silently and the NotifyIcon never registers, so the
            // tray icon is invisible. Linux/other = coloured PNG.
            #[cfg(target_os = "macos")]
            let tray_icon = tauri::image::Image::from_bytes(
                include_bytes!("../icons/icon.png"),
            ).expect("decode tray icon");
            #[cfg(target_os = "windows")]
            let tray_icon = {
                let ico_bytes = include_bytes!("../icons/icon.ico");
                let img = ::image::load_from_memory(ico_bytes)
                    .expect("decode tray .ico").to_rgba8();
                let (w, h) = img.dimensions();
                tauri::image::Image::new_owned(img.into_raw(), w, h)
            };
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            let tray_icon = tauri::image::Image::from_bytes(
                include_bytes!("../icons/128x128.png"),
            ).expect("decode tray icon");

            // `mut` is only consumed by the macOS-only block below.
            #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
            let mut tray_builder = TrayIconBuilder::with_id("main")
                .icon(tray_icon)
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => app.exit(0),
                    "open" => show_menu(app),
                    "pair" => open_pair_window(app),
                    "prefs" => open_settings_window(app),
                    "unpair" => {
                        let confirmed = app
                            .dialog()
                            .message(
                                "Removes every trusted peer and resets pairing. \
                                 Use this when a daemon was reinstalled — it clears \
                                 the stale link so you can pair again. This cannot be undone.",
                            )
                            .title("Unpair all devices?")
                            .kind(MessageDialogKind::Warning)
                            .buttons(MessageDialogButtons::OkCancelCustom(
                                "Unpair".into(),
                                "Cancel".into(),
                            ))
                            .blocking_show();
                        if confirmed {
                            tauri::async_runtime::spawn(async {
                                match ipc::one_shot(json!({"id": 1, "op": "unpair"})).await {
                                    Ok(_) => eprintln!("[fluxsync-tray] unpaired all devices"),
                                    Err(e) => eprintln!("[fluxsync-tray] unpair failed: {e}"),
                                }
                            });
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        rect,
                        ..
                    } = event
                    {
                        toggle_popup(tray.app_handle(), Some(rect));
                    }
                });

            // macOS: render the glyph as a template image so it tracks
            // the menu-bar tint. `icon_as_template` is a macOS-only method.
            #[cfg(target_os = "macos")]
            {
                tray_builder = tray_builder.icon_as_template(true);
            }

            let _ = tray_builder.build(app)?;

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app, _event| {
            // macOS: relaunching FluxSync while it's already running (e.g.
            // via Finder/Spotlight/`open -a`) while the menu window is
            // hidden fires Reopen even though there's no Dock icon to
            // click. Bring the menu window back on-screen, centred and
            // focused.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = &_event {
                show_menu(_app);
            }
            // The user quit FluxSync (tray "Quit" → app.exit(0), or Cmd-Q).
            // Stop the daemon too: it was spawned detached (setsid) so it
            // would otherwise keep running, bound to UDP 41889 and syncing
            // the clipboard, with no UI left to stop it. Quit means quit.
            if let tauri::RunEvent::Exit = &_event {
                ipc::request_daemon_shutdown();
            }
        });
}

const MENU_W: f64 = 360.0;
const MENU_H: f64 = 540.0;

// macOS only: tracks whether the menu window is logically shown, so the
// tray-icon click can toggle it. We use a real `hide()` (not off-screen
// parking): with zero visible windows, `RunEvent::Reopen` (tray relaunch,
// see above) can bring the window back; an off-screen-parked window would
// still count as visible and skip that path.
#[cfg(target_os = "macos")]
static MENU_SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Bring the menu window on-screen, centred and focused.
fn show_menu(app: &tauri::AppHandle) {
    let Some(w) = app.get_webview_window("menu") else {
        return;
    };
    // Undo the NSApp hide from `hide_menu` before re-showing, else the
    // window lands on a still-hidden app and paints nothing.
    #[cfg(target_os = "macos")]
    let _ = app.show();
    if let Ok(Some(mon)) = app.primary_monitor() {
        let scale = mon.scale_factor();
        let msize = mon.size().to_logical::<f64>(scale);
        let mpos = mon.position().to_logical::<f64>(scale);
        let x = mpos.x + (msize.width - MENU_W) / 2.0;
        let y = mpos.y + (msize.height - MENU_H) / 2.0;
        let _ = w.set_position(tauri::LogicalPosition::new(x, y));
    }
    let _ = w.unminimize();
    let _ = w.show();
    let _ = w.set_focus();
    #[cfg(target_os = "macos")]
    MENU_SHOWN.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Dismiss the menu cleanly. macOS: `NSApp hide` keeps the WKWebView
/// composited (no white repaint on re-show) and leaves zero visible
/// windows, so the tray click re-shows via `show_menu` (or a relaunch via
/// `RunEvent::Reopen`). Unlike the old off-screen park, this is a real
/// hide — the red close button actually tucks the app to the menu bar.
fn hide_menu(app: &tauri::AppHandle) {
    #[cfg(target_os = "macos")]
    {
        let _ = app.hide();
        MENU_SHOWN.store(false, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(w) = app.get_webview_window("menu") {
        let _ = w.hide();
    }
}

/// Tray-click toggle.
fn toggle_popup(app: &tauri::AppHandle, _tray_rect: Option<tauri::Rect>) {
    #[cfg(target_os = "macos")]
    {
        if MENU_SHOWN.load(std::sync::atomic::Ordering::SeqCst) {
            hide_menu(app);
        } else {
            show_menu(app);
        }
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(w) = app.get_webview_window("menu") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
        } else {
            show_menu(app);
        }
    }
}

/// Open the dedicated pair window (separate WebView so the user can
/// keep the menu popup open in parallel).
fn open_pair_window(app: &tauri::AppHandle) {
    // Pair window is now declared in tauri.conf.json (visible:false at
    // boot). Runtime WebviewWindowBuilder cannot resolve bundled assets
    // on Windows: any `WebviewUrl::App("pair.html")` shows a blank
    // page. Pre-declared windows work because Tauri serves their URL
    // through the same path the menu/settings windows already use.
    // Separate-window UX: show it over the menu, don't hide the app.
    if let Some(w) = app.get_webview_window("pair") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Open the dedicated settings window.
fn open_settings_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("settings") {
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let _ = WebviewWindowBuilder::new(app, "settings", WebviewUrl::App("settings.html".into()))
        .title("FluxSync — Settings")
        .inner_size(760.0, 500.0)
        .resizable(false)
        .build();
}
