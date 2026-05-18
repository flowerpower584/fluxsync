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

use blake3;
use serde_json::{json, Value};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
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

#[tauri::command]
async fn fluxsync_set_launch_at_login(value: bool) -> Result<(), String> {
    // Forward to daemon which manages the launchd agent or use a tauri plugin.
    // For now, we just inform the daemon of the preference.
    ipc::one_shot(json!({"id": 1, "op": "set_launch_at_login", "value": value}))
        .await
        .map(|_| ())
}

#[tauri::command]
fn fluxsync_set_show_in_dock(app: tauri::AppHandle, value: bool) {
    use tauri::ActivationPolicy;
    if value {
        let _ = app.set_activation_policy(ActivationPolicy::Regular);
    } else {
        let _ = app.set_activation_policy(ActivationPolicy::Accessory);
    }
}

#[tauri::command]
async fn fluxsync_set_prefer_lan(value: bool) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "set_prefer_lan", "value": value}))
        .await
        .map(|_| ())
}

#[tauri::command]
async fn fluxsync_unpair() -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "unpair"}))
        .await
        .map(|_| ())
}

#[tauri::command]
fn fluxsync_open_url(url: String) {
    // Uses the shell plugin to open the system browser.
    // This is safer than window.open in some environments.
    let _ = std::process::Command::new("open").arg(url).spawn();
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

#[tauri::command]
async fn fluxsync_push(text: String) -> Result<(), String> {
    ipc::one_shot(json!({"id": 1, "op": "push", "text": text}))
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
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let _ = app.get_webview_window("menu").map(|w| {
                let _ = w.show();
                let _ = w.set_focus();
            });
        }))
        .invoke_handler(tauri::generate_handler![
            fluxsync_status,
            fluxsync_toggle,
            fluxsync_set_threshold,
            fluxsync_set_charge_override,
            fluxsync_pair_show,
            fluxsync_pair_from_uri,
            fluxsync_push,
            fluxsync_open_pair,
            fluxsync_open_settings,
            fluxsync_set_launch_at_login,
            fluxsync_set_show_in_dock,
            fluxsync_set_prefer_lan,
            fluxsync_unpair,
            fluxsync_open_url,
        ])
        .setup(|app| {
            // Make the tray app self-sufficient: probe the daemon's
            // UNIX socket and, if missing, spawn `fluxsyncd` detached
            // before the rest of `setup()` runs. Synchronous (≤ 3s) so
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
                let last_history_hash: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
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
                        
                        // 1a. Check for peer name change (for QR window closing)
                        // 1a. Check for peer name change (for QR window closing)
                        if !name.is_empty() {
                            let mut guard = ln.lock().unwrap();
                            let should_emit = match &*guard {
                                // [FIX] Zero-Day: Always emit if we went from "pending" to a real name,
                                // or if the name changed. The old logic prevented emitting if the Android
                                // rejoined with the EXACT SAME NAME as the previous session!
                                Some(prev_name) => prev_name.is_empty() || prev_name == "pending" || prev_name != &name,
                                None => true,
                            };

                            if should_emit && name != "pending" {
                                *guard = Some(name.clone());
                                drop(guard);
                                eprintln!("[fluxsync-tray] pairing-success emitted: {name}");
                                let _ = ah.emit("pairing-success", name.clone());
                            } else if name == "pending" {
                                *guard = Some(name.clone());
                            }
                        }

                        if let Some(history) = state.get("history").and_then(|h| h.as_array()) {
                            if let Some(first) = history.first() {
                                if let Some(preview) = first.get("preview").and_then(|p| p.as_str()) {
                                    let mut h_guard = lh.lock().unwrap();
                                    
                                    // [FIX] RAM Protection: hash the preview instead of storing it raw.
                                    // Protects the tray app from 10MB+ clipboard payloads.
                                    let current_hash = blake3::hash(preview.as_bytes()).to_hex().to_string();

                                    if !preview.is_empty() && *h_guard != current_hash {
                                        *h_guard = current_hash;
                                        
                                        // ❌ BUG FIX: Only notify if it came from the peer (remote)
                                        let source = first.get("source").and_then(|s| s.as_str()).unwrap_or("local");
                                        if source == "remote" {
                                            eprintln!("[fluxsync-tray] showing notification for remote clipboard change: {}", preview);
                                            drop(h_guard);
                                            // Show notification
                                            use tauri_plugin_notification::NotificationExt;
                                            match ah.notification()
                                                .builder()
                                                .title("FluxSync")
                                                .body(format!("Received: {}", if preview.len() > 50 { format!("{}...", &preview[..47]) } else { preview.to_string() }))
                                                .show() {
                                                    Ok(_) => eprintln!("[fluxsync-tray] notification .show() returned Ok"),
                                                    Err(e) => eprintln!("[fluxsync-tray] notification .show() failed: {e}"),
                                                }
                                        }
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
            let pair_item = MenuItem::with_id(app, "pair", "Pair a device…", true, None::<&str>)?;
            let prefs_item =
                MenuItem::with_id(app, "prefs", "Preferences…", true, None::<&str>)?;
            let unpair_item =
                MenuItem::with_id(app, "unpair", "Unpair all devices…", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit FluxSync", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &pair_item,
                    &prefs_item,
                    &PredefinedMenuItem::separator(app)?,
                    &unpair_item,
                    &PredefinedMenuItem::separator(app)?,
                    &quit_item,
                ],
            )?;

            // Embed the tray PNG at compile time. `build.rs` generates
            // it before the macro expands, so this always resolves to a
            // real 32×32 black-on-transparent template image rather than
            // depending on whatever Tauri picks for `default_window_icon`.
            const TRAY_ICON_PNG: &[u8] = include_bytes!("../icons/icon.png");
            let tray_icon = tauri::image::Image::from_bytes(TRAY_ICON_PNG)
                .expect("decode embedded tray icon");

            let _ = TrayIconBuilder::with_id("main")
                .icon(tray_icon)
                .icon_as_template(true)
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => app.exit(0),
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
                .on_tray_icon_event(|tray, event| match event {
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } => {
                        toggle_popup(tray.app_handle());
                    }
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Show or hide the borderless 360 × 540 popup that lives at
/// `src/index.html`. The window is created hidden in
/// `tauri.conf.json` so first-show is just `.show()`.
fn toggle_popup<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(w) = app.get_webview_window("menu") {
        let visible = w.is_visible().unwrap_or(false);
        if visible {
            let _ = w.hide();
        } else {
            let _ = w.show();
            let _ = w.set_focus();
        }
    }
}

/// Open the dedicated pair window (separate WebView so the user can
/// keep the menu popup open in parallel).
fn open_pair_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(w) = app.get_webview_window("pair") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let _ = WebviewWindowBuilder::new(app, "pair", WebviewUrl::App("pair.html".into()))
        .title("FluxSync — Pair")
        .inner_size(420.0, 540.0)
        .resizable(false)
        .build();
}

/// Open the dedicated settings window.
fn open_settings_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
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
