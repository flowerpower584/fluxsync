//! Password-manager "don't record this" markers on the OS clipboard.
//!
//! Password managers flag the passwords they copy so clipboard tools leave
//! them alone: `org.nspasteboard.ConcealedType` / `TransientType` on macOS,
//! `ExcludeClipboardContentFromMonitorProcessing` (and the older
//! `Clipboard Viewer Ignore`) on Windows, `x-kde-passwordManagerHint` on
//! Linux. FluxSync still syncs such an item — copying a password on one
//! device to paste it on another is a real use — but as a sensitive one:
//! never kept in history or on disk, and cleared from the receiving
//! clipboard after a minute.
//!
//! Best effort: any error reads as "not marked".

/// Whether the clipboard's current content carries a password-manager
/// "secret" marker. Blocking — call it off the async runtime.
#[cfg(target_os = "macos")]
pub(super) fn clipboard_marked_secret() -> bool {
    use objc2_app_kit::NSPasteboard;
    const MARKERS: [&str; 2] = [
        "org.nspasteboard.ConcealedType",
        "org.nspasteboard.TransientType",
    ];
    let Some(types) = NSPasteboard::generalPasteboard().types() else {
        return false;
    };
    types
        .to_vec()
        .iter()
        .any(|t| MARKERS.contains(&t.to_string().as_str()))
}

/// See the macOS variant.
#[cfg(target_os = "windows")]
pub(super) fn clipboard_marked_secret() -> bool {
    const MARKERS: [&str; 2] = [
        "ExcludeClipboardContentFromMonitorProcessing",
        "Clipboard Viewer Ignore",
    ];
    MARKERS.iter().any(|name| {
        clipboard_win::register_format(name)
            .is_some_and(|format| clipboard_win::is_format_avail(format.get()))
    })
}

/// See the macOS variant. Wayland first, X11 otherwise.
#[cfg(target_os = "linux")]
pub(super) fn clipboard_marked_secret() -> bool {
    use wl_clipboard_rs::paste::{get_mime_types, ClipboardType, Seat};
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return get_mime_types(ClipboardType::Regular, Seat::Unspecified)
            .is_ok_and(|types| types.contains(LINUX_MARKER));
    }
    std::env::var_os("DISPLAY").is_some() && x11_marked_secret().unwrap_or(false)
}

#[cfg(target_os = "linux")]
const LINUX_MARKER: &str = "x-kde-passwordManagerHint";

/// Ask the X11 clipboard owner for its TARGETS and look for the marker.
/// Gives up after 150 ms (an owner that never answers reads as unmarked).
#[cfg(target_os = "linux")]
fn x11_marked_secret() -> Option<bool> {
    use std::time::{Duration, Instant};
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _, CreateWindowAux, WindowClass};
    use x11rb::protocol::Event;

    let (conn, screen_num) = x11rb::connect(None).ok()?;
    let root = conn.setup().roots.get(screen_num)?.root;
    let atom = |name: &str| -> Option<u32> {
        Some(
            conn.intern_atom(false, name.as_bytes())
                .ok()?
                .reply()
                .ok()?
                .atom,
        )
    };
    let clipboard = atom("CLIPBOARD")?;
    let targets = atom("TARGETS")?;
    let prop = atom("FLUXSYNC_TARGETS")?;
    let marker = atom(LINUX_MARKER)?;
    let win = conn.generate_id().ok()?;
    conn.create_window(
        x11rb::COPY_DEPTH_FROM_PARENT,
        win,
        root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_ONLY,
        x11rb::COPY_FROM_PARENT,
        &CreateWindowAux::new(),
    )
    .ok()?;
    conn.convert_selection(win, clipboard, targets, prop, x11rb::CURRENT_TIME)
        .ok()?;
    conn.flush().ok()?;
    let deadline = Instant::now() + Duration::from_millis(150);
    let answered = loop {
        match conn.poll_for_event().ok()? {
            Some(Event::SelectionNotify(e)) if e.requestor == win => {
                break e.property != x11rb::NONE
            }
            Some(_) => {}
            None if Instant::now() >= deadline => break false,
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    };
    let found = answered
        && conn
            .get_property(false, win, prop, AtomEnum::ATOM, 0, 1024)
            .ok()?
            .reply()
            .ok()?
            .value32()
            .is_some_and(|mut atoms| atoms.any(|a| a == marker));
    let _ = conn.destroy_window(win);
    let _ = conn.flush();
    Some(found)
}

/// No marker convention elsewhere.
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub(super) fn clipboard_marked_secret() -> bool {
    false
}
