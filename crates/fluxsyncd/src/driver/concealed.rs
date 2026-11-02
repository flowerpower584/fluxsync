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
//! Best effort: any error reads as "not marked". On Linux only Wayland is
//! checked; X11 relies on the content-based secret detection alone.

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

/// See the macOS variant.
#[cfg(target_os = "linux")]
pub(super) fn clipboard_marked_secret() -> bool {
    use wl_clipboard_rs::paste::{get_mime_types, ClipboardType, Seat};
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return false;
    }
    get_mime_types(ClipboardType::Regular, Seat::Unspecified)
        .is_ok_and(|types| types.contains("x-kde-passwordManagerHint"))
}

/// No marker convention elsewhere.
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub(super) fn clipboard_marked_secret() -> bool {
    false
}
