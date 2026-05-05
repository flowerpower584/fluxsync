//! Host-side smoke test: drive the FFI surface from Rust the same way
//! Kotlin will, then verify `poll_state()` returns the expected JSON.
//! Lets us catch FFI regressions in CI without an Android device.
//!
//! Skipped on Windows because the daemon's IPC layer is Unix-socket
//! only in v0.1.

#![cfg(unix)]

use fluxsync_mobile_ffi::FluxsyncHandle;


fn pick_free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().unwrap().port()
}

#[test]
fn ffi_roundtrip_push_text_observes_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("ffi.sock");
    let port = pick_free_udp_port();

    let handle = FluxsyncHandle::start(
        "host-test".into(),
        ipc.to_string_lossy().into_owned(),
        port,
        String::new(), // empty = generate fresh keypair
    )
    .expect("start");

    // Wait briefly so the state subscriber gets the initial snapshot.
    std::thread::sleep(std::time::Duration::from_millis(300));

    handle.push_text("https://kaolack.sn".into()).expect("push");

    // Poll up to 2s for the JSON containing our preview.
    let start = std::time::Instant::now();
    let mut hit = false;
    while start.elapsed() < std::time::Duration::from_secs(2) {
        let raw = handle.poll_state();
        if raw.contains("https://kaolack.sn") {
            hit = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    handle.stop();
    assert!(hit, "poll_state never saw the pushed text in JSON state");
}

#[test]
fn ffi_rejects_invalid_threshold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("ffi-thr.sock");
    let port = pick_free_udp_port();

    let handle = FluxsyncHandle::start(
        "host-test".into(),
        ipc.to_string_lossy().into_owned(),
        port,
        String::new(),
    )
    .expect("start");

    assert!(handle.set_battery_threshold(4).is_err());
    assert!(handle.set_battery_threshold(51).is_err());
    assert!(handle.set_battery_threshold(15).is_ok());
    assert!(handle.set_battery_threshold(50).is_ok());

    handle.stop();
}

#[test]
fn ffi_rejects_bad_identity_b64() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("ffi-id.sock");
    let port = pick_free_udp_port();

    let res = FluxsyncHandle::start(
        "host-test".into(),
        ipc.to_string_lossy().into_owned(),
        port,
        "not-base64-!!".into(),
    );
    assert!(res.is_err(), "expected InvalidIdentity error");
}
