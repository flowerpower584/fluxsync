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
        String::new(), // keystore_dir empty = ephemeral
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
        String::new(), // keystore_dir empty = ephemeral
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
        String::new(), // keystore_dir empty = ephemeral
        port,
        "not-base64-!!".into(),
    );
    assert!(res.is_err(), "expected InvalidIdentity error");
}

/// FS-051 regression: `stop()` must always return.
///
/// The original shutdown signal was a `tokio::sync::Notify`; `stop()`
/// fired `notify_waiters()`, which only wakes tasks *currently* parked
/// on `notified()` and stores no permit. Any daemon task momentarily
/// between `select!` awaits missed the signal, looped forever, and
/// `run()`'s task-drain never finished — so `stop()`'s `join()` blocked
/// for good. The race is intermittent, so we cycle start/stop and guard
/// with a watchdog: on the buggy code one cycle eventually wedges.
#[test]
fn ffi_stop_is_prompt_under_repeated_cycles() {
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        for i in 0..30 {
            let dir = tempfile::tempdir().expect("tempdir");
            let ipc = dir.path().join(format!("ffi-cycle-{i}.sock"));
            let port = pick_free_udp_port();
            let handle = FluxsyncHandle::start(
                "host-test".into(),
                ipc.to_string_lossy().into_owned(),
                String::new(),
                port,
                String::new(),
            )
            .expect("start");
            // Exercise the IPC path so a handler task is in flight near
            // stop() — widens the shutdown-race window.
            handle.push_text(format!("cycle-{i}")).ok();
            handle.stop();
        }
        tx.send(()).expect("done signal");
    });
    match rx.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(()) => worker.join().expect("worker panicked"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("FS-051: stop() hung — 30 start/stop cycles did not finish in 60s")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            worker
                .join()
                .expect("worker thread panicked during start/stop cycles");
            unreachable!("worker dropped the channel without signalling completion");
        }
    }
}
