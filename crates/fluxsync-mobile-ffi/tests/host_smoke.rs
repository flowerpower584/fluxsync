//! Host-side smoke test: drive the FFI surface from Rust the same way
//! Kotlin will, then verify `poll_state()` returns the expected JSON.
//! Lets us catch FFI regressions in CI without an Android device.
//!
//! Skipped on Windows because the daemon's IPC layer is Unix-socket
//! only in v0.1.

#![cfg(unix)]

use fluxsync_mobile_ffi::{FluxsyncHandle, IdentitySource};

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
        IdentitySource::Generate,
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
        IdentitySource::Generate,
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
        IdentitySource::SecretBase64 {
            secret: "not-base64-!!".into(),
        },
    );
    assert!(res.is_err(), "expected InvalidIdentity error");
}

/// DIR-P2-02: `IdentitySource::Provided` is the injection path Android's
/// `KeystoreIdentityStore` hands the AndroidKeyStore-decrypted secret to.
/// This drives it the same way Kotlin will — a raw 32-byte secret plus
/// the app-private dir — and checks the daemon boots and round-trips a
/// push, and that `dir` still wires up peers/firewall persistence the
/// same as `IdentitySource::Keystore` (verified indirectly: `start()`
/// succeeds, which requires `keystore_dir` to be set for `start_on`/
/// peers.json loading to run without error).
#[test]
fn ffi_provided_identity_starts_and_roundtrips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("ffi-provided.sock");
    let port = pick_free_udp_port();

    let handle = FluxsyncHandle::start(
        "host-test".into(),
        ipc.to_string_lossy().into_owned(),
        port,
        IdentitySource::Provided {
            secret: [0x11u8; 32].to_vec(),
            dir: dir.path().to_string_lossy().into_owned(),
        },
    )
    .expect("start with Provided identity");

    handle.push_text("provided-identity-ok".into()).expect("push");

    let start = std::time::Instant::now();
    let mut hit = false;
    while start.elapsed() < std::time::Duration::from_secs(2) {
        if handle.poll_state().contains("provided-identity-ok") {
            hit = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    handle.stop();
    assert!(hit, "poll_state never saw the pushed text in JSON state");
}

/// DIR-P2-02: a secret of the wrong length must be rejected, not
/// silently truncated/padded — that would derive a different identity
/// than the one Kotlin decrypted, unpairing the device from every peer.
#[test]
fn ffi_rejects_bad_provided_length() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("ffi-provided-len.sock");
    let port = pick_free_udp_port();

    let res = FluxsyncHandle::start(
        "host-test".into(),
        ipc.to_string_lossy().into_owned(),
        port,
        IdentitySource::Provided {
            secret: vec![0x11u8; 31],
            dir: dir.path().to_string_lossy().into_owned(),
        },
    );
    assert!(res.is_err(), "expected error for a 31-byte secret");
}

/// DIR-P2-02: an empty `dir` must be rejected up front, mirroring
/// `IdentitySource::Keystore`'s empty-dir guard — silently accepting it
/// would boot with `keystore_dir = None` and lose peers/firewall
/// persistence + auto-start without any signal to the caller.
#[test]
fn ffi_rejects_empty_provided_dir() {
    let ipc_dir = tempfile::tempdir().expect("tempdir");
    let ipc = ipc_dir.path().join("ffi-provided-dir.sock");
    let port = pick_free_udp_port();

    let res = FluxsyncHandle::start(
        "host-test".into(),
        ipc.to_string_lossy().into_owned(),
        port,
        IdentitySource::Provided {
            secret: [0x11u8; 32].to_vec(),
            dir: String::new(),
        },
    );
    assert!(res.is_err(), "expected error for an empty dir");
}

#[test]
fn ffi_rejects_empty_peer_name() {
    // SE-05: empty peer_name used to be accepted silently — the daemon
    // would then advertise a blank mDNS service. Now it errors out.
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("ffi-pn.sock");
    let port = pick_free_udp_port();
    let res = FluxsyncHandle::start(
        "   ".into(),
        ipc.to_string_lossy().into_owned(),
        port,
        IdentitySource::Generate,
    );
    assert!(res.is_err(), "expected Invalid error for empty peer_name");
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
                port,
                IdentitySource::Generate,
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
