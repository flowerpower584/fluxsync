//! REGRESSION (candidate C5): IPC NDJSON line parsing is now length-capped.
//!
//! `handle_ipc_client` (driver.rs) no longer calls the unbounded
//! `BufReader::read_line`. It uses `read_line_capped(.., MAX_IPC_LINE)`
//! (MAX_IPC_LINE = 64 MiB). `read_line_capped` accumulates via
//! `fill_buf`/`consume` and returns `std::io::ErrorKind::InvalidData` the
//! moment a single newline-less line would exceed the cap, which makes
//! `handle_ipc_client` return `Err` and the daemon close the connection —
//! so a malicious/buggy local client can no longer stream an unbounded line
//! to OOM the daemon.
//!
//! This drives the REAL daemon IPC server in-process and asserts the FIXED
//! behaviour:
//!   * CONTROL — a normal, newline-terminated, under-cap line is processed
//!     and answered (the connection stays open). Proves the cap does not
//!     break legitimate traffic.
//!   * CAP — a single newline-less line just over the 64 MiB cap is rejected:
//!     the daemon tears the connection down (write breaks / clean EOF on
//!     read) instead of buffering it unbounded.
//!
//! Memory-safe by design: we send ~70 MiB (one chunk over the 64 MiB cap) —
//! never the 300 MiB the old bug probe used — and the daemon stops reading
//! and closes once the cap is crossed, so resident memory stays bounded.
//! The real production cap is MAX_IPC_LINE = 64 MiB.

#![cfg(unix)]

use fluxsync_crypto::Identity;
use fluxsyncd::{run, DaemonConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio_util::sync::CancellationToken;

async fn pick_free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.expect("pick port");
    s.local_addr().expect("port").port()
}

/// RSS of a pid in KiB (macOS/Linux `ps -o rss=`). Informational only.
fn rss_kb(pid: u32) -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("run ps");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_line_is_length_capped_no_oom() {
    let _ = tracing_subscriber::fmt::try_init();

    // ---- boot one real daemon, IPC only (no clipboard, no mDNS, no peer)
    let id = Identity::generate();
    let port = pick_free_udp_port().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let ipc = dir.path().join("a.sock");

    let mut cfg = DaemonConfig::new(id, port, ipc.clone());
    cfg.udp_bind = "127.0.0.1".into();
    cfg.disable_clipboard = true;
    cfg.disable_mdns = true;
    cfg.peer_name_self = "device-a".into();

    let shutdown = CancellationToken::new();
    let sd = shutdown.clone();
    let daemon = tokio::spawn(async move { run(cfg, sd).await });

    // wait for the IPC socket to accept connections
    let mut stream = None;
    for _ in 0..200 {
        if let Ok(s) = UnixStream::connect(&ipc).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let stream = stream.expect("ipc never came up");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // open the Cmd channel (valid opening line, terminated)
    write_half
        .write_all(b"{\"subscribe\":\"cmd\"}\n")
        .await
        .expect("subscribe");
    write_half.flush().await.expect("flush sub");

    // ---- CONTROL: a normal, terminated, under-cap line is processed and
    // answered. `not-json` is below the cap, so the capped reader hands it to
    // the parser, which replies with an error envelope — and crucially the
    // connection stays open. This proves the length cap does not break
    // ordinary IPC traffic.
    write_half
        .write_all(b"not-json\n")
        .await
        .expect("write control");
    write_half.flush().await.expect("flush control");

    let mut resp = String::new();
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut resp))
        .await
        .expect("control: daemon never answered an under-cap line")
        .expect("control: read error");
    assert!(
        n > 0,
        "control: expected a response line for a bounded request"
    );
    assert!(
        resp.contains("\"ok\":false") && resp.contains("bad json"),
        "control: expected a CmdResponse error envelope, got: {resp:?}"
    );

    let pid = std::process::id();
    let base = rss_kb(pid);

    // ---- CAP: stream ONE un-terminated line just over the 64 MiB cap.
    // The daemon reads until accumulation crosses MAX_IPC_LINE, returns
    // InvalidData, and closes the connection. Because it stops reading at the
    // cap, our write_all will eventually hit a broken pipe; if not, the read
    // side observes a clean EOF. Either outcome == the line was rejected.
    let chunk = vec![b'a'; 1024 * 1024]; // 1 MiB of payload, never a newline
    let chunks = 70u64; // 70 MiB on a single line -> just over the 64 MiB cap
    let mut sent_mib = 0u64;
    let mut write_broke = false;
    for _ in 0..chunks {
        match tokio::time::timeout(Duration::from_secs(5), write_half.write_all(&chunk)).await {
            Ok(Ok(())) => sent_mib += 1,
            Ok(Err(_)) => {
                // daemon closed its read half after the cap -> broken pipe
                write_broke = true;
                break;
            }
            Err(elapsed) => panic!(
                "CAP: write blocked >5s after {sent_mib} MiB ({elapsed}) — daemon kept \
                 draining a newline-less line (cap not enforced?)"
            ),
        }
    }
    let _ = write_half.flush().await;

    // If the writes all went through, the rejection shows up as a clean EOF
    // (or read error) on the next read — the daemon dropped the connection.
    let mut tail = String::new();
    let closed =
        match tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut tail)).await {
            Ok(Ok(0) | Err(_)) => true, // clean EOF, or connection reset == torn down
            Ok(Ok(_)) | Err(_) => false, // over-cap reply, or timed out buffering -> unbounded (bug)
        };

    let after = rss_kb(pid);
    // RSS KiB values never approach 2^52; no precision loss in practice.
    #[allow(clippy::cast_precision_loss)]
    let growth_mib = (after.saturating_sub(base)) as f64 / 1024.0;
    eprintln!(
        "C5 REGRESSION: over-cap line ({sent_mib} MiB written, cap = 64 MiB) \
         write_broke={write_broke} closed={closed} | RSS base={base} KiB \
         after={after} KiB growth={growth_mib:.1} MiB"
    );

    // tidy up the daemon before final asserts
    shutdown.cancel();
    drop(write_half);
    drop(reader);
    let _ = tokio::time::timeout(Duration::from_secs(5), daemon).await;

    // FIXED behaviour: the daemon rejected the over-cap line instead of
    // buffering it. The rejection manifests as a broken write pipe and/or a
    // closed connection on read.
    assert!(
        write_broke || closed,
        "over-cap IPC line ({sent_mib} MiB on one newline-less line, cap = 64 MiB) \
         was NOT rejected: the daemon neither closed the connection nor broke the \
         write — read_line cap is not enforced (OOM DoS regression)."
    );

    // It also did not buffer the whole 70 MiB: a capped daemon stops at ~64 MiB
    // and frees it on close, so resident growth stays well under the sent size.
    // (Informational guard — generous bound to avoid host flakiness.)
    assert!(
        growth_mib < 200.0,
        "daemon RSS grew {growth_mib:.1} MiB for one capped line — unexpected \
         unbounded buffering."
    );
}
