//! A copied file reaches the other device intact, under its name, and
//! shows in its history as a file — only between versions that both
//! negotiated `file-1`.

#![cfg(unix)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fluxsync_core::Kind;
use fluxsync_crypto::{test_util::pair_for_test, Identity};
use fluxsyncd::{
    cmd::{CmdData, CmdOp, CmdRequest, CmdResponse},
    run, DaemonConfig, TestPair,
};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixStream};
use tokio_util::sync::CancellationToken;

async fn pick_free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.expect("pick port");
    s.local_addr().expect("port").port()
}

async fn ipc_send_recv(path: &Path, req: CmdRequest) -> CmdResponse {
    let mut stream = UnixStream::connect(path).await.expect("connect ipc");
    stream
        .write_all(b"{\"subscribe\":\"cmd\"}\n")
        .await
        .expect("subscribe");
    stream.flush().await.expect("flush subscribe");
    let line = serde_json::to_string(&req).unwrap() + "\n";
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let (read, _w) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut buf = String::new();
    reader.read_line(&mut buf).await.unwrap();
    serde_json::from_str(buf.trim()).expect("parse resp")
}

async fn wait_until<F, Fut>(deadline: Duration, mut probe: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if probe().await {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn status(ipc: &Path) -> Box<fluxsync_core::State> {
    match ipc_send_recv(
        ipc,
        CmdRequest {
            id: 1,
            op: CmdOp::Status,
        },
    )
    .await
    .data
    {
        Some(CmdData::State(s)) => s,
        other => panic!("expected State, got {other:?}"),
    }
}

/// A tiny, genuinely-decodable PNG (not a synthetic byte string) so the
/// daemon's `decode_png_to_rgba` accepts it. `fill` varies the pixel data so
/// the control and secret images have different content hashes.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_arrives_intact_with_its_name() {
    let _ = tracing_subscriber::fmt::try_init();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let peer_id_a = id_a.peer_id();
    let peer_id_b = id_b.peer_id();
    let (sess_a, sess_b) = pair_for_test(&id_a, &id_b).expect("pair");

    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    assert_ne!(port_a, port_b);

    let dir = tempfile::tempdir().expect("tempdir");
    let keystore_a = dir.path().join("ks-a");
    let keystore_b = dir.path().join("ks-b");
    std::fs::create_dir(&keystore_a).unwrap();
    std::fs::create_dir(&keystore_b).unwrap();
    let ipc_a = keystore_a.join("a.sock");
    let ipc_b = keystore_b.join("b.sock");

    let addr_a: SocketAddr = format!("127.0.0.1:{port_a}").parse().unwrap();
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();

    let mut cfg_a = DaemonConfig::new(id_a.clone(), port_a, ipc_a.clone());
    cfg_a.udp_bind = "127.0.0.1".into();
    cfg_a.disable_clipboard = true;
    cfg_a.disable_mdns = true;
    cfg_a.peer_name_self = "device-a".into();
    cfg_a.keystore_dir = Some(keystore_a.clone());
    cfg_a.test_pair = Some(TestPair {
        session: sess_a,
        peer_addr: addr_b,
        peer_name: "device-b".into(),
        peer_id: peer_id_b,
    });

    let mut cfg_b = DaemonConfig::new(id_b.clone(), port_b, ipc_b.clone());
    cfg_b.udp_bind = "127.0.0.1".into();
    cfg_b.disable_clipboard = true;
    cfg_b.disable_mdns = true;
    cfg_b.peer_name_self = "device-b".into();
    cfg_b.keystore_dir = Some(keystore_b.clone());
    cfg_b.test_pair = Some(TestPair {
        session: sess_b,
        peer_addr: addr_a,
        peer_name: "device-a".into(),
        peer_id: peer_id_a,
    });

    let shutdown_a = CancellationToken::new();
    let shutdown_b = CancellationToken::new();
    let h_a = tokio::spawn(run(cfg_a, shutdown_a.clone()));
    let h_b = tokio::spawn(run(cfg_b, shutdown_b.clone()));

    let linked_a = wait_until(Duration::from_secs(3), || async {
        ipc_a.exists() && status(&ipc_a).await.peer_name == "device-b"
    })
    .await;
    assert!(linked_a, "daemon A did not link to B in 3s");
    let linked_b = wait_until(Duration::from_secs(3), || async {
        ipc_b.exists() && status(&ipc_b).await.peer_name == "device-a"
    })
    .await;
    assert!(linked_b, "daemon B did not link to A in 3s");

    assert!(
        wait_until(Duration::from_secs(3), || async {
            status(&ipc_a)
                .await
                .peer_caps
                .iter()
                .any(|c| c == fluxsync_proto::CAP_FILE)
        })
        .await,
        "A never learned that B accepts files"
    );

    // 300 KB: several hundred chunks, not valid UTF-8.
    let bytes: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let resp = ipc_send_recv(
        &ipc_a,
        CmdRequest {
            id: 1,
            op: CmdOp::PushFile {
                name: "../report.bin".into(),
                data: B64.encode(&bytes),
            },
        },
    )
    .await;
    assert!(resp.ok, "push_file failed: {resp:?}");

    let arrived = wait_until(Duration::from_secs(10), || async {
        status(&ipc_b)
            .await
            .history
            .iter()
            .any(|h| h.kind == Kind::File && h.preview.starts_with("📎 report.bin"))
    })
    .await;
    assert!(arrived, "the file never showed in B's history");
    let hash = status(&ipc_b)
        .await
        .history
        .iter()
        .find(|h| h.kind == Kind::File)
        .map(|h| h.hash.clone())
        .unwrap();

    let fetched = ipc_send_recv(
        &ipc_b,
        CmdRequest {
            id: 2,
            op: CmdOp::FetchItem { hash },
        },
    )
    .await;
    let Some(CmdData::ItemBytes { bytes: b64 }) = fetched.data else {
        panic!("fetch_item returned no bytes: {fetched:?}");
    };
    let payload = B64.decode(b64).unwrap();
    let (name, got) = fluxsync_proto::file::decode(&payload).expect("file framing");
    assert_eq!(name, "report.bin", "the name can't climb out of the folder");
    assert_eq!(got, bytes.as_slice());

    shutdown_a.cancel();
    shutdown_b.cancel();
    let _ = h_a.await;
    let _ = h_b.await;
}
