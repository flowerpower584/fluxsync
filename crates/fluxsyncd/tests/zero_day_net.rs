use anyhow::Result;
use fluxsync_crypto::{test_util, Identity};
use fluxsync_proto::{Frame, Heartbeat, Hello, Msg, PROTOCOL_VERSION};
use fluxsyncd::transport::{RecvFrame, Transport, TYPE_ENCRYPTED, TYPE_HANDSHAKE_INIT};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Setup a real transport on a random port
async fn setup_transport() -> (Arc<Transport>, u16) {
    let (t, port) = Transport::bind("127.0.0.1", 0).await.unwrap();
    (Arc::new(t), port)
}

fn is_encrypted(frame: &RecvFrame) -> bool {
    matches!(frame, RecvFrame::Encrypted { .. })
}

// =============================================================================
// CATEGORY 1: PROTOCOL & FRAMING ATTACKS
// =============================================================================

#[tokio::test]
async fn test_01_malformed_type_byte() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let attacker = UdpSocket::bind("127.0.0.1:0").await?;
    let target = format!("127.0.0.1:{port}");
    attacker.send_to(&[0xFF, 0x00, 0x01], &target).await?;
    let mut buf = [0u8; 1024];
    let res = transport.recv(&mut buf).await?;
    if let RecvFrame::Other { type_byte, .. } = res {
        assert_eq!(type_byte, 0xFF);
    } else {
        panic!("Should have caught unknown type");
    }
    Ok(())
}

#[tokio::test]
async fn test_02_empty_packet_dos() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let attacker = UdpSocket::bind("127.0.0.1:0").await?;
    attacker.send_to(&[], format!("127.0.0.1:{port}")).await?;
    let mut buf = [0u8; 1024];
    let res = transport.recv(&mut buf).await?;
    assert!(matches!(res, RecvFrame::Other { .. }));
    Ok(())
}

#[tokio::test]
async fn test_03_handshake_replay_attack() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let attacker = UdpSocket::bind("127.0.0.1:0").await?;
    let mut packet = vec![TYPE_HANDSHAKE_INIT];
    packet.extend_from_slice(&[0u8; 32]);
    for _ in 0..5 {
        attacker
            .send_to(&packet, format!("127.0.0.1:{port}"))
            .await?;
    }
    let mut buf = [0u8; 1024];
    for _ in 0..5 {
        let res = transport.recv(&mut buf).await?;
        assert!(matches!(res, RecvFrame::HandshakeInit { .. }));
    }
    Ok(())
}

// =============================================================================
// CATEGORY 2: CRYPTO & SESSION ATTACKS
// =============================================================================

#[tokio::test]
async fn test_04_auth_tag_corruption() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let (mut s1, s2) =
        test_util::pair_for_test(&Identity::generate(), &Identity::generate()).unwrap();
    transport.install_session([0u8; 32], s2).await;
    let mut ct = s1.encrypt(b"HELLO").unwrap();
    let len = ct.len();
    ct[len - 1] ^= 0xFF; // Corrupt tag
    let mut packet = vec![TYPE_ENCRYPTED];
    packet.extend_from_slice(&ct);
    UdpSocket::bind("127.0.0.1:0")
        .await?
        .send_to(&packet, format!("127.0.0.1:{port}"))
        .await?;
    let mut buf = [0u8; 1024];
    let res = transport.recv(&mut buf).await;
    assert!(res.is_err());
    Ok(())
}

#[tokio::test]
async fn test_05_session_hijack_attempt() -> Result<()> {
    let (transport, port) = setup_transport().await;
    UdpSocket::bind("127.0.0.1:0")
        .await?
        .send_to(&[TYPE_ENCRYPTED, 0x01], format!("127.0.0.1:{port}"))
        .await?;
    let mut buf = [0u8; 1024];
    assert!(transport.recv(&mut buf).await.is_err());
    Ok(())
}

// =============================================================================
// CATEGORY 3: PROTOCOL FUZZING
// =============================================================================

#[tokio::test]
async fn test_06_invalid_version_frame() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let (mut s1, s2) =
        test_util::pair_for_test(&Identity::generate(), &Identity::generate()).unwrap();
    transport.install_session([0u8; 32], s2).await;
    transport.set_peer_addr("127.0.0.1:1111".parse()?).await;

    // Encode a VALID frame first
    let frame = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Heartbeat(Heartbeat {
            lamport: 0,
            rtt_hint: Some(0),
        }),
    };
    let mut payload = fluxsync_proto::encode(&frame).unwrap();

    // Hack the version byte in the CBOR (usually the second byte after the map marker)
    // For simplicity, let's just make the payload invalid CBOR or manual version
    if payload.len() > 2 {
        payload[1] = 99;
    }

    let ct = s1.encrypt(&payload).unwrap();
    let mut packet = vec![TYPE_ENCRYPTED];
    packet.extend_from_slice(&ct);
    UdpSocket::bind("127.0.0.1:0")
        .await?
        .send_to(&packet, format!("127.0.0.1:{port}"))
        .await?;

    let mut buf = [0u8; 1024];
    let res = transport.recv(&mut buf).await?;
    if let RecvFrame::Encrypted { plaintext, .. } = res {
        let decoded = fluxsync_proto::decode(&plaintext);
        assert!(
            decoded.is_err(),
            "Should have rejected corrupted version/CBOR"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_07_ip_roaming_legitimacy() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let (mut s1, s2) =
        test_util::pair_for_test(&Identity::generate(), &Identity::generate()).unwrap();
    transport.install_session([0u8; 32], s2).await;
    let attacker_addr: SocketAddr = "127.0.0.1:9999".parse()?;
    let attacker = UdpSocket::bind(attacker_addr).await?;
    let ct = s1.encrypt(b"ROAM").unwrap();
    let mut packet = vec![TYPE_ENCRYPTED];
    packet.extend_from_slice(&ct);
    attacker
        .send_to(&packet, format!("127.0.0.1:{port}"))
        .await?;
    let mut buf = [0u8; 1024];
    let _ = transport.recv(&mut buf).await?;
    assert_eq!(*transport.peer_addr.lock().await, Some(attacker_addr));
    Ok(())
}

// =============================================================================
// CATEGORY 4: ADVANCED ZERO-DAY SCENARIOS
// =============================================================================

#[tokio::test]
async fn test_11_rapid_ip_roaming() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let (mut s1, s2) =
        test_util::pair_for_test(&Identity::generate(), &Identity::generate()).unwrap();
    transport.install_session([0u8; 32], s2).await;
    for i in 0..5 {
        let sender = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = sender.local_addr()?;
        let ct = s1.encrypt(format!("Msg {i}").as_bytes()).unwrap();
        let mut packet = vec![TYPE_ENCRYPTED];
        packet.extend_from_slice(&ct);
        sender.send_to(&packet, format!("127.0.0.1:{port}")).await?;
        let mut buf = [0u8; 1024];
        let _ = transport.recv(&mut buf).await?;
        assert_eq!(*transport.peer_addr.lock().await, Some(addr));
    }
    Ok(())
}

#[tokio::test]
async fn test_12_handshake_racing_initiators() -> Result<()> {
    let (t1, p1) = setup_transport().await;
    let (t2, p2) = setup_transport().await;
    t1.socket
        .send_to(&[TYPE_HANDSHAKE_INIT, 0x01], format!("127.0.0.1:{p2}"))
        .await?;
    t2.socket
        .send_to(&[TYPE_HANDSHAKE_INIT, 0x02], format!("127.0.0.1:{p1}"))
        .await?;
    let mut buf = [0u8; 1024];
    assert!(matches!(
        t1.recv(&mut buf).await?,
        RecvFrame::HandshakeInit { .. }
    ));
    assert!(matches!(
        t2.recv(&mut buf).await?,
        RecvFrame::HandshakeInit { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn test_14_double_hello_in_session() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let (mut s1, s2) =
        test_util::pair_for_test(&Identity::generate(), &Identity::generate()).unwrap();
    transport.install_session([0u8; 32], s2).await;
    transport.set_peer_addr("127.0.0.1:1234".parse()?).await;
    let frame = Frame {
        version: PROTOCOL_VERSION,
        msg: Msg::Hello(Hello { name: "A".into() }),
    };
    let ct = s1
        .encrypt(&fluxsync_proto::encode(&frame).unwrap())
        .unwrap();
    let mut pkt = vec![TYPE_ENCRYPTED];
    pkt.extend_from_slice(&ct);
    let attacker = UdpSocket::bind("127.0.0.1:0").await?;
    attacker.send_to(&pkt, format!("127.0.0.1:{port}")).await?;
    attacker.send_to(&pkt, format!("127.0.0.1:{port}")).await?;
    let mut buf = [0u8; 1024];
    assert!(transport.recv(&mut buf).await.is_ok());
    assert!(transport.recv(&mut buf).await.is_err()); // Correctly caught by Noise
    Ok(())
}

#[tokio::test]
async fn test_15_chunk_overflow_attack() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let giant = vec![0x03; 2048]; // Larger than 1024 buf
    UdpSocket::bind("127.0.0.1:0")
        .await?
        .send_to(&giant, format!("127.0.0.1:{port}"))
        .await?;
    let mut buf = [0u8; 1024];
    assert!(transport.recv(&mut buf).await.is_err());
    Ok(())
}

#[tokio::test]
async fn test_18_malformed_cbor_encrypted() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let (mut s1, s2) =
        test_util::pair_for_test(&Identity::generate(), &Identity::generate()).unwrap();
    transport.install_session([0u8; 32], s2).await;
    let ct = s1.encrypt(b"NOT-CBOR").unwrap();
    let mut pkt = vec![TYPE_ENCRYPTED];
    pkt.extend_from_slice(&ct);
    UdpSocket::bind("127.0.0.1:0")
        .await?
        .send_to(&pkt, format!("127.0.0.1:{port}"))
        .await?;
    let mut buf = [0u8; 1024];
    if let RecvFrame::Encrypted { plaintext, .. } = transport.recv(&mut buf).await? {
        assert!(fluxsync_proto::decode(&plaintext).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn test_28_encrypted_frame_replay_protection() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let (mut s1, s2) =
        test_util::pair_for_test(&Identity::generate(), &Identity::generate()).unwrap();
    transport.install_session([0u8; 32], s2).await;
    let ct = s1.encrypt(b"SECRET").unwrap();
    let mut pkt = vec![TYPE_ENCRYPTED];
    pkt.extend_from_slice(&ct);
    let attacker = UdpSocket::bind("127.0.0.1:0").await?;
    attacker.send_to(&pkt, format!("127.0.0.1:{port}")).await?;
    let mut buf = [0u8; 1024];
    let res = transport.recv(&mut buf).await?;
    assert!(is_encrypted(&res));
    attacker.send_to(&pkt, format!("127.0.0.1:{port}")).await?;
    assert!(transport.recv(&mut buf).await.is_err()); // Nonce reuse rejection
    Ok(())
}

#[tokio::test]
async fn test_30_simultaneous_handshake_and_encrypted() -> Result<()> {
    let (transport, port) = setup_transport().await;
    let (mut s1, s2) =
        test_util::pair_for_test(&Identity::generate(), &Identity::generate()).unwrap();
    transport.install_session([0u8; 32], s2).await;
    let attacker = UdpSocket::bind("127.0.0.1:0").await?;
    attacker
        .send_to(&[TYPE_HANDSHAKE_INIT, 0x01], format!("127.0.0.1:{port}"))
        .await?;
    let ct = s1.encrypt(b"HI").unwrap();
    let mut pkt = vec![TYPE_ENCRYPTED];
    pkt.extend_from_slice(&ct);
    attacker.send_to(&pkt, format!("127.0.0.1:{port}")).await?;
    let mut buf = [0u8; 1024];
    assert!(matches!(
        transport.recv(&mut buf).await?,
        RecvFrame::HandshakeInit { .. }
    ));
    assert!(matches!(
        transport.recv(&mut buf).await?,
        RecvFrame::Encrypted { .. }
    ));
    Ok(())
}
