//! Noise IK handshake driver.
//!
//! Two paths:
//! * **Initiator** — fired by the driver when discovery (or a manual
//!   pair) tells us a trusted peer is reachable at a known UDP address.
//!   Sends `HandshakeInit`, awaits the matching `HandshakeResp` from the
//!   transport recv loop, finalizes the session, installs it into the
//!   `Transport`, and pings `Event::HandshakeOk` so the FSM transitions
//!   to `Linked`.
//! * **Responder** — fired by the transport recv loop when a
//!   `HandshakeInit` datagram arrives. Validates that the initiator's
//!   static key is in the trusted set, sends `HandshakeResp`, installs
//!   the session, fires `Event::HandshakeOk`, and points the transport
//!   at the initiator's address so subsequent encrypted sends find it.

use anyhow::{anyhow, Result};
use fluxsync_core::Event;
use fluxsync_crypto::{Identity, Initiator, Responder};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use crate::transport::{Transport, TYPE_HANDSHAKE_INIT, TYPE_HANDSHAKE_RESP};

/// In-memory peer trust registry (v0.1.1; persistence in v0.1.2).
#[derive(Debug, Clone)]
pub struct TrustedPeer {
    pub static_pub: [u8; 32],
    pub name: String,
}

pub type TrustedSet = Arc<Mutex<HashMap<[u8; 32], TrustedPeer>>>;

/// Run the initiator side. Sends msg1, then awaits one msg2 on the
/// `incoming` channel. Times out after 5 s.
pub async fn run_initiator(
    identity: Identity,
    peer_static_pub: [u8; 32],
    peer_addr: SocketAddr,
    transport: Arc<Transport>,
    mut incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    event_tx: mpsc::UnboundedSender<Event>,
    peer_id: [u8; 32],
    peer_name: String,
) -> Result<()> {
    let (initiator, msg1) = Initiator::start(&identity, &peer_static_pub)?;
    transport
        .send_typed(TYPE_HANDSHAKE_INIT, &msg1, peer_addr)
        .await?;

    let msg2 = tokio::time::timeout(std::time::Duration::from_secs(5), incoming.recv())
        .await
        .map_err(|_| anyhow!("handshake timeout (no resp in 5s)"))?
        .ok_or_else(|| anyhow!("handshake channel closed"))?;

    let session = initiator.finish(&msg2)?;
    transport.install_session(session).await;
    transport.set_peer_addr(peer_addr).await;
    let _ = event_tx.send(Event::PeerSeen {
        peer_id,
        name: peer_name,
    });
    let _ = event_tx.send(Event::HandshakeOk);
    Ok(())
}

/// Run the responder side once. Reads msg1 from `init_msg`, sends msg2
/// back to `from`, installs the session.
pub async fn run_responder(
    identity: Identity,
    init_msg: Vec<u8>,
    from: SocketAddr,
    transport: Arc<Transport>,
    trusted: TrustedSet,
    event_tx: mpsc::UnboundedSender<Event>,
) -> Result<()> {
    let (session, msg2, remote_static) = Responder::step(&identity, &init_msg)?;

    let peer_id = peer_id_for(&remote_static);
    let trusted_guard = trusted.lock().await;
    let entry = trusted_guard.get(&peer_id).cloned();
    drop(trusted_guard);
    let Some(entry) = entry else {
        anyhow::bail!("handshake from untrusted peer {:x?}; refusing", &peer_id[..6]);
    };
    if entry.static_pub != remote_static {
        anyhow::bail!("trusted peer key mismatch; refusing handshake");
    }

    transport
        .send_typed(TYPE_HANDSHAKE_RESP, &msg2, from)
        .await?;
    transport.install_session(session).await;
    transport.set_peer_addr(from).await;
    let _ = event_tx.send(Event::PeerSeen {
        peer_id,
        name: entry.name,
    });
    let _ = event_tx.send(Event::HandshakeOk);
    Ok(())
}

/// Stable peer id = `BLAKE3(static_pub)`. Re-uses the workspace's
/// shared hash helper so producers can't accidentally diverge.
#[must_use]
pub fn peer_id_for(static_pub: &[u8; 32]) -> [u8; 32] {
    fluxsync_core::dedup::DedupRing::hash(static_pub)
}
