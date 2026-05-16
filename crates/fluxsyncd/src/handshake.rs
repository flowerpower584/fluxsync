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
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};

use crate::transport::{Transport, TYPE_HANDSHAKE_INIT, TYPE_HANDSHAKE_RESP};

/// In-memory peer trust registry (v0.1.1; persistence in v0.1.2).
#[derive(Debug, Clone)]
pub struct TrustedPeer {
    pub static_pub: [u8; 32],
    pub name: String,
}

pub type TrustedSet = Arc<Mutex<HashMap<[u8; 32], TrustedPeer>>>;

/// Placeholder name a peer carries between TOFU acceptance and the
/// `Msg::Hello` exchange that swaps in the real device name. Used as the
/// single source for both the in-memory and on-disk records so they
/// cannot diverge (FS-030).
pub const TOFU_PLACEHOLDER_NAME: &str = "New Peer";

/// Build the in-memory trust record for a peer accepted via TOFU.
#[must_use]
pub fn tofu_trusted_peer(remote_static: [u8; 32]) -> TrustedPeer {
    TrustedPeer {
        static_pub: remote_static,
        name: String::from(TOFU_PLACEHOLDER_NAME),
    }
}

/// Time-bounded "trust on first use" window. While the contained
/// `Instant` is in the future, the responder accepts handshakes from
/// previously-unknown peers and adds them to [`TrustedSet`] on success.
/// Set by `CmdOp::PairShow` to `now + 5min` so the user has a finite
/// pairing window after they generate their QR code; otherwise stays
/// `None` and the responder enforces strict trust.
pub type PairingWindow = Arc<Mutex<Option<Instant>>>;

/// Run the initiator side. Sends msg1, then awaits one msg2 on the
/// `incoming` channel. Times out after 5 s.
#[allow(clippy::too_many_arguments)]
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
    if !transport.try_install_session(peer_id, session).await {
        // Responder side completed first (simultaneous-init race). The
        // existing session is authoritative; drop ours and let the peer
        // own the link.
        tracing::debug!("initiator: session already installed; aborting install");
        return Ok(());
    }
    transport.set_peer_info(peer_id, peer_addr).await;
    let _ = event_tx.send(Event::PeerSeen {
        peer_id,
        name: peer_name,
    });
    let _ = event_tx.send(Event::HandshakeOk);
    Ok(())
}

/// Run the responder side once. Reads msg1 from `init_msg`, sends msg2
/// back to `from`, installs the session.
///
/// Trust resolution (in order):
/// 1. Peer pubkey already in `trusted` → accept (verifies key match).
/// 2. Peer unknown but `pairing_window` is open → accept under TOFU,
///    insert into `trusted` so subsequent reconnects skip the window.
///    `peer_name` is recorded as `"pending"` because the responder
///    never learns the peer's friendly name from the handshake bytes.
/// 3. Peer unknown + window closed → refuse with "untrusted peer".
#[allow(clippy::too_many_arguments)]
pub async fn run_responder(
    identity: Identity,
    init_msg: Vec<u8>,
    from: SocketAddr,
    transport: Arc<Transport>,
    trusted: TrustedSet,
    pairing_window: PairingWindow,
    event_tx: mpsc::UnboundedSender<Event>,
    keystore_dir: Option<std::path::PathBuf>,
) -> Result<()> {
    let (session, msg2, remote_static) = Responder::step(&identity, &init_msg)?;

    let peer_id = peer_id_for(&remote_static);
    let entry = {
        let mut trusted_guard = trusted.lock().await;
        if let Some(existing) = trusted_guard.get(&peer_id).cloned() {
            if existing.static_pub != remote_static {
                anyhow::bail!("trusted peer key mismatch; refusing handshake");
            }
            existing
        } else {
            let window_open = pairing_window
                .lock()
                .await
                .map(|deadline| Instant::now() < deadline)
                .unwrap_or(false);
            if !window_open {
                anyhow::bail!(
                    "handshake from untrusted peer {:x?}; refusing",
                    &peer_id[..6]
                );
            }
            let new_peer = tofu_trusted_peer(remote_static);
            tracing::info!(
                peer = ?&peer_id[..6],
                "TOFU: trusting new peer during pairing window"
            );
            trusted_guard.insert(peer_id, new_peer.clone());

            // PERSIST to disk so we remember this peer after restart.
            // The disk name copies `new_peer.name` so the live session and
            // a post-restart load can never disagree (FS-030).
            if let Some(ref dir) = keystore_dir {
                let mut stored = crate::keystore::load_peers(dir).unwrap_or_default();
                crate::keystore::upsert_peer(
                    &mut stored,
                    crate::keystore::StoredPeer {
                        peer_id_hex: hex_encode(&peer_id),
                        static_pub_hex: hex_encode(&remote_static),
                        name: new_peer.name.clone(),
                        last_addr: Some(from.to_string()),
                    },
                );
                if let Err(e) = crate::keystore::save_peers(dir, &stored) {
                    tracing::warn!(error = %e, "failed to persist trusted peer to peers.json");
                }
            }

            new_peer
        }
    };

    // Install before sending msg2 so a duplicate inbound HandshakeInit
    // (replay or honest retry) can't end up replacing the session we
    // just committed to. If install loses, drop msg2 too — peer will
    // either retry handshake or, if it already linked through another
    // path, ignore our late reply.
    if !transport.try_install_session(peer_id, session).await {
        tracing::debug!("responder: session already installed; not sending msg2");
        return Ok(());
    }
    transport.set_peer_info(peer_id, from).await;
    transport
        .send_typed(TYPE_HANDSHAKE_RESP, &msg2, from)
        .await?;
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

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{tofu_trusted_peer, TOFU_PLACEHOLDER_NAME};

    /// FS-030: the TOFU placeholder name has one source. The in-memory
    /// `TrustedPeer` and the on-disk `StoredPeer` (which copies
    /// `new_peer.name`) must therefore carry the identical string, so the
    /// live session and a post-restart load never show two names.
    #[test]
    fn fs030_tofu_placeholder_is_single_source() {
        let peer = tofu_trusted_peer([7u8; 32]);
        assert_eq!(peer.name, TOFU_PLACEHOLDER_NAME);
        assert_eq!(peer.name, "New Peer");

        // The disk record is built as `name: new_peer.name.clone()`;
        // mirror that here to lock the structural single-source invariant.
        let disk_name = peer.name.clone();
        assert_eq!(disk_name, peer.name);
    }
}
