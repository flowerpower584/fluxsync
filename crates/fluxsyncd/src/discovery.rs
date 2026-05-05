//! mDNS service registration + peer discovery.
//!
//! Service type: `_fluxsync._udp.local.`. TXT record carries:
//!   * `peer_id` — hex of `BLAKE3(static_pub)`
//!   * `static_pub` — hex of the 32-byte X25519 public key
//!
//! Other daemons browse the same service type; on resolve, the driver
//! checks the advertised `peer_id` against its trusted set and (only if
//! it matches a known key) synthesizes an `Event::PeerSeen` for the FSM.
//!
//! mDNS is **best-effort**: if the daemon's loopback or LAN multicast
//! is broken, discovery silently degrades and pair-time `--addr` is the
//! manual fallback.

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};

pub const SERVICE_TYPE: &str = "_fluxsync._udp.local.";

/// What discovery emits to the driver. The driver decides whether the
/// peer is trusted; discovery just reports what it sees.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    Resolved {
        peer_id_hex: String,
        static_pub_hex: String,
        name: String,
        addr: std::net::SocketAddr,
    },
    Removed {
        fullname: String,
    },
}

/// Register self under mDNS and start a browse loop, forwarding events
/// to `tx`. Returns the `ServiceDaemon` handle so the driver can
/// `shutdown()` it on exit.
pub fn start(
    instance_name: &str,
    peer_id_hex: &str,
    static_pub_hex: &str,
    bind_ip: IpAddr,
    udp_port: u16,
    tx: mpsc::UnboundedSender<DiscoveryEvent>,
    shutdown: Arc<Notify>,
) -> Result<ServiceDaemon> {
    let daemon = ServiceDaemon::new().context("create mdns daemon")?;

    let mut props: HashMap<String, String> = HashMap::new();
    props.insert("peer_id".into(), peer_id_hex.into());
    props.insert("static_pub".into(), static_pub_hex.into());
    let host_name = format!("{instance_name}.local.");
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        &host_name,
        bind_ip,
        udp_port,
        Some(props),
    )
    .context("build ServiceInfo")?;

    daemon.register(info).context("mdns register")?;

    let receiver = daemon.browse(SERVICE_TYPE).context("mdns browse")?;
    let self_peer_id = peer_id_hex.to_string();
    let daemon_for_loop = daemon.clone();
    tokio::spawn(async move {
        if let Err(e) = browse_loop(receiver, self_peer_id, tx, shutdown).await {
            tracing::warn!(error = %e, "discovery browse loop exited");
        }
        let _ = daemon_for_loop.shutdown();
    });

    Ok(daemon)
}

async fn browse_loop(
    receiver: mdns_sd::Receiver<ServiceEvent>,
    self_peer_id: String,
    tx: mpsc::UnboundedSender<DiscoveryEvent>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => return Ok(()),
            evt = receiver.recv_async() => {
                let Ok(e) = evt else { return Ok(()) };
                match e {
                    ServiceEvent::ServiceResolved(info) => {
                        let props = info.get_properties();
                        let Some(peer_id) = props.get_property_val_str("peer_id") else { continue };
                        if peer_id == self_peer_id { continue; }
                        let Some(static_pub) = props.get_property_val_str("static_pub") else { continue };
                        let addr = info.get_addresses().iter().next().copied();
                        let Some(ip) = addr else { continue };
                        let port = info.get_port();
                        let sock_addr = std::net::SocketAddr::new(ip, port);
                        let name = info.get_fullname()
                            .split('.')
                            .next()
                            .unwrap_or("")
                            .to_string();
                        let _ = tx.send(DiscoveryEvent::Resolved {
                            peer_id_hex: peer_id.to_string(),
                            static_pub_hex: static_pub.to_string(),
                            name,
                            addr: sock_addr,
                        });
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        let _ = tx.send(DiscoveryEvent::Removed { fullname });
                    }
                    _ => {}
                }
            }
        }
    }
}
