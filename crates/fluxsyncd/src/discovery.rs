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
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub const SERVICE_TYPE: &str = "_fluxsync._udp.local.";

/// Delay between discovery browse attempts after a failure or exit.
pub const DISCOVERY_RETRY: Duration = Duration::from_secs(2);

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
    shutdown: CancellationToken,
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

    let self_peer_id = peer_id_hex.to_string();
    let daemon_for_loop = daemon.clone();
    tokio::spawn(async move {
        supervise(shutdown.clone(), DISCOVERY_RETRY, || {
            let daemon = daemon_for_loop.clone();
            let self_peer_id = self_peer_id.clone();
            let tx = tx.clone();
            let shutdown = shutdown.clone();
            async move {
                match daemon.browse(SERVICE_TYPE) {
                    Ok(receiver) => {
                        if let Err(e) = browse_loop(receiver, self_peer_id, tx, shutdown).await {
                            tracing::warn!(error = %e, "discovery browse loop exited, retrying");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "mdns browse failed, retrying");
                    }
                }
            }
        })
        .await;
        let _ = daemon_for_loop.shutdown();
    });

    Ok(daemon)
}

/// Run `attempt` repeatedly, sleeping `retry` between runs, until
/// `shutdown` fires. No new attempt is started once shutdown is
/// cancelled — checked both before each run and via the sleep `select!`.
async fn supervise<F, Fut>(shutdown: CancellationToken, retry: Duration, mut attempt: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    loop {
        if shutdown.is_cancelled() {
            return;
        }
        attempt().await;
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(retry) => {}
        }
    }
}

/// True for a well-formed 32-byte hex identifier (64 ASCII hex chars).
/// Rejects wrong-length, non-hex, empty and whitespace-only strings.
#[must_use]
fn is_valid_hex_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn browse_loop(
    receiver: mdns_sd::Receiver<ServiceEvent>,
    self_peer_id: String,
    tx: mpsc::UnboundedSender<DiscoveryEvent>,
    shutdown: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            evt = receiver.recv_async() => {
                let Ok(e) = evt else { return Ok(()) };
                match e {
                    ServiceEvent::ServiceResolved(info) => {
                        let props = info.get_properties();
                        let Some(peer_id) = props.get_property_val_str("peer_id") else { continue };
                        if peer_id == self_peer_id { continue; }
                        if !is_valid_hex_id(peer_id) { continue; }
                        let Some(static_pub) = props.get_property_val_str("static_pub") else { continue };
                        if !is_valid_hex_id(static_pub) { continue; }
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

#[cfg(test)]
mod tests {
    use super::{is_valid_hex_id, supervise, DISCOVERY_RETRY};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[tokio::test(start_paused = true)]
    async fn fs036_supervise_retries_until_shutdown() {
        let token = CancellationToken::new();
        let count = Arc::new(AtomicUsize::new(0));

        let task = {
            let token = token.clone();
            let count = count.clone();
            tokio::spawn(async move {
                supervise(token, DISCOVERY_RETRY, || {
                    let count = count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                })
                .await;
            })
        };

        // Attempts fire at t0, t2, t4, t6 (DISCOVERY_RETRY = 2s).
        tokio::time::sleep(Duration::from_secs(7)).await;
        let during = count.load(Ordering::SeqCst);
        assert!(during >= 3, "expected >=3 retries, got {during}");

        token.cancel();
        task.await.unwrap();
        let after_cancel = count.load(Ordering::SeqCst);

        // No further attempt once shutdown has fired.
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_eq!(count.load(Ordering::SeqCst), after_cancel);
    }

    #[test]
    fn fs037_hex_id_validation() {
        assert!(is_valid_hex_id(&"a".repeat(64)));
        assert!(is_valid_hex_id(&"0123456789abcdef".repeat(4)));
        assert!(!is_valid_hex_id("garbage"));
        assert!(!is_valid_hex_id(""));
        assert!(!is_valid_hex_id(&"a".repeat(63)));
        assert!(!is_valid_hex_id(&format!("{}g", "a".repeat(63))));
        assert!(!is_valid_hex_id(&" ".repeat(64)));
    }
}
