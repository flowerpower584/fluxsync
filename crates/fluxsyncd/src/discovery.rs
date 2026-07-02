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
use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
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
        /// Every advertised, reachable address for the peer, ranked
        /// most-likely-reachable first (Wi-Fi LAN IPv4 before cellular /
        /// IPv6). The initiator tries each in order. A peer on both Wi-Fi
        /// and cellular advertises several IPs; handing over only one
        /// arbitrary HashSet element used to send the initiator to the
        /// cellular or IPv6 address → "no resp in 5s" forever.
        addrs: Vec<std::net::SocketAddr>,
        /// PR2: 6-digit pairing PIN advertised by the peer's
        /// `PairShow`. `None` when the peer has no open pair window —
        /// PIN-method pairing requires a `Some(_)`.
        pair_pin: Option<String>,
    },
    Removed {
        fullname: String,
    },
}

/// Build the `ServiceInfo` we publish on mDNS. Centralised so the
/// initial register and any PIN-driven re-publish (PR2) build the
/// exact same record minus the rotating `pair_pin` TXT.
fn build_service_info(
    instance_name: &str,
    peer_id_hex: &str,
    static_pub_hex: &str,
    bind_ip: IpAddr,
    udp_port: u16,
    pair_pin: Option<&str>,
) -> Result<ServiceInfo> {
    let mut props: HashMap<String, String> = HashMap::new();
    props.insert("peer_id".into(), peer_id_hex.into());
    props.insert("static_pub".into(), static_pub_hex.into());
    if let Some(pin) = pair_pin {
        props.insert("pair_pin".into(), pin.into());
    }
    let host_name = format!("{instance_name}.local.");
    ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        &host_name,
        bind_ip,
        udp_port,
        Some(props),
    )
    .context("build ServiceInfo")
}

/// PR2: re-publish the service record so the rotating `pair_pin` TXT
/// reaches the LAN. Call with `pair_pin = None` to clear the PIN when
/// the pair window closes. mdns-sd treats `register` as idempotent —
/// re-registering with the same instance name updates the TXT in place
/// and triggers a fresh announcement.
pub fn republish_with_pin(
    daemon: &ServiceDaemon,
    instance_name: &str,
    peer_id_hex: &str,
    static_pub_hex: &str,
    bind_ip: IpAddr,
    udp_port: u16,
    pair_pin: Option<&str>,
) -> Result<()> {
    let info = build_service_info(
        instance_name,
        peer_id_hex,
        static_pub_hex,
        bind_ip,
        udp_port,
        pair_pin,
    )?;
    daemon.register(info).context("mdns re-register")?;
    Ok(())
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
    tx: mpsc::Sender<DiscoveryEvent>,
    shutdown: CancellationToken,
) -> Result<ServiceDaemon> {
    let daemon = ServiceDaemon::new().context("create mdns daemon")?;

    // Pin mDNS to the LAN interface we actually bind to. mdns-sd's default
    // is "all interfaces"; on macOS that includes awdl0/utunN and the
    // multicast egresses off-LAN, so announcements never reach peers.
    // Restricting to `bind_ip`'s interface fixes cross-host discovery.
    if !bind_ip.is_unspecified() && !bind_ip.is_loopback() {
        let _ = daemon.disable_interface(IfKind::All);
        let _ = daemon.enable_interface(bind_ip);
    }

    let info = build_service_info(
        instance_name,
        peer_id_hex,
        static_pub_hex,
        bind_ip,
        udp_port,
        None,
    )?;
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

/// Link-local addresses (169.254/16, fe80::/10) are never the LAN address a
/// peer is reachable at, so they're dropped before ranking.
fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Sort key (lower = tried first) for a peer's advertised addresses. Home
/// Wi-Fi IPv4 (192.168/16, 172.16/12) goes first; the 10/8 block is ranked
/// after the other private ranges because it is the usual cellular-CGNAT
/// range, so a phone on both Wi-Fi and data tries the Wi-Fi IP first; public
/// IPv4 next; IPv6 last. The initiator still tries every address, so a
/// mis-rank only costs one 5s timeout, never a failed link.
fn addr_rank(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o[0] == 192 && o[1] == 168 {
                0
            } else if o[0] == 172 && (16..=31).contains(&o[1]) {
                1
            } else if o[0] == 10 {
                2
            } else {
                3
            }
        }
        IpAddr::V6(_) => 4,
    }
}

async fn browse_loop(
    receiver: mdns_sd::Receiver<ServiceEvent>,
    self_peer_id: String,
    tx: mpsc::Sender<DiscoveryEvent>,
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
                        // mdns-sd 0.19: `get_addresses` returns
                        // `&HashSet<ScopedIp>`. Collect EVERY advertised
                        // address (not an arbitrary `.next()`), drop the
                        // unreachable ones, and rank LAN-Wi-Fi-IPv4 first so a
                        // peer that also has cellular / IPv6 still links fast.
                        let port = info.get_port();
                        let mut addrs: Vec<std::net::SocketAddr> = info
                            .get_addresses()
                            .iter()
                            .map(mdns_sd::ScopedIp::to_ip_addr)
                            .filter(|ip| {
                                !ip.is_loopback()
                                    && !ip.is_unspecified()
                                    && !is_link_local(ip)
                            })
                            .map(|ip| std::net::SocketAddr::new(ip, port))
                            .collect();
                        addrs.sort_by_key(|a| addr_rank(&a.ip()));
                        if addrs.is_empty() { continue; }
                        let name = info.get_fullname()
                            .split('.')
                            .next()
                            .unwrap_or("")
                            .to_string();
                        // PR2: PIN may be absent (peer has no open pair
                        // window) or stale (peer just rotated). Validate
                        // length+digits cheaply so a malformed TXT can't
                        // poison the cache.
                        let pair_pin = props
                            .get_property_val_str("pair_pin")
                            .filter(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit()))
                            .map(str::to_string);
                        let _ = tx.try_send(DiscoveryEvent::Resolved {
                            peer_id_hex: peer_id.to_string(),
                            static_pub_hex: static_pub.to_string(),
                            name,
                            addrs,
                            pair_pin,
                        });
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        let _ = tx.try_send(DiscoveryEvent::Removed { fullname });
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{addr_rank, is_link_local, is_valid_hex_id, supervise, DISCOVERY_RETRY};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn wifi_lan_ipv4_ranks_before_cellular_and_ipv6() {
        // A phone on Wi-Fi (192.168.1.9) + cellular (10.238.x CGNAT) + IPv6
        // advertises all three. The Wi-Fi LAN address must be tried first so
        // the initiator doesn't waste 5s timing out on the unreachable ones.
        let v4_wifi: IpAddr = Ipv4Addr::new(192, 168, 1, 9).into();
        let v4_cell: IpAddr = Ipv4Addr::new(10, 238, 131, 121).into();
        let v6: IpAddr = Ipv6Addr::new(0x2001, 0x4278, 0, 0, 0, 0, 0, 1).into();
        let mut addrs: Vec<SocketAddr> = [v4_cell, v6, v4_wifi]
            .iter()
            .map(|ip| SocketAddr::new(*ip, 41889))
            .collect();
        addrs.sort_by_key(|a| addr_rank(&a.ip()));
        assert_eq!(addrs.first().unwrap().ip(), v4_wifi);
        assert_eq!(addrs.last().unwrap().ip(), v6);
        // 10/8 ranks after 192.168 but before IPv6.
        assert!(addr_rank(&v4_wifi) < addr_rank(&v4_cell));
        assert!(addr_rank(&v4_cell) < addr_rank(&v6));
    }

    #[test]
    fn link_local_is_filtered() {
        assert!(is_link_local(&Ipv4Addr::new(169, 254, 1, 2).into()));
        assert!(is_link_local(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into()));
        assert!(!is_link_local(&Ipv4Addr::new(192, 168, 1, 9).into()));
        assert!(!is_link_local(&Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1).into()));
    }

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
