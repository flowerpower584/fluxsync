pub use fluxsync_core::state::{ConnectionMetrics, DisconnectReason};
use std::time::Instant;

pub struct MetricsTracker {
    metrics: ConnectionMetrics,
    session_start: Option<Instant>,
    last_heartbeat_sent: Option<Instant>,
}

impl Default for MetricsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            metrics: ConnectionMetrics {
                handshakes_total: 0,
                handshakes_failed: 0,
                heartbeats_sent: 0,
                heartbeats_received: 0,
                heartbeats_missed_consecutive: 0,
                last_rtt_ms: 0,
                rtt_p99_ms: 0,
                network_changes: 0,
                reconnects: 0,
                decrypt_failures: 0,
                dedup_drops: 0,
                last_disconnect_reason: None,
                uptime_session_secs: 0,
                items_sent: 0,
                items_received: 0,
            },
            session_start: None,
            last_heartbeat_sent: None,
        }
    }

    pub fn snapshot(&mut self) -> ConnectionMetrics {
        if let Some(start) = self.session_start {
            self.metrics.uptime_session_secs = start.elapsed().as_secs();
        }
        self.metrics.clone()
    }

    pub fn on_handshake_start(&mut self) {
        self.metrics.handshakes_total += 1;
    }

    pub fn on_handshake_ok(&mut self) {
        self.session_start = Some(Instant::now());
        self.metrics.reconnects += 1;
        self.metrics.heartbeats_missed_consecutive = 0;
    }

    pub fn on_handshake_fail(&mut self) {
        self.metrics.handshakes_failed += 1;
    }

    pub fn on_heartbeat_sent(&mut self) {
        self.metrics.heartbeats_sent += 1;
        self.last_heartbeat_sent = Some(Instant::now());
    }

    pub fn on_heartbeat_received(&mut self) {
        self.metrics.heartbeats_received += 1;
        self.metrics.heartbeats_missed_consecutive = 0;
    }

    pub fn on_ack_received(&mut self) {
        if let Some(sent) = self.last_heartbeat_sent.take() {
            let rtt_ms = u32::try_from(sent.elapsed().as_millis()).unwrap_or(u32::MAX);
            self.metrics.last_rtt_ms = rtt_ms;
            // Simple smoothing for p99
            if self.metrics.rtt_p99_ms == 0 {
                self.metrics.rtt_p99_ms = rtt_ms;
            } else {
                self.metrics.rtt_p99_ms = (self.metrics.rtt_p99_ms * 9 + rtt_ms) / 10;
            }
        }
    }

    pub fn on_heartbeat_missed(&mut self) {
        self.metrics.heartbeats_missed_consecutive += 1;
    }

    pub fn on_network_change(&mut self) {
        self.metrics.network_changes += 1;
    }

    pub fn on_decrypt_failure(&mut self) {
        self.metrics.decrypt_failures += 1;
    }

    pub fn on_dedup_drop(&mut self) {
        self.metrics.dedup_drops += 1;
    }

    /// DIR-P1-09: a clipboard item was handed to the transport for sending
    /// (`Action::SendItem`, at least one linked peer targeted).
    pub fn on_item_sent(&mut self) {
        self.metrics.items_sent += 1;
    }

    /// DIR-P1-09: a clipboard item arriving from a peer was applied to the
    /// local OS clipboard (`Action::WriteClipboard`).
    pub fn on_item_received(&mut self) {
        self.metrics.items_received += 1;
    }

    pub fn on_disconnect(&mut self, reason: DisconnectReason) {
        self.metrics.last_disconnect_reason = Some(reason);
        self.session_start = None;
        self.metrics.uptime_session_secs = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DIR-P1-09: the KPI set advances independently and doesn't cross-wire
    /// (e.g. a dedup drop must not also bump `items_received`).
    #[test]
    fn kpi_counters_advance_independently() {
        let mut m = MetricsTracker::new();
        m.on_item_sent();
        m.on_item_sent();
        m.on_item_received();
        m.on_dedup_drop();
        m.on_handshake_fail();
        m.on_handshake_fail();
        m.on_handshake_fail();

        let s = m.snapshot();
        assert_eq!(s.items_sent, 2);
        assert_eq!(s.items_received, 1);
        assert_eq!(s.dedup_drops, 1);
        assert_eq!(s.handshakes_failed, 3);
        assert_eq!(s.reconnects, 0);
    }
}
