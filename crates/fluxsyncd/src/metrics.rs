pub use fluxsync_core::state::{ConnectionMetrics, DisconnectReason};
use std::time::Instant;

pub struct MetricsTracker {
    metrics: ConnectionMetrics,
    session_start: Option<Instant>,
    last_heartbeat_sent: Option<Instant>,
}

impl MetricsTracker {
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
            let rtt_ms = sent.elapsed().as_millis() as u32;
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

    pub fn on_disconnect(&mut self, reason: DisconnectReason) {
        self.metrics.last_disconnect_reason = Some(reason);
        self.session_start = None;
        self.metrics.uptime_session_secs = 0;
    }
}
