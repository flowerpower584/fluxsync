package sn.kaolack.fluxsync.vm

import org.json.JSONArray
import org.json.JSONObject

/**
 * Parsed view of the daemon's `State` JSON. Only the fields the UI
 * actually renders are surfaced here — anything else stays in the raw
 * JSON object and can be added incrementally without an FFI bump.
 *
 * Serialized shape (mirrors `fluxsync_core::State`):
 *
 * ```json
 * {
 *   "phase": "Idle" | "Discovering" | "Linked" | "Paused" | "Error",
 *   "status": "Inactive" | "Active",
 *   "peer_name": "",
 *   "peer_battery": 0,
 *   "peer_charging": false,
 *   "battery_level": 0,
 *   "charging": false,
 *   "battery_threshold": 20,
 *   "link_latency_ms": 0,
 *   "history": [{"hash": "…", "kind": "text", "preview": "…", "time": "14:32", "sensitive": false, "lamport": 0}],
 *   "version": "0.5.0",
 *   "cipher": "chacha20-poly1305"
 * }
 * ```
 */
data class DaemonState(
    val phase: String,
    val status: String,
    val active: Boolean,
    val peerName: String,
    val peerPlatform: String,
    val peerBattery: Int,
    val peerCharging: Boolean,
    val selfBattery: Int,
    val selfCharging: Boolean,
    val threshold: Int,
    val linkLatencyMs: Int,
    val chargeOverride: Boolean,
    val history: List<HistoryItem>,
    val version: String,
    val cipher: String,
    val trustedPeerName: String?,
    val metrics: ConnectionMetricsView?,
    val raw: JSONObject,
) {
    companion object {
        fun parse(json: String): DaemonState? = try {
            val o = JSONObject(json)
            DaemonState(
                phase = o.optString("phase", "idle"),
                status = o.optString("status", "inactive"),
                // The daemon's `status` is a derived label
                // (inactive/syncing/paused/critical) — never literally
                // "Active". The UI's Online switch should mirror the
                // user-facing toggle, which the daemon exposes as the
                // `on` boolean.
                active = o.optBoolean("on", false),
                peerName = o.optString("peer_name", ""),
                peerPlatform = o.optString("peer_platform", ""),
                peerBattery = o.optInt("peer_battery", 0),
                peerCharging = o.optBoolean("peer_charging", false),
                selfBattery = o.optInt("battery_level", 0),
                selfCharging = o.optBoolean("charging", false),
                threshold = o.optInt("battery_threshold", 20),
                linkLatencyMs = o.optInt("link_latency_ms", 0),
                chargeOverride = o.optBoolean("charge_override", true),
                history = parseHistory(o.optJSONArray("history")),
                version = o.optString("version", ""),
                cipher = o.optString("cipher", ""),
                trustedPeerName = o.optString("trusted_peer_name", null),
                metrics = ConnectionMetricsView.parse(o.optJSONObject("metrics")),
                raw = o,
            )
        } catch (e: Exception) {
            android.util.Log.w("FluxSync", parseFailureMessage(e, json))
            null
        }

        /**
         * FS-017: diagnostic line for a failed [parse] call. Includes the
         * exception message and a bounded head of the offending JSON so a
         * silent empty screen becomes a traceable logcat entry.
         */
        internal fun parseFailureMessage(e: Throwable, json: String): String =
            "DaemonState.parse failed: ${e.message} (raw head: ${json.take(120)})"

        private fun parseHistory(arr: JSONArray?): List<HistoryItem> {
            if (arr == null) return emptyList()
            val out = mutableListOf<HistoryItem>()
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                out += HistoryItem(
                    hash = o.optString("hash", ""),
                    kind = o.optString("kind", "text"),
                    preview = o.optString("preview", ""),
                    time = o.optString("time", ""),
                    source = o.optString("source", "local"),
                    sensitive = o.optBoolean("sensitive", false),
                    lamport = o.optLong("lamport", 0L),
                )
            }
            return out
        }
    }
}

/**
 * Friendly OS label for a peer's `peer_platform` (from `Msg::Hello`), or null
 * when the platform is unknown / not yet received. Lets the UI show what the
 * peer is instead of assuming a phone.
 */
fun platformLabel(platform: String): String? = when (platform.lowercase()) {
    "macos" -> "macOS"
    "windows" -> "Windows"
    "linux" -> "Linux"
    "android" -> "Android"
    "ios" -> "iOS"
    else -> null
}

data class HistoryItem(
    val hash: String,
    val kind: String,
    val preview: String,
    val time: String,
    val source: String,
    val sensitive: Boolean,
    val lamport: Long,
)

/**
 * UI-friendly snapshot of one log line. Decoupled from the
 * UniFFI-generated `FfiLogEntry` so Compose previews and tests don't
 * have to depend on the regenerated Kotlin bindings being present.
 */
data class LogEntryView(
    val seq: Long,
    val time: String,
    val level: String,
    val msg: String,
    val raw: String,
)

/**
 * Subset of `fluxsync_core::state::ConnectionMetrics` the UI actually
 * surfaces. Nullable: `metrics` is `Option<ConnectionMetrics>` on the
 * daemon side, only populated once the transport has produced a number.
 */
data class ConnectionMetricsView(
    val lastRttMs: Int,
    val rttP99Ms: Int,
    val handshakesTotal: Long,
    val handshakesFailed: Long,
    val reconnects: Long,
    val networkChanges: Long,
    val decryptFailures: Long,
    val dedupDrops: Long,
    val heartbeatsMissedConsecutive: Int,
    val uptimeSessionSecs: Long,
    val lastDisconnectReason: String?,
) {
    companion object {
        fun parse(o: JSONObject?): ConnectionMetricsView? {
            if (o == null) return null
            return ConnectionMetricsView(
                lastRttMs = o.optInt("last_rtt_ms", 0),
                rttP99Ms = o.optInt("rtt_p99_ms", 0),
                handshakesTotal = o.optLong("handshakes_total", 0L),
                handshakesFailed = o.optLong("handshakes_failed", 0L),
                reconnects = o.optLong("reconnects", 0L),
                networkChanges = o.optLong("network_changes", 0L),
                decryptFailures = o.optLong("decrypt_failures", 0L),
                dedupDrops = o.optLong("dedup_drops", 0L),
                heartbeatsMissedConsecutive = o.optInt("heartbeats_missed_consecutive", 0),
                uptimeSessionSecs = o.optLong("uptime_session_secs", 0L),
                lastDisconnectReason = o.optString("last_disconnect_reason", "").ifEmpty { null },
            )
        }
    }
}
