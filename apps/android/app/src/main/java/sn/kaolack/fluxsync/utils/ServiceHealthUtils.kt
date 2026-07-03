package sn.kaolack.fluxsync.utils

/**
 * DIR-P3-07: `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` only proves
 * the service is *toggled on* — some OEM task killers stop the hosting
 * process without touching that list, leaving the setting ON while nothing
 * is actually capturing the clipboard. Cross-checking against a heartbeat
 * the service itself maintains catches that "enabled but dead" state.
 */
object ServiceHealthUtils {
    /**
     * How long a missing heartbeat is tolerated before the service reads as
     * dead. Generous relative to the a11y poll loop's slowest cadence (2s
     * idle — see `FluxsyncAccessibilityService.pollIntervalMs`) so ordinary
     * timing jitter can't trip a false positive.
     */
    const val STALE_AFTER_MS = 8_000L

    /**
     * [lastHeartbeatMs] is written from inside the AccessibilityService's
     * existing poll loop (no extra timer added for this check). `0L` means
     * this process incarnation hasn't had the service connect+poll yet —
     * that's a fresh launch racing the service's own startup, NOT the
     * "was alive, now dead" case this banner targets, so it does not trip
     * a false positive.
     */
    fun isServiceDead(enabledInSettings: Boolean, lastHeartbeatMs: Long, nowMs: Long): Boolean {
        if (!enabledInSettings) return false
        if (lastHeartbeatMs <= 0L) return false
        return nowMs - lastHeartbeatMs > STALE_AFTER_MS
    }
}
