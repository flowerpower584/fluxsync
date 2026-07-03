package sn.kaolack.fluxsync.utils

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * DIR-P3-07: the self-check banner must fire only for the "Settings says
 * ON, but the service hasn't heartbeated in a while" case — never for a
 * cleanly-disabled service, and never on a fresh process racing the
 * service's own startup.
 */
class ServiceHealthUtilsTest {

    @Test
    fun notDeadWhenDisabledInSettings() {
        // A never-enabled or user-disabled service isn't this banner's
        // concern — AccessibilityBlockingScreen owns that state.
        assertFalse(ServiceHealthUtils.isServiceDead(enabledInSettings = false, lastHeartbeatMs = 0L, nowMs = 100_000L))
        assertFalse(ServiceHealthUtils.isServiceDead(enabledInSettings = false, lastHeartbeatMs = 1L, nowMs = 999_999L))
    }

    @Test
    fun notDeadWhenHeartbeatNeverRecorded() {
        // 0L = fresh process, service hasn't connected+polled yet. Racy by
        // nature — must not read as "dead".
        assertFalse(ServiceHealthUtils.isServiceDead(enabledInSettings = true, lastHeartbeatMs = 0L, nowMs = 100_000L))
    }

    @Test
    fun notDeadWhenHeartbeatIsRecent() {
        val now = 100_000L
        assertFalse(ServiceHealthUtils.isServiceDead(enabledInSettings = true, lastHeartbeatMs = now - 2_000L, nowMs = now))
    }

    @Test
    fun deadWhenHeartbeatIsStale() {
        val now = 100_000L
        assertTrue(
            ServiceHealthUtils.isServiceDead(
                enabledInSettings = true,
                lastHeartbeatMs = now - ServiceHealthUtils.STALE_AFTER_MS - 1L,
                nowMs = now,
            ),
        )
    }

    @Test
    fun boundaryAtExactlyStaleAfterMsIsNotYetDead() {
        val now = 100_000L
        assertFalse(
            ServiceHealthUtils.isServiceDead(
                enabledInSettings = true,
                lastHeartbeatMs = now - ServiceHealthUtils.STALE_AFTER_MS,
                nowMs = now,
            ),
        )
    }
}
