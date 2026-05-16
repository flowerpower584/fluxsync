package sn.kaolack.fluxsync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FS-011: the FFI poll loop must back off when no peer is linked so a
 * backgrounded, disconnected app stops doing 10 FFI reads per second.
 */
class FluxsyncAccessibilityServiceTest {

    @Test
    fun pollIsTightWhileLinked() {
        assertEquals(200L, FluxsyncAccessibilityService.pollIntervalMs(true))
    }

    @Test
    fun pollBacksOffWhenIdle() {
        val idle = FluxsyncAccessibilityService.pollIntervalMs(false)
        val linked = FluxsyncAccessibilityService.pollIntervalMs(true)
        assertTrue("idle cadence must be slower than linked", idle > linked)
        assertEquals(2000L, idle)
    }
}
