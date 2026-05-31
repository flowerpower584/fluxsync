package sn.kaolack.fluxsync

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import sn.kaolack.fluxsync.vm.HistoryItem

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

    // FS-013: onDestroy's daemon stop must be bounded so a wedged
    // handle.stop() can never ANR the AccessibilityService.

    @Test
    fun stopWithinTimeoutReturnsTrueWhenStopIsFast() = runBlocking {
        val ok = FluxsyncAccessibilityService.stopWithinTimeout(1000L) {
            delay(10L)
        }
        assertTrue("a prompt stop must report success", ok)
    }

    // FS-019: the peer name sent to the daemon must be human-readable —
    // manufacturer-prefixed, never a bare Build.MODEL code.

    @Test
    fun peerNamePrefixesAndCapitalisesTheManufacturer() {
        assertEquals(
            "Samsung SM-G998B",
            FluxsyncAccessibilityService.formatPeerName("samsung", "SM-G998B"),
        )
    }

    @Test
    fun peerNameFallsBackWhenBuildFieldsAreMissing() {
        assertEquals("Android", FluxsyncAccessibilityService.formatPeerName(null, null))
        assertEquals("Android", FluxsyncAccessibilityService.formatPeerName("", "  "))
        assertEquals("Pixel 8", FluxsyncAccessibilityService.formatPeerName("", "Pixel 8"))
    }

    // M-AND-01: inbound dedup keys on content hash, not a Lamport cursor, so
    // a daemon restart (Lamport resets to 0) can't silently stop inbound sync.

    private fun histItem(lamport: Long, source: String) = HistoryItem(
        hash = "h$lamport",
        kind = "text",
        preview = "p$lamport",
        time = "",
        source = source,
        sensitive = false,
        lamport = lamport,
    )

    @Test
    fun newRemoteItemsFloodsWhenSeenSetIsEmpty() {
        val history = listOf(
            histItem(5, "remote"),
            histItem(4, "local"),
            histItem(3, "remote"),
            histItem(2, "remote"),
        )
        // A restart with no persisted set → every remote item resynced, oldest-first.
        val fresh = FluxsyncAccessibilityService.newRemoteItems(history, emptySet())
        assertEquals(listOf(2L, 3L, 5L), fresh.map { it.lamport })
    }

    @Test
    fun newRemoteItemsEmptyWhenAllHashesSeen() {
        val history = listOf(
            histItem(5, "remote"),
            histItem(4, "local"),
            histItem(3, "remote"),
        )
        val fresh = FluxsyncAccessibilityService.newRemoteItems(history, setOf("h5", "h3"))
        assertTrue("known hashes must suppress the restart flood", fresh.isEmpty())
    }

    @Test
    fun newRemoteItemsExcludesLocalAndKeepsOldestFirst() {
        val history = listOf(
            histItem(9, "remote"),
            histItem(8, "remote"),
            histItem(7, "local"),
        )
        val fresh = FluxsyncAccessibilityService.newRemoteItems(history, emptySet())
        assertEquals(listOf(8L, 9L), fresh.map { it.lamport })
    }

    @Test
    fun newRemoteItemsSurvivesDaemonLamportReset() {
        // After a daemon restart the new remote item carries a LOW lamport (1)
        // while a previously-applied item had a high one (500). A Lamport gate
        // would `break` and drop it; the hash set lets it through.
        val history = listOf(
            histItem(1, "remote"),
            histItem(500, "remote"),
        )
        val fresh = FluxsyncAccessibilityService.newRemoteItems(history, setOf("h500"))
        assertEquals(listOf(1L), fresh.map { it.lamport })
    }

    @Test
    fun stopWithinTimeoutBoundsAWedgedStop() = runBlocking {
        val started = System.currentTimeMillis()
        val ok = FluxsyncAccessibilityService.stopWithinTimeout(100L) {
            delay(5_000L)
        }
        val elapsed = System.currentTimeMillis() - started
        assertFalse("a wedged stop must report timeout", ok)
        assertTrue(
            "must return near the deadline ($elapsed ms), not after the full hang",
            elapsed < 1_000L,
        )
    }
}
