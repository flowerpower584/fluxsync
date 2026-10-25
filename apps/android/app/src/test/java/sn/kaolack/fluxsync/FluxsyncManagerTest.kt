package sn.kaolack.fluxsync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import sn.kaolack.fluxsync.vm.LogEntryView
import java.util.concurrent.CountDownLatch

class FluxsyncManagerTest {

    // FluxsyncManager is a process-wide singleton; isolate every test.
    @Before
    fun reset() {
        FluxsyncManager.resetForTesting()
    }

    @Test
    fun concurrentAppendLogsDropsNothing() {
        val count = 100
        val start = CountDownLatch(1)
        val done = CountDownLatch(count)

        val threads = (0 until count).map { i ->
            Thread {
                start.await()
                FluxsyncManager.appendLogs(
                    listOf(
                        LogEntryView(
                            seq = i.toLong(),
                            time = "00:00",
                            level = "info",
                            msg = "entry-$i",
                            raw = "entry-$i",
                        ),
                    ),
                )
                done.countDown()
            }
        }
        threads.forEach { it.start() }
        start.countDown()
        done.await()

        val logs = FluxsyncManager.logs.value
        assertEquals(count, logs.size)
        assertEquals((0 until count).toSet(), logs.map { it.seq.toInt() }.toSet())
    }

    /**
     * FS-012: appendLogs merges the log cursor with a read-modify-write.
     * Under concurrent appends the cursor must still settle on the highest
     * seq seen. The old `@Volatile var` could lose an update and let the
     * cursor regress, re-delivering already-seen entries on the next poll.
     */
    @Test
    fun concurrentAppendLogsKeepsHighestCursor() {
        val count = 100
        val start = CountDownLatch(1)
        val done = CountDownLatch(count)

        val threads = (1..count).map { seq ->
            Thread {
                start.await()
                FluxsyncManager.appendLogs(
                    listOf(
                        LogEntryView(
                            seq = seq.toLong(),
                            time = "00:00",
                            level = "info",
                            msg = "entry-$seq",
                            raw = "entry-$seq",
                        ),
                    ),
                )
                done.countDown()
            }
        }
        threads.forEach { it.start() }
        start.countDown()
        done.await()

        assertEquals(count.toLong(), FluxsyncManager.logCursor)
    }

    /**
     * FS-018: reportError publishes a transient error for the Snackbar,
     * clearError dismisses it, and resetForTesting wipes it.
     */
    @Test
    fun reportAndClearTransientError() {
        assertNull("starts clean", FluxsyncManager.lastError.value)

        FluxsyncManager.reportError("Toggle failed: daemon not running")
        assertEquals(
            "Toggle failed: daemon not running",
            FluxsyncManager.lastError.value,
        )

        FluxsyncManager.clearError()
        assertNull("clearError dismisses", FluxsyncManager.lastError.value)

        FluxsyncManager.reportError("again")
        FluxsyncManager.resetForTesting()
        assertNull("resetForTesting wipes", FluxsyncManager.lastError.value)
    }

    // Clipboard guards. Every call passes an explicit elapsedRealtime so the
    // echo window is exercised without a device clock.

    private val window = FluxsyncManager.ECHO_WINDOW_MS

    @Test
    fun peerWriteReadBackImmediatelyIsAnEcho() {
        FluxsyncManager.rememberPeerClip("from desktop", nowMs = 1_000)
        assertTrue(FluxsyncManager.isRecentPeerClip("from desktop", nowMs = 1_050))
        assertTrue("keys are trimmed", FluxsyncManager.isRecentPeerClip(" from desktop\n", nowMs = 1_050))
        assertFalse(FluxsyncManager.isRecentPeerClip("something else", nowMs = 1_050))
    }

    @Test
    fun peerTextCopiedAgainAfterTheWindowIsPushed() {
        FluxsyncManager.rememberPeerClip("A", nowMs = 0)
        assertTrue(FluxsyncManager.isRecentPeerClip("A", nowMs = window - 1))
        // 6 s later the same text on the clipboard is the user copying it.
        assertFalse(FluxsyncManager.isRecentPeerClip("A", nowMs = 6_000))
        assertTrue(FluxsyncManager.markPushedIfNew("A", nowMs = 6_000))
    }

    @Test
    fun oneCopySeenTwiceIsPushedOnce() {
        // a11y "Copy" detector + clip listener for the same copy.
        assertTrue(FluxsyncManager.markPushedIfNew("A", nowMs = 1_000))
        assertFalse(FluxsyncManager.markPushedIfNew("A", nowMs = 1_040))
        assertFalse(FluxsyncManager.markPushedIfNew("A", nowMs = 1_000 + window - 1))
        assertTrue(FluxsyncManager.markPushedIfNew("A", nowMs = 1_000 + window))
    }

    @Test
    fun copyingABThenAAgainPushesAAgain() {
        assertTrue(FluxsyncManager.markPushedIfNew("A", nowMs = 0))
        assertTrue(FluxsyncManager.markPushedIfNew("B", nowMs = 2_000))
        assertTrue("re-copy of A must sync", FluxsyncManager.markPushedIfNew("A", nowMs = 6_000))
        // …and that re-copy's own second detection is still deduped.
        assertFalse(FluxsyncManager.markPushedIfNew("A", nowMs = 6_050))
    }

    @Test
    fun resumeDoesNotRepushAStaleClip() {
        // Last thing we pushed is still on the clipboard a minute later.
        assertTrue(FluxsyncManager.markPushedIfNew("pushed", nowMs = 0))
        assertFalse(FluxsyncManager.markResumePushIfNew("pushed", nowMs = 60_000))

        // Same for the last item written from a peer.
        FluxsyncManager.rememberPeerClip("from peer", nowMs = 0)
        assertFalse(FluxsyncManager.markResumePushIfNew("from peer", nowMs = 60_000))

        // An older clip, not the newest, is just as stale.
        assertTrue(FluxsyncManager.markPushedIfNew("newer", nowMs = 1_000))
        assertFalse(FluxsyncManager.markResumePushIfNew("pushed", nowMs = 120_000))
    }

    @Test
    fun resumePushesTextNeverSyncedOnce() {
        assertTrue(FluxsyncManager.markResumePushIfNew("new", nowMs = 10_000))
        assertFalse("next resume", FluxsyncManager.markResumePushIfNew("new", nowMs = 70_000))
        assertFalse("listener racing the resume", FluxsyncManager.markPushedIfNew("new", nowMs = 10_050))
    }

    @Test
    fun guardsStayBounded() {
        for (i in 0 until 16) FluxsyncManager.markPushedIfNew("t$i", nowMs = i.toLong())
        FluxsyncManager.markPushedIfNew("t16", nowMs = 16)
        // The oldest of 17 fell out; the other 16 are still known to onResume.
        assertFalse(FluxsyncManager.markResumePushIfNew("t1", nowMs = 60_000))
        assertTrue(FluxsyncManager.markResumePushIfNew("t0", nowMs = 60_000))
    }

    @Test
    fun clearPeerClipsForgetsPeerWrites() {
        FluxsyncManager.rememberPeerClip("from peer", nowMs = 0)
        FluxsyncManager.clearPeerClips()
        assertFalse(FluxsyncManager.isRecentPeerClip("from peer", nowMs = 10))
        assertTrue(FluxsyncManager.markResumePushIfNew("from peer", nowMs = 10))
    }
}
