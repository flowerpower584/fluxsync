package sn.kaolack.fluxsync

import org.junit.Assert.assertEquals
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
}
