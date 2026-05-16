package sn.kaolack.fluxsync

import org.junit.Assert.assertEquals
import org.junit.Test
import sn.kaolack.fluxsync.vm.LogEntryView
import java.util.concurrent.CountDownLatch

class FluxsyncManagerTest {

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
}
