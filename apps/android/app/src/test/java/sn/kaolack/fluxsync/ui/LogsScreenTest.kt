package sn.kaolack.fluxsync.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import sn.kaolack.fluxsync.ui.screens.shouldAutoScrollLogs

/**
 * FS-023: log auto-scroll must follow new entries only while the user is
 * pinned at the exact top, and pause the moment they scroll away.
 */
class LogsScreenTest {

    @Test
    fun autoScrollsWhenPinnedAtTop() {
        assertTrue(shouldAutoScrollLogs(firstVisibleItemIndex = 0, firstVisibleItemScrollOffset = 0))
    }

    @Test
    fun doesNotYankUserReadingTheSecondEntry() {
        // The old `<= 1` threshold wrongly auto-scrolled here.
        assertFalse(shouldAutoScrollLogs(firstVisibleItemIndex = 1, firstVisibleItemScrollOffset = 0))
    }

    @Test
    fun pausesWhenScrolledWithinTheFirstItem() {
        assertFalse(shouldAutoScrollLogs(firstVisibleItemIndex = 0, firstVisibleItemScrollOffset = 50))
    }

    @Test
    fun pausesWhenScrolledWellDown() {
        assertFalse(shouldAutoScrollLogs(firstVisibleItemIndex = 5, firstVisibleItemScrollOffset = 0))
    }
}
