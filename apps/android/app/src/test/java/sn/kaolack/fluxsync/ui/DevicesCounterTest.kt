package sn.kaolack.fluxsync.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import sn.kaolack.fluxsync.ui.screens.pairedPeerCount
import sn.kaolack.fluxsync.vm.DaemonState

class DevicesCounterTest {

    private fun state(peerName: String): DaemonState =
        DaemonState.parse("""{"peer_name":"$peerName"}""")
            ?: error("parse returned null")

    @Test
    fun zeroPeersWhenPeerNameEmpty() {
        assertEquals(0, pairedPeerCount(state("")))
    }

    @Test
    fun onePeerWhenPeerNamePresent() {
        assertEquals(1, pairedPeerCount(state("Dethie-Mac")))
    }
}
