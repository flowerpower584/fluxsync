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

    @Test
    fun countsFullMeshWhenPeersPresent() {
        val s = DaemonState.parse(
            """{"peer_name":"A","peers":[{"name":"A","primary":true},{"name":"B","primary":false}]}"""
        ) ?: error("parse returned null")
        assertEquals(2, pairedPeerCount(s))
    }
}
