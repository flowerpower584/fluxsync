package sn.kaolack.fluxsync.vm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DaemonStateTest {

    @Test
    fun parsesFullJson() {
        val json = """
            {
              "phase": "Linked",
              "status": "Active",
              "on": true,
              "peer_name": "Dethie-Mac",
              "peer_battery": 88,
              "peer_charging": true,
              "battery_level": 64,
              "charging": false,
              "battery_threshold": 25,
              "link_latency_ms": 12,
              "charge_override": false,
              "history": [
                {"hash":"abc","kind":"text","preview":"hello","time":"14:32","source":"peer","sensitive":false,"lamport":7}
              ],
              "version": "0.5.0",
              "cipher": "chacha20-poly1305",
              "trusted_peer_name": "Dethie-Mac"
            }
        """.trimIndent()

        val s = DaemonState.parse(json)
        assertNotNull(s)
        s!!
        assertEquals("Linked", s.phase)
        assertEquals("Active", s.status)
        assertTrue(s.active)
        assertEquals("Dethie-Mac", s.peerName)
        assertEquals(88, s.peerBattery)
        assertTrue(s.peerCharging)
        assertEquals(64, s.selfBattery)
        assertFalse(s.selfCharging)
        assertEquals(25, s.threshold)
        assertEquals(12, s.linkLatencyMs)
        assertFalse(s.chargeOverride)
        assertEquals(1, s.history.size)
        assertEquals("hello", s.history[0].preview)
        assertEquals(7L, s.history[0].lamport)
        assertEquals("0.5.0", s.version)
        assertEquals("chacha20-poly1305", s.cipher)
        assertEquals("Dethie-Mac", s.trustedPeerName)
    }

    @Test
    fun appliesDefaultsWhenOptionalFieldsMissing() {
        val s = DaemonState.parse("{}")
        assertNotNull(s)
        s!!
        assertEquals("idle", s.phase)
        assertEquals("inactive", s.status)
        assertFalse(s.active)
        assertEquals("", s.peerName)
        assertEquals(0, s.peerBattery)
        assertEquals(0, s.selfBattery)
        assertEquals(20, s.threshold)
        assertEquals(0, s.linkLatencyMs)
        assertTrue(s.chargeOverride)
        assertTrue(s.history.isEmpty())
        assertNull(s.metrics)
    }

    @Test
    fun returnsNullOnMalformedJson() {
        assertNull(DaemonState.parse("{not valid json"))
        assertNull(DaemonState.parse(""))
        assertNull(DaemonState.parse("[]"))
    }

    // FS-017: a parse failure must be traceable, not silent. The catch
    // logs parseFailureMessage — assert it carries the exception text and
    // a bounded head of the offending payload.
    @Test
    fun parseFailureMessageCarriesExceptionAndBoundedRawHead() {
        val long = "x".repeat(500)
        val msg = DaemonState.parseFailureMessage(IllegalStateException("boom"), long)
        assertTrue("must name the failure", msg.contains("DaemonState.parse failed"))
        assertTrue("must include the exception text", msg.contains("boom"))
        assertTrue("must include the raw head", msg.contains("x".repeat(120)))
        assertFalse("raw head must be bounded", msg.contains("x".repeat(121)))
    }
}
