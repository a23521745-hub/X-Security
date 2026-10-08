package org.xsecurity.scanner.autopilot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AuditLogModelTest {
    @Test
    fun auditEncodingStoresEventSignalsDecisionAndNoPhishingInput() {
        val privateText = "https://secret.example/account"
        val event = SecurityEvent.Manual(origin = "phishing_share")
        val signal = SecuritySignal(
            SecuritySignal.ProviderId.PHISHING,
            SecuritySignal.Verdict.KNOWN_BAD,
            SecuritySignal.Risk.HIGH,
            "phishing_blocklist_match"
        )
        val decision = PolicyEngine.decide(event, listOf(signal))
        val record = AuditRecord.from(event, listOf(signal), decision, AutonomyLevel.L2, timestampMillis = 7L)
        val encoded = AuditLog.encode(record)

        assertFalse(encoded.contains(privateText))
        assertFalse(encoded.contains("secret.example"))
        val decoded = AuditLog.decode(encoded)
        assertEquals(event.type.name, decoded.eventType)
        assertEquals(signal, decoded.signals.single())
        assertEquals(PolicyAction.BLOCK_CONTENT.name, decoded.decisionAction)
        assertEquals("phishing_blocklist_match", decoded.signals.single().reasonCode)
    }
}
