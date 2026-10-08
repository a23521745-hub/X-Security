package org.xsecurity.scanner.autopilot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FileScanAutopilotTest {
    @Test fun knownBadAtL2ChoosesQuarantineAndAuditOmitsPathAndHash() {
        val secretPath = "/private/user/downloads/bad.apk"
        val secretHash = "a".repeat(64)
        val event = SecurityEvent.FileScan(secretPath, secretHash, SecuritySignal.Verdict.KNOWN_BAD, "YARA")
        val signal = SecuritySignal(SecuritySignal.ProviderId.SCANNER, SecuritySignal.Verdict.KNOWN_BAD,
            SecuritySignal.Risk.HIGH, "file_signature_match")
        val decision = PolicyEngine.decide(event, listOf(signal), AutonomyLevel.L2)
        assertEquals(PolicyAction.BLOCK_AND_QUARANTINE, decision.action)
        val auditLine = AuditLog.encode(AuditRecord.from(event, listOf(signal), decision, AutonomyLevel.L2))
        assertTrue(auditLine.contains("FILE_SCAN"))
        assertTrue(auditLine.contains("KNOWN_BAD"))
        assertFalse(auditLine.contains(secretPath))
        assertFalse(auditLine.contains(secretHash))
    }

    @Test fun unknownHighAsksAndKnownGoodIsSilentAllow() {
        val unknown = SecurityEvent.FileScan("/tmp/input", null, SecuritySignal.Verdict.UNKNOWN, "unavailable")
        val unknownSignal = SecuritySignal(SecuritySignal.ProviderId.SCANNER, SecuritySignal.Verdict.UNKNOWN,
            SecuritySignal.Risk.HIGH, "file_scan_incomplete")
        assertEquals(PolicyAction.ASK_USER, PolicyEngine.decide(unknown, listOf(unknownSignal), AutonomyLevel.L2).action)

        val clean = SecurityEvent.FileScan("/tmp/input", "b".repeat(64), SecuritySignal.Verdict.KNOWN_GOOD, "YARA")
        val cleanSignal = SecuritySignal(SecuritySignal.ProviderId.SCANNER, SecuritySignal.Verdict.KNOWN_GOOD,
            SecuritySignal.Risk.LOW, "file_scan_clean")
        assertEquals(PolicyAction.ALLOW, PolicyEngine.decide(clean, listOf(cleanSignal), AutonomyLevel.L2).action)
    }
}
