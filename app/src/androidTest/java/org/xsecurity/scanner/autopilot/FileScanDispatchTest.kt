package org.xsecurity.scanner.autopilot

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.xsecurity.scanner.quarantine.QuarantineRepository
import org.xsecurity.scanner.quarantine.QuarantineState
import java.io.File

@RunWith(AndroidJUnit4::class)
class FileScanDispatchTest {
    @Test fun knownBadFileIsVaultedAndAudited() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val fixture = File(context.cacheDir, "dispatch-fixture-${System.nanoTime()}").apply { writeText("test fixture") }
        try {
            val event = SecurityEvent.FileScan(fixture.absolutePath, "ab".repeat(32), SecuritySignal.Verdict.KNOWN_BAD, "YARA")
            val signals = listOf(SecuritySignal(SecuritySignal.ProviderId.SCANNER, SecuritySignal.Verdict.KNOWN_BAD,
                SecuritySignal.Risk.HIGH, "file_signature_match"))
            val decision = PolicyDecision(PolicyAction.BLOCK_AND_QUARANTINE, PolicyEngine.REASON_KNOWN_BAD_CONTAINED, true)
            assertEquals(ActionDispatcher.Result.EXECUTED,
                ActionDispatcher().dispatch(context, event, signals, decision, AutonomyLevel.L2))
            QuarantineRepository.restore(context)
            val record = QuarantineRepository.records.value.firstOrNull { it.packageName == "file-vault" && it.engine == "YARA" }
            assertNotNull(record)
            assertEquals(QuarantineState.QUARANTINED, record!!.state)
            assertNotNull(record.vaultFileName)
            assertTrue(AuditLog.read(context).any { it.eventType == "FILE_SCAN" && it.decisionAction == "BLOCK_AND_QUARANTINE" })
        } finally {
            fixture.delete()
        }
    }
}
