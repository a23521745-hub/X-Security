package org.xsecurity.scanner.autopilot

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.quarantine.CutOutcome
import org.xsecurity.scanner.quarantine.CutResultCodes
import org.xsecurity.scanner.quarantine.FileVault
import org.xsecurity.scanner.quarantine.OriginalResidue
import org.xsecurity.scanner.quarantine.QuarantineHonesty
import org.xsecurity.scanner.quarantine.QuarantineRecord
import org.xsecurity.scanner.quarantine.QuarantineRepository
import org.xsecurity.scanner.quarantine.QuarantineState
import org.xsecurity.scanner.quarantine.RestoreDestination
import org.xsecurity.scanner.quarantine.RestoreOutcome
import org.xsecurity.scanner.quarantine.VaultDeleteFlow
import java.io.File

/**
 * Cut-and-paste quarantine end to end on a device: automation stages non-destructively
 * (ORIGINAL_PRESENT, file untouched), the user's tap removes the original, restore moves it back.
 */
@RunWith(AndroidJUnit4::class)
class FileScanDispatchTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun dispatchKnownBad(fixture: File, sha256: String?, engine: String): ActionDispatcher.Result {
        val event = SecurityEvent.FileScan(
            path = fixture.absolutePath,
            sha256 = sha256,
            verdict = SecuritySignal.Verdict.KNOWN_BAD,
            engine = engine,
            sourceUri = Uri.fromFile(fixture).toString()
        )
        val signals = listOf(
            SecuritySignal(SecuritySignal.ProviderId.SCANNER, SecuritySignal.Verdict.KNOWN_BAD, SecuritySignal.Risk.HIGH, "file_signature_match")
        )
        val decision = PolicyDecision(PolicyAction.BLOCK_AND_QUARANTINE, PolicyEngine.REASON_KNOWN_BAD_CONTAINED, true)
        return ActionDispatcher().dispatch(context, event, signals, decision, AutonomyLevel.L2)
    }

    private fun recordFor(engine: String): QuarantineRecord? {
        QuarantineRepository.restore(context)
        return QuarantineRepository.records.value.firstOrNull { it.packageName == "file-vault" && it.engine == engine }
    }

    @Test fun knownBadFileIsStagedNonDestructivelyAndAudited() {
        val engine = "YARA-stage-${System.nanoTime()}"
        val fixture = File(context.cacheDir, "dispatch-fixture-${System.nanoTime()}").apply { writeText("test fixture") }
        try {
            assertEquals(ActionDispatcher.Result.EXECUTED, dispatchKnownBad(fixture, Digest.sha256Hex(fixture), engine))
            val record = recordFor(engine)
            assertNotNull(record)
            assertEquals(QuarantineState.QUARANTINED, record!!.state)
            assertNotNull(record.vaultFileName)
            assertTrue(FileVault.verify(context, record.vaultFileName!!, record.sha256))
            // L2 automation never touches the original: it is still there and the record says so.
            assertTrue(fixture.isFile)
            assertEquals(OriginalResidue.ORIGINAL_PRESENT, record.residue)
            assertEquals(fixture.absolutePath, record.sourcePath)
            assertFalse(QuarantineHonesty.mayClaimFullQuarantine(record))
            assertTrue(QuarantineHonesty.originalRemovalPending(record))
            assertTrue(AuditLog.read(context).any { it.eventType == "FILE_SCAN" && it.decisionAction == "BLOCK_AND_QUARANTINE" })
        } finally {
            fixture.delete()
        }
    }

    @Test fun userTapRemovesAnAppPrivateOriginalDirectlyAndRestoreMovesItBack() {
        val engine = "YARA-cut-${System.nanoTime()}"
        val payload = "cut me".toByteArray()
        val fixture = File(context.cacheDir, "dispatch-cut-${System.nanoTime()}").apply { writeBytes(payload) }
        try {
            assertEquals(ActionDispatcher.Result.EXECUTED, dispatchKnownBad(fixture, Digest.sha256Hex(fixture), engine))
            val staged = recordFor(engine)!!

            // The one user tap: app-private path => direct delete, no system dialog.
            val cut = VaultDeleteFlow.cut(context, staged.id)
            assertEquals(CutOutcome.Removed(CutResultCodes.REMOVED_DIRECT), cut)
            assertFalse(fixture.exists())
            val removed = recordFor(engine)!!
            assertEquals(OriginalResidue.ORIGINAL_REMOVED, removed.residue)
            assertTrue(QuarantineHonesty.mayClaimFullQuarantine(removed))

            // Restore = move back + drop the vault copy, RESTORED by user action.
            val restore = VaultDeleteFlow.restore(context, staged.id)
            assertTrue("restore failed: $restore", restore is RestoreOutcome.Restored)
            assertEquals(RestoreDestination.KIND_ORIGINAL_PATH, (restore as RestoreOutcome.Restored).destination.kind)
            assertArrayEquals(payload, fixture.readBytes())
            assertFalse(FileVault.exists(context, staged.vaultFileName!!))
            assertEquals(QuarantineState.RESTORED, recordFor(engine)!!.state)
        } finally {
            fixture.delete()
        }
    }

    @Test fun rescanningTheSameFileUpdatesTheSameRecordInsteadOfAddingASecondRow() {
        // P0 record dedup: same sha256 + same sourcePath => UPDATE, never a second row.
        val engine = "YARA-dedup-${System.nanoTime()}"
        val fixture = File(context.cacheDir, "dispatch-dedup-${System.nanoTime()}").apply { writeText("dedup fixture") }
        try {
            val sha = Digest.sha256Hex(fixture)
            assertEquals(ActionDispatcher.Result.EXECUTED, dispatchKnownBad(fixture, sha, engine))
            val first = recordFor(engine)!!

            assertEquals(ActionDispatcher.Result.EXECUTED, dispatchKnownBad(fixture, sha, engine))

            QuarantineRepository.restore(context)
            val matching = QuarantineRepository.records.value.filter {
                it.packageName == "file-vault" && it.sourcePath == fixture.absolutePath
            }
            assertEquals("rescan must not create a second record: $matching", 1, matching.size)
            val updated = matching.single()
            assertEquals(first.id, updated.id)
            assertEquals(QuarantineState.QUARANTINED, updated.state)
            assertEquals(OriginalResidue.ORIGINAL_PRESENT, updated.residue)
            assertTrue(updated.updatedAtMillis >= first.updatedAtMillis)
            // Record identity: the row keeps the real file name and its size, not a hash.
            assertEquals(fixture.name, updated.label)
            assertEquals(fixture.length(), updated.sizeBytes)
            assertTrue(FileVault.verify(context, updated.vaultFileName!!, updated.sha256))
        } finally {
            fixture.delete()
        }
    }

    @Test fun fileWhoseHashNoLongerMatchesTheScanIsNotVaulted() {
        val engine = "YARA-mismatch-${System.nanoTime()}"
        val fixture = File(context.cacheDir, "dispatch-mismatch-${System.nanoTime()}").apply { writeText("changed after scan") }
        try {
            assertEquals(ActionDispatcher.Result.ACTION_FAILED, dispatchKnownBad(fixture, "ab".repeat(32), engine))
            assertNull(recordFor(engine))
            assertTrue(fixture.isFile)
        } finally {
            fixture.delete()
        }
    }
}
