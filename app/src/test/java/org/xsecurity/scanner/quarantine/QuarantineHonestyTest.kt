package org.xsecurity.scanner.quarantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** HONESTY RULE: no display state may claim a full quarantine while the original file is intact. */
class QuarantineHonestyTest {
    private fun record(
        state: QuarantineState,
        residue: OriginalResidue?,
        packageName: String = QuarantineHonesty.FILE_VAULT_PACKAGE
    ) = QuarantineRecord(
        id = "r",
        packageName = packageName,
        label = "bad.apk",
        sha256 = "ab".repeat(32),
        verdict = "KNOWN_BAD",
        engine = "YARA",
        detectedAtMillis = 1,
        updatedAtMillis = 1,
        state = state,
        residue = residue,
        sourcePath = "/storage/emulated/0/Download/bad.apk"
    )

    @Test
    fun noDisplayStateClaimsFullQuarantineWhileOriginalIsPresent() {
        for (state in QuarantineState.values()) {
            for (residue in listOf(null, OriginalResidue.ORIGINAL_PRESENT, OriginalResidue.ORIGINAL_REMOVED)) {
                for (packageName in listOf(QuarantineHonesty.FILE_VAULT_PACKAGE, "org.example.app")) {
                    val candidate = record(state, residue, packageName)
                    val display = QuarantineHonesty.displayState(candidate)
                    if (QuarantineHonesty.claimsFullQuarantine(display)) {
                        assertEquals(
                            "full claim with residue $residue for $packageName/$state",
                            OriginalResidue.ORIGINAL_REMOVED,
                            QuarantineHonesty.effectiveResidue(candidate)
                        )
                        assertTrue(QuarantineHonesty.mayClaimFullQuarantine(candidate))
                    } else {
                        assertFalse(QuarantineHonesty.mayClaimFullQuarantine(candidate))
                    }
                    if (QuarantineHonesty.effectiveResidue(candidate) == OriginalResidue.ORIGINAL_PRESENT) {
                        assertFalse("$state/$residue must not claim full quarantine", QuarantineHonesty.claimsFullQuarantine(display))
                    }
                }
            }
        }
    }

    @Test
    fun quarantinedFileWithOriginalPresentIsOnlyACopySavedState() {
        val staged = record(QuarantineState.QUARANTINED, OriginalResidue.ORIGINAL_PRESENT)
        assertEquals(QuarantineDisplayState.FILE_COPY_SAVED_ORIGINAL_PRESENT, QuarantineHonesty.displayState(staged))
        assertTrue(QuarantineHonesty.originalRemovalPending(staged))
        assertFalse(QuarantineHonesty.mayClaimFullQuarantine(staged))

        val cut = record(QuarantineState.QUARANTINED, OriginalResidue.ORIGINAL_REMOVED)
        assertEquals(QuarantineDisplayState.FILE_QUARANTINED_ORIGINAL_REMOVED, QuarantineHonesty.displayState(cut))
        assertFalse(QuarantineHonesty.originalRemovalPending(cut))
        assertTrue(QuarantineHonesty.mayClaimFullQuarantine(cut))
    }

    @Test
    fun legacyFileRecordsWithoutResidueAreTreatedAsOriginalPresent() {
        val legacy = record(QuarantineState.QUARANTINED, residue = null)
        assertEquals(OriginalResidue.ORIGINAL_PRESENT, QuarantineHonesty.effectiveResidue(legacy))
        assertEquals(QuarantineDisplayState.FILE_COPY_SAVED_ORIGINAL_PRESENT, QuarantineHonesty.displayState(legacy))
        assertFalse(QuarantineHonesty.mayClaimFullQuarantine(legacy))
    }

    @Test
    fun packageRecordsCarryNoResidueAndStayBestEffort() {
        val pkg = record(QuarantineState.QUARANTINED, OriginalResidue.ORIGINAL_REMOVED, packageName = "org.example.app")
        assertNull(QuarantineHonesty.effectiveResidue(pkg))
        assertEquals(QuarantineDisplayState.PACKAGE_CONTAINED_BEST_EFFORT, QuarantineHonesty.displayState(pkg))
        assertFalse(QuarantineHonesty.claimsFullQuarantine(QuarantineHonesty.displayState(pkg)))
        assertFalse(QuarantineHonesty.originalRemovalPending(pkg))
    }

    @Test
    fun deletedFileRecordDistinguishesWhetherOriginalWasEverRemoved() {
        assertEquals(
            QuarantineDisplayState.FILE_COPY_DELETED_ORIGINAL_PRESENT,
            QuarantineHonesty.displayState(record(QuarantineState.DELETED, OriginalResidue.ORIGINAL_PRESENT))
        )
        assertEquals(
            QuarantineDisplayState.DELETED,
            QuarantineHonesty.displayState(record(QuarantineState.DELETED, OriginalResidue.ORIGINAL_REMOVED))
        )
    }

    @Test
    fun stateMachineTransitionsPreserveResidueAndSourceFields() {
        val staged = record(QuarantineState.QUARANTINED, OriginalResidue.ORIGINAL_PRESENT).copy(sourceUri = "file:///x")
        val restored = QuarantineStateMachine.transition(staged, QuarantineState.RESTORED, 5, QuarantineActor.USER_ACTION)
        assertTrue(restored is QuarantineTransitionResult.Accepted)
        val record = (restored as QuarantineTransitionResult.Accepted).record
        assertEquals(OriginalResidue.ORIGINAL_PRESENT, record.residue)
        assertEquals("file:///x", record.sourceUri)
        assertEquals(staged.sourcePath, record.sourcePath)
    }
}
