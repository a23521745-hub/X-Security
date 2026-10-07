package org.xsecurity.scanner.quarantine

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.IOException

/**
 * Cut-and-paste quarantine flow on the JVM with fake ports: vault -> (user tap) -> delete request,
 * the ORIGINAL_PRESENT retry path, byte-exact move-back restore without duplicates, and the
 * record-delete semantics. Nothing in here deletes an original without an explicit user call.
 */
class VaultCutEngineTest {
    private lateinit var workDir: File
    private lateinit var downloadsDir: File
    private lateinit var vault: FakeVault
    private lateinit var original: FakeOriginal
    private lateinit var records: FakeRecords
    private lateinit var engine: VaultCutEngine

    private val payload = "known-bad fixture bytes".toByteArray()

    @Before
    fun setUp() {
        workDir = java.nio.file.Files.createTempDirectory("xsec-cut").toFile()
        downloadsDir = File(workDir, "Download").apply { mkdirs() }
        vault = FakeVault()
        original = FakeOriginal(workDir, downloadsDir)
        records = FakeRecords()
        engine = VaultCutEngine(vault, original, records)
    }

    @After
    fun tearDown() {
        workDir.deleteRecursively()
    }

    /** Automation's non-destructive staging: file on disk, encrypted copy in the vault, ORIGINAL_PRESENT. */
    private fun stage(name: String = "bad.apk", bytes: ByteArray = payload): QuarantineRecord {
        val file = File(downloadsDir, name).apply { writeBytes(bytes) }
        val vaultName = "f-${name.hashCode().toUInt()}.xsv"
        vault.entries[vaultName] = bytes.copyOf()
        val record = QuarantineRecord(
            id = "rec-$name",
            packageName = QuarantineHonesty.FILE_VAULT_PACKAGE,
            label = name,
            sha256 = sha256(bytes),
            verdict = "KNOWN_BAD",
            engine = "YARA",
            detectedAtMillis = 100,
            updatedAtMillis = 100,
            state = QuarantineState.QUARANTINED,
            vaultFileName = vaultName,
            residue = OriginalResidue.ORIGINAL_PRESENT,
            sourceUri = "file://${file.absolutePath}",
            sourcePath = file.absolutePath
        )
        records.map[record.id] = record
        return record
    }

    @Test
    fun vaultThenSystemDeleteRequestFlowRemovesOriginalOnlyAfterTheUserConfirms() {
        val record = stage()
        original.mediaUriAvailable = true

        val outcome = engine.cut(record.id, nowMillis = 200)
        assertTrue("expected a system confirmation step, got $outcome", outcome is CutOutcome.NeedsUserConfirmation)
        assertEquals(VaultCutPolicy.Route.SYSTEM_DELETE_REQUEST, (outcome as CutOutcome.NeedsUserConfirmation).route)
        assertEquals("system-token", outcome.token)
        // Nothing is destroyed while the dialog is up.
        assertTrue(File(record.sourcePath!!).isFile)
        val awaiting = records.map.getValue(record.id)
        assertEquals(OriginalResidue.ORIGINAL_PRESENT, awaiting.residue)
        assertEquals(CutResultCodes.AWAITING_USER, awaiting.cutResult)
        assertEquals(QuarantineState.QUARANTINED, awaiting.state)

        original.userAnswersSystemDialog(record, confirmed = true)
        val done = engine.completeUserConfirmation(record.id, outcome.route, confirmed = true, nowMillis = 300)
        assertEquals(CutOutcome.Removed(CutResultCodes.REMOVED_SYSTEM_DIALOG), done)
        val cut = records.map.getValue(record.id)
        assertEquals(OriginalResidue.ORIGINAL_REMOVED, cut.residue)
        assertEquals(QuarantineState.QUARANTINED, cut.state)
        assertFalse(File(record.sourcePath).exists())
        assertTrue(vault.entries.containsKey(record.vaultFileName))
        assertTrue(QuarantineHonesty.mayClaimFullQuarantine(cut))
    }

    @Test
    fun denyingTheSystemDialogKeepsOriginalPresentAndRetryCanStillSucceed() {
        val record = stage()
        original.mediaUriAvailable = true

        val first = engine.cut(record.id, nowMillis = 200) as CutOutcome.NeedsUserConfirmation
        original.userAnswersSystemDialog(record, confirmed = false)
        val denied = engine.completeUserConfirmation(record.id, first.route, confirmed = false, nowMillis = 250)
        assertEquals(CutOutcome.Denied, denied)

        val afterDenial = records.map.getValue(record.id)
        assertEquals(QuarantineState.QUARANTINED, afterDenial.state)
        assertEquals(OriginalResidue.ORIGINAL_PRESENT, afterDenial.residue)
        assertEquals(CutResultCodes.DENIED_BY_USER, afterDenial.cutResult)
        assertTrue(File(record.sourcePath!!).isFile)
        assertTrue("retry must remain available", QuarantineHonesty.originalRemovalPending(afterDenial))
        assertFalse(QuarantineHonesty.mayClaimFullQuarantine(afterDenial))

        // "Delete now" again.
        val retry = engine.cut(record.id, nowMillis = 300) as CutOutcome.NeedsUserConfirmation
        original.userAnswersSystemDialog(record, confirmed = true)
        assertEquals(
            CutOutcome.Removed(CutResultCodes.REMOVED_SYSTEM_DIALOG),
            engine.completeUserConfirmation(record.id, retry.route, confirmed = true, nowMillis = 350)
        )
        assertEquals(OriginalResidue.ORIGINAL_REMOVED, records.map.getValue(record.id).residue)
        assertFalse(File(record.sourcePath).exists())
    }

    @Test
    fun allFilesAccessDeletesDirectlyWithoutAnySystemDialog() {
        val record = stage()
        original.directWriteAccess = true
        original.mediaUriAvailable = true

        assertEquals(CutOutcome.Removed(CutResultCodes.REMOVED_DIRECT), engine.cut(record.id, nowMillis = 200))
        assertFalse(File(record.sourcePath!!).exists())
        assertEquals(0, original.confirmationsRequested)
        assertEquals(OriginalResidue.ORIGINAL_REMOVED, records.map.getValue(record.id).residue)
    }

    @Test
    fun appPrivateStagedCopyIsDirectlyDeletableWithoutAnyStoragePermission() {
        val record = stage()
        original.appPrivate = true
        assertEquals(CutOutcome.Removed(CutResultCodes.REMOVED_DIRECT), engine.cut(record.id, nowMillis = 200))
        assertFalse(File(record.sourcePath!!).exists())
    }

    @Test
    fun unverifiableVaultCopyNeverLetsTheOriginalBeDeleted() {
        val record = stage()
        original.directWriteAccess = true
        vault.verifyOverride = false

        assertEquals(CutOutcome.Failed(CutResultCodes.FAILED_VAULT_VERIFY), engine.cut(record.id, nowMillis = 200))
        assertTrue(File(record.sourcePath!!).isFile)
        assertEquals(0, original.deleteAttempts)
        val stored = records.map.getValue(record.id)
        assertEquals(OriginalResidue.ORIGINAL_PRESENT, stored.residue)
        assertEquals(CutResultCodes.FAILED_VAULT_VERIFY, stored.cutResult)
    }

    @Test
    fun originalChangedSinceScanIsNotDeleted() {
        val record = stage()
        original.directWriteAccess = true
        File(record.sourcePath!!).writeBytes("something else entirely".toByteArray())

        assertEquals(CutOutcome.Failed(CutResultCodes.FAILED_ORIGINAL_CHANGED), engine.cut(record.id, nowMillis = 200))
        assertTrue(File(record.sourcePath).isFile)
        assertEquals(0, original.deleteAttempts)
    }

    @Test
    fun hiddenOriginalWithoutAnyPermittedRouteStaysPresentWithAnHonestReason() {
        val record = stage()
        original.hiddenByScopedStorage = true
        assertEquals(CutOutcome.Failed(CutResultCodes.FAILED_PERMISSION), engine.cut(record.id, nowMillis = 200))
        assertTrue(File(record.sourcePath!!).isFile)

        val unknownLocation = record.copy(id = "unknown", sourcePath = null, sourceUri = null)
        records.map[unknownLocation.id] = unknownLocation
        assertEquals(CutOutcome.Failed(CutResultCodes.FAILED_LOCATION_UNKNOWN), engine.cut(unknownLocation.id, nowMillis = 200))
    }

    @Test
    fun alreadyMissingOriginalIsRecordedAsRemovedWithoutDeleting() {
        val record = stage()
        File(record.sourcePath!!).delete()
        assertEquals(CutOutcome.Removed(CutResultCodes.REMOVED_ALREADY_ABSENT), engine.cut(record.id, nowMillis = 200))
        assertEquals(0, original.deleteAttempts)
    }

    @Test
    fun restoreMovesBytesBackToTheOriginalPathWithoutDuplicates() {
        val record = stage()
        original.directWriteAccess = true
        assertTrue(engine.cut(record.id, nowMillis = 200) is CutOutcome.Removed)
        assertFalse(File(record.sourcePath!!).exists())

        val outcome = engine.restore(record.id, nowMillis = 300)
        assertTrue("expected restore, got $outcome", outcome is RestoreOutcome.Restored)
        val destination = (outcome as RestoreOutcome.Restored).destination
        assertEquals(RestoreDestination.KIND_ORIGINAL_PATH, destination.kind)
        assertEquals(record.sourcePath, destination.location)
        assertArrayEquals(payload, File(destination.location).readBytes())

        // Exactly one plaintext copy, no scratch, no vault copy.
        assertFalse(original.restoreScratchFile(record).exists())
        assertFalse(vault.entries.containsKey(record.vaultFileName))
        assertEquals(1, downloadsDir.listFiles()!!.size)
        val restored = records.map.getValue(record.id)
        assertEquals(QuarantineState.RESTORED, restored.state)
        assertEquals(OriginalResidue.ORIGINAL_PRESENT, restored.residue)
        assertNotNull(restored.restoreInfo)
        assertTrue(restored.restoreInfo!!.contains("destination_kind=original_path"))
    }

    @Test
    fun restoreWhileOriginalIsStillPresentDoesNotWriteASecondCopy() {
        val record = stage()
        val outcome = engine.restore(record.id, nowMillis = 300) as RestoreOutcome.Restored
        assertEquals(RestoreDestination.KIND_ORIGINAL_UNCHANGED, outcome.destination.kind)
        assertEquals(1, downloadsDir.listFiles()!!.size)
        assertArrayEquals(payload, File(record.sourcePath!!).readBytes())
        assertFalse(vault.entries.containsKey(record.vaultFileName))
        assertEquals(QuarantineState.RESTORED, records.map.getValue(record.id).state)
    }

    @Test
    fun restoreFallsBackToDownloadsWhenTheOriginalPathIsNotWritable() {
        val record = stage()
        original.directWriteAccess = true
        assertTrue(engine.cut(record.id, nowMillis = 200) is CutOutcome.Removed)
        original.directWriteAccess = false
        original.fallbackDownloads = File(workDir, "FallbackDownloads").apply { mkdirs() }

        val outcome = engine.restore(record.id, nowMillis = 300) as RestoreOutcome.Restored
        assertEquals(RestoreDestination.KIND_DOWNLOADS, outcome.destination.kind)
        assertArrayEquals(payload, File(outcome.destination.location).readBytes())
        assertFalse(vault.entries.containsKey(record.vaultFileName))
        assertFalse(original.restoreScratchFile(record).exists())
    }

    @Test
    fun restoreRefusesACorruptVaultCopyAndKeepsEverything() {
        val record = stage()
        vault.entries[record.vaultFileName!!] = "tampered".toByteArray()
        assertEquals(RestoreOutcome.Failed(CutResultCodes.RESTORE_HASH_MISMATCH), engine.restore(record.id, nowMillis = 300))
        assertTrue(vault.entries.containsKey(record.vaultFileName))
        assertFalse(original.restoreScratchFile(record).exists())
        assertEquals(QuarantineState.QUARANTINED, records.map.getValue(record.id).state)
    }

    @Test
    fun deleteRecordOffersOriginalDeletionFirstAndOnlyThenDropsTheVaultCopy() {
        val record = stage()
        original.mediaUriAvailable = true

        // System dialog route: the vault copy must survive until the original is really gone.
        val pending = engine.deleteRecord(record.id, alsoDeleteOriginal = true, nowMillis = 200)
        assertTrue(pending is DeleteOutcome.NeedsUserConfirmation)
        assertTrue(vault.entries.containsKey(record.vaultFileName))
        assertTrue(File(record.sourcePath!!).isFile)

        original.userAnswersSystemDialog(record, confirmed = true)
        assertTrue(
            engine.completeUserConfirmation(
                record.id, (pending as DeleteOutcome.NeedsUserConfirmation).route, confirmed = true, nowMillis = 250
            ) is CutOutcome.Removed
        )
        val deleted = engine.deleteRecord(record.id, alsoDeleteOriginal = false, nowMillis = 300)
        assertEquals(DeleteOutcome.Deleted(OriginalResidue.ORIGINAL_REMOVED), deleted)
        assertFalse(vault.entries.containsKey(record.vaultFileName))
        assertEquals(QuarantineDisplayState.DELETED, QuarantineHonesty.displayState(records.map.getValue(record.id)))
    }

    @Test
    fun deleteRecordWithoutTouchingTheOriginalKeepsAnHonestResidue() {
        val record = stage()
        val deleted = engine.deleteRecord(record.id, alsoDeleteOriginal = false, nowMillis = 200)
        assertEquals(DeleteOutcome.Deleted(OriginalResidue.ORIGINAL_PRESENT), deleted)
        assertTrue(File(record.sourcePath!!).isFile)
        assertFalse(vault.entries.containsKey(record.vaultFileName))
        val stored = records.map.getValue(record.id)
        assertEquals(QuarantineState.DELETED, stored.state)
        assertEquals(QuarantineDisplayState.FILE_COPY_DELETED_ORIGINAL_PRESENT, QuarantineHonesty.displayState(stored))
    }

    @Test
    fun deniedRecordDeleteLeavesVaultCopyAndOriginalUntouched() {
        val record = stage()
        original.mediaUriAvailable = true
        val pending = engine.deleteRecord(record.id, alsoDeleteOriginal = true, nowMillis = 200) as DeleteOutcome.NeedsUserConfirmation
        assertEquals(CutOutcome.Denied, engine.completeUserConfirmation(record.id, pending.route, confirmed = false, nowMillis = 250))
        assertTrue(vault.entries.containsKey(record.vaultFileName))
        assertTrue(File(record.sourcePath!!).isFile)
        assertEquals(QuarantineState.QUARANTINED, records.map.getValue(record.id).state)
    }

    @Test
    fun api29RecoverablePromptRedoesTheDeleteAfterConsent() {
        val record = stage()
        original.sdkInt = 29
        original.mediaUriAvailable = true
        original.resolverDeletesAfterConsent = true

        val pending = engine.cut(record.id, nowMillis = 200) as CutOutcome.NeedsUserConfirmation
        assertEquals(VaultCutPolicy.Route.RECOVERABLE_SECURITY_PROMPT, pending.route)
        assertTrue(File(record.sourcePath!!).isFile)
        original.userAnswersSystemDialog(record, confirmed = true, platformDeletes = false)
        assertEquals(
            CutOutcome.Removed(CutResultCodes.REMOVED_SYSTEM_DIALOG),
            engine.completeUserConfirmation(record.id, pending.route, confirmed = true, nowMillis = 250)
        )
        assertFalse(File(record.sourcePath).exists())
    }

    @Test
    fun packageRecordsAreRejectedByTheFileFlow() {
        val pkg = stage().copy(id = "pkg", packageName = "org.example.app")
        records.map[pkg.id] = pkg
        assertEquals(CutOutcome.Failed(CutResultCodes.FAILED_NOT_FILE_RECORD), engine.cut(pkg.id, nowMillis = 200))
        assertEquals(RestoreOutcome.Failed(CutResultCodes.FAILED_NOT_FILE_RECORD), engine.restore(pkg.id, nowMillis = 200))
    }

    // --- fakes -------------------------------------------------------------------------------

    private class FakeVault : VaultPort {
        val entries = HashMap<String, ByteArray>()
        var verifyOverride: Boolean? = null

        override fun verify(fileName: String, expectedSha256: String?): Boolean {
            verifyOverride?.let { return it }
            val bytes = entries[fileName] ?: return false
            return expectedSha256 == null || sha256(bytes).equals(expectedSha256, ignoreCase = true)
        }

        override fun restoreTo(fileName: String, destination: File) {
            val bytes = entries[fileName] ?: throw IOException("missing")
            destination.parentFile?.mkdirs()
            destination.writeBytes(bytes)
        }

        override fun delete(fileName: String): Boolean = entries.remove(fileName) != null
    }

    private class FakeOriginal(private val scratchDir: File, private val downloads: File) : OriginalPort {
        var sdkInt = 34
        var directWriteAccess = false
        var appPrivate = false
        var documentGrantAlive = false
        var mediaUriAvailable = false
        var hiddenByScopedStorage = false
        var resolverDeletesAfterConsent = false
        var fallbackDownloads: File = downloads
        var confirmationsRequested = 0
        var deleteAttempts = 0
        private var consentGranted = false

        override fun capabilities(record: QuarantineRecord) = VaultCutPolicy.Capabilities(
            sdkInt = sdkInt,
            directWriteAccess = directWriteAccess,
            pathKnown = record.sourcePath != null,
            pathIsAppPrivate = appPrivate,
            documentGrantAlive = documentGrantAlive,
            mediaUriAvailable = mediaUriAvailable && record.sourcePath != null
        )

        override fun exists(record: QuarantineRecord): Boolean? {
            if (hiddenByScopedStorage) return null
            val path = record.sourcePath ?: return null
            return File(path).exists()
        }

        override fun sha256(record: QuarantineRecord): String? {
            if (hiddenByScopedStorage) return null
            val file = record.sourcePath?.let(::File)?.takeIf { it.isFile } ?: return null
            return VaultCutEngine.sha256(file)
        }

        override fun deleteDirect(record: QuarantineRecord): Boolean {
            deleteAttempts++
            return File(record.sourcePath!!).delete()
        }

        override fun deleteViaDocumentProvider(record: QuarantineRecord): Boolean {
            deleteAttempts++
            return documentGrantAlive && File(record.sourcePath!!).delete()
        }

        override fun deleteViaResolver(record: QuarantineRecord): Boolean {
            deleteAttempts++
            if (sdkInt == 29 && !consentGranted && !directWriteAccess) return false
            if (!directWriteAccess && !(consentGranted && resolverDeletesAfterConsent)) return false
            return File(record.sourcePath!!).delete()
        }

        override fun requestSystemConfirmation(record: QuarantineRecord, route: VaultCutPolicy.Route): SystemConfirmation {
            confirmationsRequested++
            return SystemConfirmation.Pending("system-token")
        }

        /** Simulates the platform dialog: on consent the platform itself deletes (API 30+) unless told otherwise. */
        fun userAnswersSystemDialog(record: QuarantineRecord, confirmed: Boolean, platformDeletes: Boolean = sdkInt >= 30) {
            consentGranted = confirmed
            if (confirmed && platformDeletes) File(record.sourcePath!!).delete()
        }

        override fun restoreScratchFile(record: QuarantineRecord): File = File(scratchDir, "scratch-${record.id}.tmp")

        override fun placeRestored(record: QuarantineRecord, payload: File): RestoreDestination? {
            val target = record.sourcePath?.let(::File)
            if (target != null && target.isFile && VaultCutEngine.sha256(target) == VaultCutEngine.sha256(payload)) {
                payload.delete()
                return RestoreDestination(RestoreDestination.KIND_ORIGINAL_UNCHANGED, target.absolutePath)
            }
            if (target != null && (directWriteAccess || appPrivate)) {
                target.parentFile?.mkdirs()
                if (!payload.renameTo(target)) {
                    target.writeBytes(payload.readBytes())
                    payload.delete()
                }
                return RestoreDestination(RestoreDestination.KIND_ORIGINAL_PATH, target.absolutePath)
            }
            val fallback = File(fallbackDownloads, target?.name ?: record.label)
            fallback.writeBytes(payload.readBytes())
            payload.delete()
            return RestoreDestination(RestoreDestination.KIND_DOWNLOADS, fallback.absolutePath)
        }
    }

    private class FakeRecords : RecordPort {
        val map = HashMap<String, QuarantineRecord>()

        override fun load(id: String): QuarantineRecord? = map[id]

        override fun saveResidue(id: String, residue: OriginalResidue, cutResult: String?, nowMillis: Long): QuarantineRecord? {
            val current = map[id] ?: return null
            return current.copy(residue = residue, cutResult = cutResult, updatedAtMillis = nowMillis).also { map[id] = it }
        }

        override fun transition(
            id: String,
            state: QuarantineState,
            actor: QuarantineActor,
            nowMillis: Long,
            failureCode: String?
        ): QuarantineTransitionResult {
            val current = map[id] ?: return QuarantineTransitionResult.Rejected("record_not_found")
            val result = QuarantineStateMachine.transition(current, state, nowMillis, actor, failureCode)
            if (result is QuarantineTransitionResult.Accepted) map[id] = result.record
            return result
        }

        override fun updateRestoreInfo(id: String, restoreInfo: String, nowMillis: Long) {
            map[id]?.let { map[id] = it.copy(restoreInfo = restoreInfo, updatedAtMillis = nowMillis) }
        }
    }

    private companion object {
        fun sha256(bytes: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
    }
}
