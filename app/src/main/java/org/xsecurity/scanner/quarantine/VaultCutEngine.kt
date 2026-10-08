package org.xsecurity.scanner.quarantine

import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * Ports the pure engine needs. Android adapters live in [VaultDeleteFlow]; JVM tests use fakes.
 */
interface VaultPort {
    /** Streams the entry through decryption + SHA-256; false if the entry is missing, tampered, or differs. */
    fun verify(fileName: String, expectedSha256: String?): Boolean

    @Throws(IOException::class)
    fun restoreTo(fileName: String, destination: File)

    fun delete(fileName: String): Boolean
}

/** Where the restored bytes ended up. */
data class RestoreDestination(val kind: String, val location: String) {
    companion object {
        const val KIND_ORIGINAL_PATH = "original_path"
        const val KIND_ORIGINAL_UNCHANGED = "original_still_present"
        const val KIND_DOWNLOADS = "downloads"
        const val KIND_APP_PRIVATE = "app_private"
    }
}

/** Result of asking the platform for a user confirmation step. */
sealed class SystemConfirmation {
    /** An opaque token (an IntentSender on Android) the host must launch; the engine waits for the answer. */
    data class Pending(val token: Any) : SystemConfirmation()

    /** The platform deleted the item without needing a prompt. */
    object CompletedWithoutPrompt : SystemConfirmation()

    object Unavailable : SystemConfirmation()
}

interface OriginalPort {
    fun capabilities(record: QuarantineRecord): VaultCutPolicy.Capabilities

    /** true/false when it can be determined, null when the platform hides the file from us. */
    fun exists(record: QuarantineRecord): Boolean?

    /** Current SHA-256 of the original, or null when it cannot be read. */
    fun sha256(record: QuarantineRecord): String?

    fun deleteDirect(record: QuarantineRecord): Boolean
    fun deleteViaDocumentProvider(record: QuarantineRecord): Boolean
    fun deleteViaResolver(record: QuarantineRecord): Boolean
    fun requestSystemConfirmation(record: QuarantineRecord, route: VaultCutPolicy.Route): SystemConfirmation

    /** App-private scratch file the decrypted bytes are written to before the move. */
    fun restoreScratchFile(record: QuarantineRecord): File

    /**
     * Moves [payload] to the original location (Downloads / app-private fallback). On success the
     * payload file no longer exists (moved, or deleted after copy); null means nothing was written.
     */
    fun placeRestored(record: QuarantineRecord, payload: File): RestoreDestination?
}

interface RecordPort {
    fun load(id: String): QuarantineRecord?
    fun saveResidue(id: String, residue: OriginalResidue, cutResult: String?, nowMillis: Long): QuarantineRecord?
    fun transition(
        id: String,
        state: QuarantineState,
        actor: QuarantineActor,
        nowMillis: Long,
        failureCode: String? = null
    ): QuarantineTransitionResult

    fun updateRestoreInfo(id: String, restoreInfo: String, nowMillis: Long)
}

sealed class CutOutcome {
    data class Removed(val method: String) : CutOutcome()
    object Denied : CutOutcome()
    data class Failed(val code: String) : CutOutcome()
    data class NeedsUserConfirmation(val token: Any, val route: VaultCutPolicy.Route) : CutOutcome()
}

sealed class RestoreOutcome {
    data class Restored(val destination: RestoreDestination) : RestoreOutcome()
    data class Failed(val code: String) : RestoreOutcome()
}

sealed class DeleteOutcome {
    data class Deleted(val residue: OriginalResidue) : DeleteOutcome()
    data class NeedsUserConfirmation(val token: Any, val route: VaultCutPolicy.Route) : DeleteOutcome()
    object Denied : DeleteOutcome()
    data class Failed(val code: String) : DeleteOutcome()
}

/**
 * Cut-and-paste quarantine, pure part.
 *
 *  - [cut]: verify the vault copy, make sure the original is still what we scanned, then remove it
 *    through the first permitted [VaultCutPolicy.Route]. Routes that need the platform's own
 *    confirmation suspend the flow with [CutOutcome.NeedsUserConfirmation]; the host launches the
 *    token and reports back via [completeUserConfirmation].
 *  - Denied / failed attempts leave the record QUARANTINED + ORIGINAL_PRESENT with a result code
 *    so the UI can offer "Delete now" again. Nothing here ever deletes without a prior user tap:
 *    automation must only ever call the staging side ([VaultDeleteFlow.stage]).
 *  - [restore]: decrypt to scratch, verify the hash, move the bytes back, drop the vault copy
 *    (no duplicates), RESTORED by USER_ACTION only (state machine enforces the actor).
 *  - [deleteRecord]: optionally cuts the original first, then removes the vault copy.
 */
class VaultCutEngine(
    private val vault: VaultPort,
    private val original: OriginalPort,
    private val records: RecordPort
) {
    fun cut(recordId: String, nowMillis: Long = System.currentTimeMillis()): CutOutcome {
        val record = records.load(recordId) ?: return CutOutcome.Failed(CutResultCodes.FAILED_RECORD_NOT_FOUND)
        if (!QuarantineHonesty.isFileRecord(record)) return CutOutcome.Failed(CutResultCodes.FAILED_NOT_FILE_RECORD)
        if (record.state != QuarantineState.QUARANTINED) return CutOutcome.Failed(CutResultCodes.FAILED_NOT_QUARANTINED)
        if (QuarantineHonesty.effectiveResidue(record) == OriginalResidue.ORIGINAL_REMOVED) {
            return CutOutcome.Removed(record.cutResult ?: CutResultCodes.REMOVED_ALREADY_ABSENT)
        }
        val vaultFile = record.vaultFileName ?: return fail(record, CutResultCodes.FAILED_VAULT_MISSING, nowMillis)
        // Never destroy the only copy: the encrypted entry must decrypt and match the scanned hash.
        if (!vault.verify(vaultFile, record.sha256)) return fail(record, CutResultCodes.FAILED_VAULT_VERIFY, nowMillis)

        if (original.exists(record) == false) return removed(record, CutResultCodes.REMOVED_ALREADY_ABSENT, nowMillis)
        val currentHash = original.sha256(record)
        if (currentHash != null && record.sha256 != null && !currentHash.equals(record.sha256, ignoreCase = true)) {
            // Somebody replaced the file after the scan: it is not the threat we vaulted.
            return fail(record, CutResultCodes.FAILED_ORIGINAL_CHANGED, nowMillis)
        }

        val capabilities = original.capabilities(record)
        val routes = VaultCutPolicy.routes(capabilities)
        if (routes.isEmpty()) return fail(record, VaultCutPolicy.unavailableReason(capabilities), nowMillis)

        for (route in routes) {
            when (route) {
                VaultCutPolicy.Route.DIRECT_DELETE ->
                    if (original.deleteDirect(record)) return confirmRemoved(record, CutResultCodes.REMOVED_DIRECT, nowMillis)
                VaultCutPolicy.Route.DOCUMENT_PROVIDER_DELETE ->
                    if (original.deleteViaDocumentProvider(record)) return confirmRemoved(record, CutResultCodes.REMOVED_DOCUMENT_PROVIDER, nowMillis)
                VaultCutPolicy.Route.RESOLVER_DELETE ->
                    if (original.deleteViaResolver(record)) return confirmRemoved(record, CutResultCodes.REMOVED_RESOLVER, nowMillis)
                VaultCutPolicy.Route.SYSTEM_DELETE_REQUEST, VaultCutPolicy.Route.RECOVERABLE_SECURITY_PROMPT -> {
                    when (val confirmation = original.requestSystemConfirmation(record, route)) {
                        is SystemConfirmation.Pending -> {
                            records.saveResidue(record.id, OriginalResidue.ORIGINAL_PRESENT, CutResultCodes.AWAITING_USER, nowMillis)
                            return CutOutcome.NeedsUserConfirmation(confirmation.token, route)
                        }
                        SystemConfirmation.CompletedWithoutPrompt ->
                            return confirmRemoved(record, CutResultCodes.REMOVED_RESOLVER, nowMillis)
                        SystemConfirmation.Unavailable -> Unit
                    }
                }
            }
        }
        val code = if (capabilities.directWriteAccess || capabilities.pathIsAppPrivate) CutResultCodes.FAILED_DELETE
        else CutResultCodes.FAILED_PERMISSION
        return fail(record, code, nowMillis)
    }

    /** The host launched the platform confirmation returned by [cut]; [confirmed] is the user's answer. */
    fun completeUserConfirmation(
        recordId: String,
        route: VaultCutPolicy.Route,
        confirmed: Boolean,
        nowMillis: Long = System.currentTimeMillis()
    ): CutOutcome {
        val record = records.load(recordId) ?: return CutOutcome.Failed(CutResultCodes.FAILED_RECORD_NOT_FOUND)
        if (!QuarantineHonesty.isFileRecord(record)) return CutOutcome.Failed(CutResultCodes.FAILED_NOT_FILE_RECORD)
        if (!confirmed) {
            records.saveResidue(record.id, OriginalResidue.ORIGINAL_PRESENT, CutResultCodes.DENIED_BY_USER, nowMillis)
            return CutOutcome.Denied
        }
        if (route == VaultCutPolicy.Route.RECOVERABLE_SECURITY_PROMPT) {
            // API 29 prompt only grants permission; the delete itself is ours to redo.
            if (!original.deleteViaResolver(record) && original.exists(record) != false) {
                return fail(record, CutResultCodes.FAILED_DELETE, nowMillis)
            }
            return confirmRemoved(record, CutResultCodes.REMOVED_SYSTEM_DIALOG, nowMillis)
        }
        return confirmRemoved(record, CutResultCodes.REMOVED_SYSTEM_DIALOG, nowMillis)
    }

    fun restore(recordId: String, nowMillis: Long = System.currentTimeMillis()): RestoreOutcome {
        val record = records.load(recordId) ?: return RestoreOutcome.Failed(CutResultCodes.FAILED_RECORD_NOT_FOUND)
        if (!QuarantineHonesty.isFileRecord(record)) return RestoreOutcome.Failed(CutResultCodes.FAILED_NOT_FILE_RECORD)
        if (record.state != QuarantineState.QUARANTINED) return RestoreOutcome.Failed(CutResultCodes.FAILED_NOT_QUARANTINED)
        val vaultFile = record.vaultFileName ?: return RestoreOutcome.Failed(CutResultCodes.FAILED_VAULT_MISSING)

        val scratch = original.restoreScratchFile(record)
        try {
            vault.restoreTo(vaultFile, scratch)
        } catch (_: IOException) {
            scratch.delete()
            return RestoreOutcome.Failed(CutResultCodes.RESTORE_DECRYPT_FAILED)
        }
        val hash = try {
            sha256(scratch)
        } catch (_: IOException) {
            scratch.delete()
            return RestoreOutcome.Failed(CutResultCodes.RESTORE_DECRYPT_FAILED)
        }
        if (record.sha256 != null && !hash.equals(record.sha256, ignoreCase = true)) {
            scratch.delete()
            return RestoreOutcome.Failed(CutResultCodes.RESTORE_HASH_MISMATCH)
        }
        val destination = original.placeRestored(record, scratch)
        if (destination == null) {
            scratch.delete()
            return RestoreOutcome.Failed(CutResultCodes.RESTORE_WRITE_FAILED)
        }
        // "Move", not "copy": exactly one plaintext copy and no vault copy remain.
        if (scratch.exists()) scratch.delete()
        val vaultRemoved = vault.delete(vaultFile)
        records.updateRestoreInfo(
            record.id,
            "method=file_restore;destination_kind=${destination.kind};destination=${destination.location}" +
                ";vault_copy=${if (vaultRemoved) "removed" else "removal_failed"}",
            nowMillis
        )
        records.saveResidue(record.id, OriginalResidue.ORIGINAL_PRESENT, record.cutResult, nowMillis)
        return when (val result = records.transition(record.id, QuarantineState.RESTORED, QuarantineActor.USER_ACTION, nowMillis)) {
            is QuarantineTransitionResult.Accepted -> RestoreOutcome.Restored(destination)
            is QuarantineTransitionResult.Rejected -> RestoreOutcome.Failed(result.code)
        }
    }

    fun deleteRecord(
        recordId: String,
        alsoDeleteOriginal: Boolean,
        nowMillis: Long = System.currentTimeMillis()
    ): DeleteOutcome {
        val record = records.load(recordId) ?: return DeleteOutcome.Failed(CutResultCodes.FAILED_RECORD_NOT_FOUND)
        if (!QuarantineHonesty.isFileRecord(record)) return DeleteOutcome.Failed(CutResultCodes.FAILED_NOT_FILE_RECORD)
        if (record.state != QuarantineState.QUARANTINED && record.state != QuarantineState.FAILED) {
            return DeleteOutcome.Failed(CutResultCodes.FAILED_NOT_QUARANTINED)
        }
        if (alsoDeleteOriginal && QuarantineHonesty.originalRemovalPending(record)) {
            when (val cut = cut(recordId, nowMillis)) {
                is CutOutcome.Removed -> Unit
                is CutOutcome.NeedsUserConfirmation -> return DeleteOutcome.NeedsUserConfirmation(cut.token, cut.route)
                CutOutcome.Denied -> return DeleteOutcome.Denied
                is CutOutcome.Failed -> return DeleteOutcome.Failed(cut.code)
            }
        }
        record.vaultFileName?.let { vault.delete(it) }
        return when (val result = records.transition(record.id, QuarantineState.DELETED, QuarantineActor.USER_ACTION, nowMillis)) {
            is QuarantineTransitionResult.Accepted ->
                DeleteOutcome.Deleted(QuarantineHonesty.effectiveResidue(result.record) ?: OriginalResidue.ORIGINAL_PRESENT)
            is QuarantineTransitionResult.Rejected -> DeleteOutcome.Failed(result.code)
        }
    }

    private fun confirmRemoved(record: QuarantineRecord, method: String, nowMillis: Long): CutOutcome {
        // A route claimed success; if we can still see the file, the claim is false and we say so.
        if (original.exists(record) == true) return fail(record, CutResultCodes.FAILED_STILL_PRESENT, nowMillis)
        return removed(record, method, nowMillis)
    }

    private fun removed(record: QuarantineRecord, method: String, nowMillis: Long): CutOutcome {
        records.saveResidue(record.id, OriginalResidue.ORIGINAL_REMOVED, method, nowMillis)
        return CutOutcome.Removed(method)
    }

    private fun fail(record: QuarantineRecord, code: String, nowMillis: Long): CutOutcome {
        records.saveResidue(record.id, OriginalResidue.ORIGINAL_PRESENT, code, nowMillis)
        return CutOutcome.Failed(code)
    }

    companion object {
        @Throws(IOException::class)
        fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (read > 0) digest.update(buffer, 0, read)
                }
            }
            return digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        }
    }
}
