package org.xsecurity.scanner.quarantine

import android.app.PendingIntent
import android.app.RecoverableSecurityException
import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import androidx.annotation.RequiresApi
import org.xsecurity.scanner.autopilot.AuditLog
import org.xsecurity.scanner.autopilot.AuditRecord
import org.xsecurity.scanner.autopilot.AutopilotSettings
import org.xsecurity.scanner.autopilot.SecurityEvent
import org.xsecurity.scanner.autopilot.SecuritySignal
import org.xsecurity.scanner.data.ScanController
import org.xsecurity.scanner.device.StorageAccess
import java.io.File
import java.io.IOException
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Cut-and-paste quarantine for files, Android side.
 *
 *  1. [stage] (automation, non-destructive): encrypt a copy into [FileVault], verify it decrypts
 *     to the scanned hash, create the record QUARANTINED + ORIGINAL_PRESENT with the original's
 *     location. Nothing of the user's is touched.
 *  2. [cut] (always behind the user's one in-app tap): remove the original. With All Files
 *     Access (or legacy WRITE) this is a silent direct delete; without it the same tap is routed
 *     through `MediaStore.createDeleteRequest` (API 30+) / the RecoverableSecurityException prompt
 *     (API 29), which the host activity launches and reports back via [completeUserConfirmation].
 *  3. Denied / failed: the record stays QUARANTINED + ORIGINAL_PRESENT, the ongoing notification
 *     keeps offering "Delete now".
 *  4. [restore] moves the bytes back (original path, Downloads fallback) and removes the vault copy.
 *
 * All decisions live in the pure [VaultCutEngine]; this file only adapts storage/UI.
 */
object VaultDeleteFlow {
    const val TAG = "xsec-vault-cut"

    /** Non-destructive staging after a known-bad verdict. Null when nothing could be vaulted. */
    fun stage(context: Context, event: SecurityEvent.FileScan): QuarantineRecord? {
        val appContext = context.applicationContext
        val scanned = File(event.path)
        val id = "f-${UUID.randomUUID()}"
        val stored = try {
            FileVault.store(appContext, scanned, id)
        } catch (_: Exception) {
            return null
        }
        if (event.sha256 != null && !stored.sha256.equals(event.sha256, ignoreCase = true)) {
            // The file changed between scan and vaulting: do not vault something we never scanned.
            FileVault.delete(appContext, stored.fileName)
            return null
        }
        if (!FileVault.verify(appContext, stored.fileName, stored.sha256)) {
            FileVault.delete(appContext, stored.fileName)
            return null
        }
        val source = SourceLocation.resolve(appContext, event.sourceUri, scanned)
        // Real file name (real extension) from the ORIGINAL location; never the staged copy name
        // (`<sha256>.apk`) or a vault entry name — see RecordLabel.
        val label = RecordLabel.derive(source.path, source.uri)
            ?: source.displayName?.takeIf { !RecordLabel.isPlaceholder(it, stored.sha256, stored.fileName) }
            ?: RecordLabel.UNKNOWN_FILENAME
        val sizeBytes = scanned.length().takeIf { it > 0L }
        val scanOrigin = QuarantineFormat.normalizeOrigin(event.origin)

        // RECORD DEDUP (P0): the same bytes from the same location are the same case. Re-scanning
        // updates that row (new timestamps/state, new vault copy) instead of appending a second one.
        val existing = QuarantineRepository.findFileRecordByIdentity(
            appContext, stored.sha256, source.path, source.uri
        )
        val now = System.currentTimeMillis()
        val record = if (existing != null) {
            // The superseded vault copy is only dropped once the new one verified above.
            existing.vaultFileName
                ?.takeIf { it != stored.fileName }
                ?.let { FileVault.delete(appContext, it) }
            QuarantineRepository.saveReobserved(
                appContext,
                RecordDedup.reobserved(
                    existing = existing,
                    sha256 = stored.sha256,
                    label = label,
                    engine = event.engine,
                    sizeBytes = sizeBytes,
                    scanOrigin = scanOrigin,
                    vaultFileName = stored.fileName,
                    sourcePath = source.path,
                    sourceUri = source.uri,
                    nowMillis = now
                )
            )
        } else {
            val created = QuarantineRepository.newRecord(
                packageName = QuarantineHonesty.FILE_VAULT_PACKAGE,
                label = label,
                sha256 = stored.sha256,
                verdict = "KNOWN_BAD",
                engine = event.engine.ifBlank { "unknown" },
                nowMillis = now,
                vaultFileName = stored.fileName,
                restoreInfo = "encrypted_file_vault",
                residue = OriginalResidue.ORIGINAL_PRESENT,
                sourceUri = source.uri,
                sourcePath = source.path,
                sizeBytes = sizeBytes,
                scanOrigin = scanOrigin
            )
            QuarantineRepository.insert(appContext, created)
            QuarantineRepository.transition(appContext, created.id, QuarantineState.PENDING, QuarantineActor.AUTOMATION)
            QuarantineRepository.transition(appContext, created.id, QuarantineState.QUARANTINED, QuarantineActor.AUTOMATION)
            created
        }
        if (source.uri == null && source.path == null) {
            QuarantineRepository.updateResidue(
                appContext, record.id, OriginalResidue.ORIGINAL_PRESENT, CutResultCodes.FAILED_LOCATION_UNKNOWN
            )
        }
        return QuarantineRepository.record(appContext, record.id)
    }

    fun engine(context: Context): VaultCutEngine {
        val appContext = context.applicationContext
        return VaultCutEngine(AndroidVaultPort(appContext), AndroidOriginalPort(appContext), RepositoryRecordPort(appContext))
    }

    /** The user tapped "Delete now" (in-app confirmation already given by that tap). */
    fun cut(context: Context, recordId: String): CutOutcome {
        val appContext = context.applicationContext
        val outcome = engine(appContext).cut(recordId)
        afterCut(appContext, recordId, outcome, "user_delete_original")
        return outcome
    }

    /** Result of the platform dialog launched for [CutOutcome.NeedsUserConfirmation]. */
    fun completeUserConfirmation(
        context: Context,
        recordId: String,
        route: VaultCutPolicy.Route,
        confirmed: Boolean
    ): CutOutcome {
        val appContext = context.applicationContext
        val outcome = engine(appContext).completeUserConfirmation(recordId, route, confirmed)
        afterCut(appContext, recordId, outcome, if (confirmed) "user_confirmed_system_delete" else "user_denied_system_delete")
        return outcome
    }

    fun restore(context: Context, recordId: String): RestoreOutcome {
        val appContext = context.applicationContext
        val outcome = engine(appContext).restore(recordId)
        when (outcome) {
            is RestoreOutcome.Restored -> {
                SourceGrants.release(appContext, QuarantineRepository.record(appContext, recordId)?.sourceUri)
                QuarantineFileNotifications.cancel(appContext, recordId)
                audit(appContext, "USER_FILE_RESTORE", "file_restored_${outcome.destination.kind}")
            }
            is RestoreOutcome.Failed -> audit(appContext, "USER_FILE_RESTORE", "file_restore_failed_${outcome.code}")
        }
        return outcome
    }

    fun deleteRecord(context: Context, recordId: String, alsoDeleteOriginal: Boolean): DeleteOutcome {
        val appContext = context.applicationContext
        val outcome = engine(appContext).deleteRecord(recordId, alsoDeleteOriginal)
        when (outcome) {
            is DeleteOutcome.Deleted -> {
                SourceGrants.release(appContext, QuarantineRepository.record(appContext, recordId)?.sourceUri)
                QuarantineFileNotifications.cancel(appContext, recordId)
                audit(appContext, "USER_FILE_RECORD_DELETE", "file_record_deleted_${outcome.residue.name.lowercase()}")
            }
            is DeleteOutcome.Failed -> audit(appContext, "USER_FILE_RECORD_DELETE", "file_record_delete_failed_${outcome.code}")
            DeleteOutcome.Denied -> audit(appContext, "USER_FILE_RECORD_DELETE", "user_denied_system_delete")
            is DeleteOutcome.NeedsUserConfirmation -> Unit
        }
        return outcome
    }

    /** Re-shows the honest "original still on device" notification for every pending record (boot/app start). */
    fun refreshPendingNotifications(context: Context) {
        val appContext = context.applicationContext
        QuarantineRepository.pendingOriginalRemovals(appContext).forEach { record ->
            QuarantineFileNotifications.showStaged(appContext, record)
        }
    }

    private fun afterCut(context: Context, recordId: String, outcome: CutOutcome, gesture: String) {
        val record = QuarantineRepository.record(context, recordId)
        when (outcome) {
            is CutOutcome.Removed -> {
                SourceGrants.release(context, record?.sourceUri)
                if (record != null) QuarantineFileNotifications.showRemoved(context, record)
                audit(context, "USER_FILE_CUT", "${gesture}_${outcome.method}")
            }
            CutOutcome.Denied -> {
                if (record != null) QuarantineFileNotifications.showStaged(context, record)
                audit(context, "USER_FILE_CUT", gesture)
            }
            is CutOutcome.Failed -> {
                if (record != null) QuarantineFileNotifications.showStaged(context, record)
                audit(context, "USER_FILE_CUT", "${gesture}_failed_${outcome.code}")
            }
            is CutOutcome.NeedsUserConfirmation -> Unit
        }
    }

    /** Content-free audit line: codes only, never paths or names. */
    private fun audit(context: Context, action: String, reason: String) {
        val now = System.currentTimeMillis()
        val safeReason = reason.lowercase().replace(Regex("[^a-z0-9_]"), "_").take(80)
        AuditLog.append(
            context,
            AuditRecord(
                id = UUID.randomUUID().toString(),
                timestampMillis = now,
                eventType = SecurityEvent.Type.MANUAL.name,
                packageName = QuarantineHonesty.FILE_VAULT_PACKAGE,
                isSystemPackage = false,
                eventOccurredAtMillis = now,
                signals = listOf(
                    SecuritySignal(
                        SecuritySignal.ProviderId.LIFECYCLE,
                        SecuritySignal.Verdict.UNKNOWN,
                        SecuritySignal.Risk.LOW,
                        safeReason
                    )
                ),
                decisionAction = action,
                decisionReason = safeReason,
                autonomyLevel = AutopilotSettings.level(context).name
            )
        )
    }
}

/** Where the scanned bytes originally came from, as far as we can tell without touching them. */
internal data class SourceLocation(val uri: String?, val path: String?, val displayName: String?) {
    companion object {
        fun resolve(context: Context, sourceUri: String?, scanned: File): SourceLocation {
            val staging = runCatching { ScanController.stagingDirectory(context).canonicalPath }.getOrNull()
            val scannedIsStagedCopy = staging != null &&
                SourceLocator.isUnder(runCatching { scanned.canonicalPath }.getOrDefault(scanned.absolutePath), listOf(staging))
            if (sourceUri.isNullOrBlank()) {
                // No origin recorded: the scanned file itself is the original unless it is our staged copy.
                return if (scannedIsStagedCopy) SourceLocation(null, null, null)
                else SourceLocation(Uri.fromFile(scanned).toString(), scanned.absolutePath, scanned.name)
            }
            val ref = SourceLocator.parse(sourceUri) ?: return SourceLocation(sourceUri, null, null)
            val path = ref.path
                ?: externalStoragePath(ref)
                ?: mediaPath(context, ref)
            val displayName = path?.substringAfterLast('/')
                ?: ref.relativePath?.substringAfterLast('/')
                ?: displayNameOf(context, sourceUri)
            return SourceLocation(sourceUri, path, displayName)
        }

        private fun externalStoragePath(ref: SourceLocator.SourceRef): String? {
            val volume = ref.volume ?: return null
            val relative = ref.relativePath ?: return null
            @Suppress("DEPRECATION")
            val root = if (volume.equals("primary", ignoreCase = true)) {
                runCatching { Environment.getExternalStorageDirectory().absolutePath }.getOrNull() ?: return null
            } else {
                "/storage/$volume"
            }
            return "$root/$relative"
        }

        private fun mediaPath(context: Context, ref: SourceLocator.SourceRef): String? {
            val uri = AndroidOriginalPort.mediaUri(context, ref, null) ?: return null
            return try {
                @Suppress("DEPRECATION")
                context.contentResolver.query(uri, arrayOf(MediaStore.MediaColumns.DATA), null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getString(0) else null
                }
            } catch (_: Exception) {
                null
            }
        }

        private fun displayNameOf(context: Context, sourceUri: String): String? = try {
            context.contentResolver.query(
                Uri.parse(sourceUri), arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null
            )?.use { cursor -> if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getString(0) else null }
        } catch (_: Exception) {
            null
        }
    }
}

/** Persistable SAF grants on the user's original, so a later "Delete now" can still reach it. */
object SourceGrants {
    fun takePersistable(context: Context, uri: Uri?) {
        if (uri == null || uri.scheme != "content") return
        val resolver = context.contentResolver
        try {
            resolver.takePersistableUriPermission(
                uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
            return
        } catch (_: SecurityException) {
            // No write grant offered (e.g. GET_CONTENT); keep at least read if possible.
        } catch (_: RuntimeException) {
            return
        }
        try {
            resolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (_: RuntimeException) {
            // Not persistable at all; the cut will fall back to MediaStore / All Files Access routes.
        }
    }

    fun release(context: Context, uri: String?) {
        val parsed = uri?.let { runCatching { Uri.parse(it) }.getOrNull() } ?: return
        if (parsed.scheme != "content") return
        val resolver = context.contentResolver
        val held = try {
            resolver.persistedUriPermissions.firstOrNull { it.uri == parsed }
        } catch (_: RuntimeException) {
            null
        } ?: return
        var flags = 0
        if (held.isReadPermission) flags = flags or Intent.FLAG_GRANT_READ_URI_PERMISSION
        if (held.isWritePermission) flags = flags or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        if (flags == 0) return
        try {
            resolver.releasePersistableUriPermission(parsed, flags)
        } catch (_: RuntimeException) {
            // Already gone.
        }
    }

    fun hasWriteGrant(context: Context, uri: Uri): Boolean = try {
        context.contentResolver.persistedUriPermissions.any { permission ->
            permission.isWritePermission && (
                permission.uri == uri ||
                    (DocumentsContract.isTreeUri(permission.uri) && uri.toString().startsWith(permission.uri.toString()))
                )
        }
    } catch (_: RuntimeException) {
        false
    }
}

internal class AndroidVaultPort(private val context: Context) : VaultPort {
    override fun verify(fileName: String, expectedSha256: String?): Boolean = FileVault.verify(context, fileName, expectedSha256)

    @Throws(IOException::class)
    override fun restoreTo(fileName: String, destination: File) = FileVault.restoreTo(context, fileName, destination)

    override fun delete(fileName: String): Boolean = FileVault.delete(context, fileName)
}

internal class RepositoryRecordPort(private val context: Context) : RecordPort {
    override fun load(id: String): QuarantineRecord? = QuarantineRepository.record(context, id)

    override fun saveResidue(id: String, residue: OriginalResidue, cutResult: String?, nowMillis: Long): QuarantineRecord? =
        QuarantineRepository.updateResidue(context, id, residue, cutResult, nowMillis)

    override fun transition(
        id: String,
        state: QuarantineState,
        actor: QuarantineActor,
        nowMillis: Long,
        failureCode: String?
    ): QuarantineTransitionResult = QuarantineRepository.transition(context, id, state, actor, nowMillis, failureCode)

    override fun updateRestoreInfo(id: String, restoreInfo: String, nowMillis: Long) {
        QuarantineRepository.updateRestoreInfo(context, id, restoreInfo, nowMillis)
    }
}

/**
 * Reaches the user's original through whichever door is open: the plain File API (app-private
 * paths, All Files Access, legacy WRITE), a live SAF write grant, or MediaStore.
 */
internal class AndroidOriginalPort(private val context: Context) : OriginalPort {
    private val resolver get() = context.contentResolver

    override fun capabilities(record: QuarantineRecord): VaultCutPolicy.Capabilities {
        val path = record.sourcePath
        val ref = SourceLocator.parse(record.sourceUri)
        return VaultCutPolicy.Capabilities(
            sdkInt = Build.VERSION.SDK_INT,
            directWriteAccess = StorageAccess.hasDirectDeleteAccess(context),
            pathKnown = path != null,
            pathIsAppPrivate = path != null && isAppPrivate(path),
            documentGrantAlive = documentUri(ref) != null,
            mediaUriAvailable = mediaUri(context, ref, path) != null
        )
    }

    override fun exists(record: QuarantineRecord): Boolean? {
        val path = record.sourcePath
        if (path != null) {
            val file = File(path)
            if (file.exists()) return true
            if (isAppPrivate(path) || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || StorageAccess.hasDirectDeleteAccess(context)) {
                return false
            }
            // Scoped storage (API 29+) hides other apps' non-media files from the File API: ask the providers.
        }
        val ref = SourceLocator.parse(record.sourceUri)
        val uri = documentUri(ref) ?: mediaUri(context, ref, path) ?: contentUri(ref)
        return if (uri != null) probe(uri) else null
    }

    override fun sha256(record: QuarantineRecord): String? {
        val path = record.sourcePath
        if (path != null) {
            val file = File(path)
            if (file.isFile && file.canRead()) return runCatching { VaultCutEngine.sha256(file) }.getOrNull()
        }
        val ref = SourceLocator.parse(record.sourceUri)
        val uri = documentUri(ref) ?: mediaUri(context, ref, path) ?: contentUri(ref) ?: return null
        return try {
            resolver.openInputStream(uri)?.use { input ->
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (read > 0) digest.update(buffer, 0, read)
                }
                digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
            }
        } catch (_: Exception) {
            null
        }
    }

    override fun deleteDirect(record: QuarantineRecord): Boolean {
        val path = record.sourcePath ?: return false
        val file = File(path)
        if (!file.exists()) return true
        val deleted = try {
            file.delete()
        } catch (_: SecurityException) {
            false
        }
        if (deleted || !file.exists()) {
            if (!isAppPrivate(path)) runCatching { MediaScannerConnection.scanFile(context, arrayOf(path), null, null) }
            return true
        }
        return false
    }

    override fun deleteViaDocumentProvider(record: QuarantineRecord): Boolean {
        val uri = documentUri(SourceLocator.parse(record.sourceUri)) ?: return false
        return try {
            DocumentsContract.deleteDocument(resolver, uri)
        } catch (_: Exception) {
            false
        }
    }

    override fun deleteViaResolver(record: QuarantineRecord): Boolean {
        val uri = mediaUri(context, SourceLocator.parse(record.sourceUri), record.sourcePath) ?: return false
        return try {
            resolver.delete(uri, null, null) > 0
        } catch (_: SecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }
    }

    override fun requestSystemConfirmation(record: QuarantineRecord, route: VaultCutPolicy.Route): SystemConfirmation {
        val uri = mediaUri(context, SourceLocator.parse(record.sourceUri), record.sourcePath)
            ?: return SystemConfirmation.Unavailable
        return when (route) {
            VaultCutPolicy.Route.SYSTEM_DELETE_REQUEST ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) createDeleteRequest(uri) else SystemConfirmation.Unavailable
            VaultCutPolicy.Route.RECOVERABLE_SECURITY_PROMPT ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) deleteWithRecoverablePrompt(uri) else SystemConfirmation.Unavailable
            else -> SystemConfirmation.Unavailable
        }
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun createDeleteRequest(uri: Uri): SystemConfirmation = try {
        val pending: PendingIntent = MediaStore.createDeleteRequest(resolver, listOf(uri))
        SystemConfirmation.Pending(pending.intentSender)
    } catch (_: Exception) {
        SystemConfirmation.Unavailable
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun deleteWithRecoverablePrompt(uri: Uri): SystemConfirmation = try {
        if (resolver.delete(uri, null, null) > 0) SystemConfirmation.CompletedWithoutPrompt
        else SystemConfirmation.Unavailable
    } catch (recoverable: RecoverableSecurityException) {
        SystemConfirmation.Pending(recoverable.userAction.actionIntent.intentSender)
    } catch (_: Exception) {
        SystemConfirmation.Unavailable
    }

    override fun restoreScratchFile(record: QuarantineRecord): File =
        File(File(context.cacheDir, SCRATCH_DIRECTORY), "${record.id}.tmp")

    override fun placeRestored(record: QuarantineRecord, payload: File): RestoreDestination? {
        val path = record.sourcePath
        val target = path?.let(::File)
        val name = (target?.name ?: record.label).ifBlank { "restored.bin" }

        // 1. The original was never removed (or the user put it back): nothing to write.
        if (exists(record) == true) {
            val current = sha256(record)
            if (current == null || current.equals(record.sha256, ignoreCase = true)) {
                payload.delete()
                return RestoreDestination(RestoreDestination.KIND_ORIGINAL_UNCHANGED, path ?: record.sourceUri ?: name)
            }
        }

        // 2. Original path, when the File API may write there.
        if (target != null && (isAppPrivate(path) || StorageAccess.hasDirectDeleteAccess(context))) {
            val parent = target.parentFile
            if (parent != null && (parent.isDirectory || parent.mkdirs())) {
                val destination = uniqueSibling(target)
                if (moveFile(payload, destination)) {
                    if (!isAppPrivate(path)) {
                        runCatching { MediaScannerConnection.scanFile(context, arrayOf(destination.absolutePath), null, null) }
                    }
                    return RestoreDestination(RestoreDestination.KIND_ORIGINAL_PATH, destination.absolutePath)
                }
            }
        }

        // 3. Public Downloads through MediaStore (no permission needed on API 29+).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            insertIntoDownloads(name, payload)?.let { location ->
                payload.delete()
                return RestoreDestination(RestoreDestination.KIND_DOWNLOADS, location)
            }
        }

        // 4. App-private Downloads (visible via Files/USB); never silently drop the user's bytes.
        val privateDirectory = context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
            ?: File(context.filesDir, "restored")
        if (privateDirectory.isDirectory || privateDirectory.mkdirs()) {
            val destination = uniqueSibling(File(privateDirectory, name))
            if (moveFile(payload, destination)) {
                return RestoreDestination(RestoreDestination.KIND_APP_PRIVATE, destination.absolutePath)
            }
        }
        return null
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun insertIntoDownloads(name: String, payload: File): String? {
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeTypeOf(name))
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
        val item = try {
            resolver.insert(collection, values)
        } catch (_: Exception) {
            null
        } ?: return null
        return try {
            resolver.openOutputStream(item)?.use { output -> payload.inputStream().use { it.copyTo(output) } }
                ?: throw IOException("no output stream")
            resolver.update(item, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
            item.toString()
        } catch (_: Exception) {
            runCatching { resolver.delete(item, null, null) }
            null
        }
    }

    private fun moveFile(source: File, destination: File): Boolean {
        if (source.renameTo(destination)) return true
        return try {
            source.inputStream().use { input -> destination.outputStream().use { output -> input.copyTo(output) } }
            source.delete()
            true
        } catch (_: Exception) {
            runCatching { destination.delete() }
            false
        }
    }

    private fun uniqueSibling(target: File): File {
        if (!target.exists()) return target
        val base = target.nameWithoutExtension
        val extension = target.extension.takeIf { it.isNotEmpty() }?.let { ".$it" }.orEmpty()
        for (index in 1..999) {
            val candidate = File(target.parentFile, "$base ($index)$extension")
            if (!candidate.exists()) return candidate
        }
        return File(target.parentFile, "$base-${System.currentTimeMillis()}$extension")
    }

    private fun probe(uri: Uri): Boolean? = try {
        resolver.openFileDescriptor(uri, "r")?.use { }
        true
    } catch (_: java.io.FileNotFoundException) {
        false
    } catch (_: SecurityException) {
        null
    } catch (_: Exception) {
        null
    }

    private fun contentUri(ref: SourceLocator.SourceRef?): Uri? =
        ref?.takeIf { it.isContent }?.let { runCatching { Uri.parse(it.raw) }.getOrNull() }

    private fun documentUri(ref: SourceLocator.SourceRef?): Uri? {
        if (ref == null || !ref.isDocument) return null
        val uri = runCatching { Uri.parse(ref.raw) }.getOrNull() ?: return null
        return if (SourceGrants.hasWriteGrant(context, uri)) uri else null
    }

    private fun isAppPrivate(path: String): Boolean = SourceLocator.isUnder(canonical(path), appPrivateRoots())

    private fun appPrivateRoots(): List<String> {
        val roots = ArrayList<File>()
        roots += context.cacheDir
        roots += context.filesDir
        roots += context.codeCacheDir
        roots += context.noBackupFilesDir
        context.externalCacheDir?.let(roots::add)
        context.getExternalFilesDir(null)?.let(roots::add)
        context.dataDir?.let(roots::add)
        return roots.map { canonical(it.absolutePath) }
    }

    private fun canonical(path: String): String = runCatching { File(path).canonicalPath }.getOrDefault(path)

    companion object {
        private const val SCRATCH_DIRECTORY = "quarantine-restore"
        private const val SCAN_WAIT_MILLIS = 3_000L

        /** MediaStore item URI for the original, from the recorded URI or by looking the path up. */
        fun mediaUri(context: Context, ref: SourceLocator.SourceRef?, path: String?): Uri? {
            if (ref != null) {
                if (ref.isContent && ref.authority == SourceLocator.AUTHORITY_MEDIA) {
                    return runCatching { Uri.parse(ref.raw) }.getOrNull()
                }
                val id = ref.mediaId
                if (id != null) {
                    val collection = when (ref.mediaCollection) {
                        SourceLocator.MediaCollection.DOWNLOADS ->
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) MediaStore.Downloads.EXTERNAL_CONTENT_URI
                            else MediaStore.Files.getContentUri("external")
                        SourceLocator.MediaCollection.IMAGES -> MediaStore.Images.Media.EXTERNAL_CONTENT_URI
                        SourceLocator.MediaCollection.VIDEO -> MediaStore.Video.Media.EXTERNAL_CONTENT_URI
                        SourceLocator.MediaCollection.AUDIO -> MediaStore.Audio.Media.EXTERNAL_CONTENT_URI
                        SourceLocator.MediaCollection.FILES, null -> MediaStore.Files.getContentUri("external")
                    }
                    return ContentUris.withAppendedId(collection, id)
                }
            }
            if (path == null) return null
            val now = System.currentTimeMillis()
            pathLookups[path]?.let { cached ->
                if (cached.second != null || now - cached.first < NEGATIVE_CACHE_MILLIS) return cached.second
            }
            val found = lookupByPath(context, path) ?: run {
                scanPath(context, path)
                lookupByPath(context, path)
            }
            pathLookups[path] = now to found
            return found
        }

        private val pathLookups = java.util.concurrent.ConcurrentHashMap<String, Pair<Long, Uri?>>()
        private const val NEGATIVE_CACHE_MILLIS = 30_000L

        private fun lookupByPath(context: Context, path: String): Uri? = try {
            val collection = MediaStore.Files.getContentUri("external")
            @Suppress("DEPRECATION")
            context.contentResolver.query(
                collection,
                arrayOf(MediaStore.MediaColumns._ID),
                "${MediaStore.MediaColumns.DATA} = ?",
                arrayOf(path),
                null
            )?.use { cursor -> if (cursor.moveToFirst()) ContentUris.withAppendedId(collection, cursor.getLong(0)) else null }
        } catch (_: Exception) {
            null
        }

        /** The media scanner runs inside MediaProvider, so it can index files the File API hides from us. */
        private fun scanPath(context: Context, path: String) {
            val latch = CountDownLatch(1)
            try {
                MediaScannerConnection.scanFile(context, arrayOf(path), null) { _, _ -> latch.countDown() }
                latch.await(SCAN_WAIT_MILLIS, TimeUnit.MILLISECONDS)
            } catch (_: Exception) {
                // Best effort only.
            }
        }

        private fun mimeTypeOf(name: String): String {
            val extension = name.substringAfterLast('.', "").lowercase()
            if (extension == "apk") return "application/vnd.android.package-archive"
            return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension) ?: "application/octet-stream"
        }
    }
}
