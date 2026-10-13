package org.xsecurity.scanner.quarantine

/**
 * Display identity of a quarantine record: WHICH file was scanned, under its REAL name.
 *
 * The v19 incident: file records were listed under a vault entry name, the staged scan copy
 * name (`<sha256>.apk`) or a bare hash, so the user could not recognise the file — and a
 * forced `.apk` extension was shown even for files that were never APKs. The label is now
 * derived from the original location (sourcePath / sourceUri) and keeps the file's own
 * extension. A hash or a vault entry name is never a label.
 *
 * Pure Kotlin so the rules (and the backfill of legacy rows) are unit-tested on the JVM.
 */
object RecordLabel {
    /** Last-resort stored label for a record whose real name cannot be recovered. */
    const val UNKNOWN_FILENAME = "Scanned file"

    /** Vault entries are `<id>.xsv`; showing one as the file name is exactly the bug. */
    private val VAULT_ENTRY = Regex("(?i)^[a-z0-9-]{1,80}\\.xsv$")

    /** A bare hash, or our staged copy name `<sha256>.apk` (the forced-extension case). */
    private val HASHISH_NAME = Regex("(?i)^[0-9a-f]{16,}(\\.[a-z0-9]{1,10})?$")

    /** Real filename — with its own extension — from an absolute path, or null. */
    fun fromPath(path: String?): String? = path
        ?.trim()
        ?.trimEnd('/', '\\')
        ?.substringAfterLast('/')
        ?.substringAfterLast('\\')
        ?.takeIf { it.isNotBlank() }

    /**
     * Real filename from the recorded source URI. `SourceLocator` understands the SAF
     * (`externalstorage.documents`, `downloads.documents`, `media.documents`), `content://media`
     * and `file://` forms; nothing is guessed from a raw path we cannot trust.
     */
    fun fromUri(uri: String?): String? {
        val ref = SourceLocator.parse(uri) ?: return null
        ref.path?.let { path -> fromPath(path)?.let { return it } }
        ref.relativePath?.let { relative -> fromPath(relative)?.let { return it } }
        return null
    }

    /** Best real filename available from either source. */
    fun derive(sourcePath: String?, sourceUri: String?): String? =
        fromPath(sourcePath) ?: fromUri(sourceUri)

    /** True when this label must never be shown as the file name. */
    fun isPlaceholder(label: String?, sha256: String?, vaultFileName: String?): Boolean {
        val value = label?.trim().orEmpty()
        if (value.isEmpty() || value == UNKNOWN_FILENAME) return true
        if (!vaultFileName.isNullOrBlank() && value.equals(vaultFileName, ignoreCase = true)) return true
        if (value.equals(QuarantineHonesty.FILE_VAULT_PACKAGE, ignoreCase = true)) return true
        if (VAULT_ENTRY.matches(value) || HASHISH_NAME.matches(value)) return true
        if (!sha256.isNullOrBlank() && value.equals(sha256.trim(), ignoreCase = true)) return true
        return false
    }

    /** The label the UI (list and detail) shows; null means "fall back to the localized unknown". */
    fun displayName(record: QuarantineRecord): String? =
        record.label.takeUnless { isPlaceholder(it, record.sha256, record.vaultFileName) }

    /**
     * Backfill for records written before the identity fix: when the stored label is a
     * placeholder and the original location is known, the real filename (real extension)
     * replaces it. Returns null when nothing can be improved — nothing is written then.
     */
    fun backfill(
        label: String?,
        sha256: String?,
        vaultFileName: String?,
        sourcePath: String?,
        sourceUri: String?
    ): String? {
        if (!isPlaceholder(label, sha256, vaultFileName)) return null
        val derived = derive(sourcePath, sourceUri) ?: return null
        return derived.take(120)
    }
}
