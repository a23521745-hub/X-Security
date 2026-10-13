package org.xsecurity.scanner.quarantine

/**
 * RECORD DEDUP (P0): the same bytes re-scanned from the same location are the SAME case.
 *
 * Identity is `sha256 + sourcePath` (when the path is known) or `sha256 + sourceUri`
 * otherwise. A re-scan of the same identity UPDATES the existing row — new timestamps and
 * state — instead of appending a second one. A different path with the same bytes stays a
 * separate record: the user may hold the same file in two places.
 *
 * A re-observation only ever (re-)stages the encrypted copy, so no user-action gate is
 * bypassed: the original is still removed solely by the explicit "Delete now" tap.
 */
object RecordDedup {

    /** Stable identity string for a file record, or null when it cannot be deduplicated. */
    fun identity(sha256: String?, sourcePath: String?, sourceUri: String?): String? {
        val hash = sha256?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
        val path = sourcePath?.trim()?.takeIf { it.isNotEmpty() }
        if (path != null) return "$hash|path:$path"
        val uri = sourceUri?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        return "$hash|uri:$uri"
    }

    /** True when [existing] is the same file case as the observation described by the arguments. */
    fun isSameCase(
        existing: QuarantineRecord,
        sha256: String?,
        sourcePath: String?,
        sourceUri: String?
    ): Boolean {
        if (!existing.isFileRecord) return false
        val observed = identity(sha256, sourcePath, sourceUri) ?: return false
        return identity(existing.sha256, existing.sourcePath, existing.sourceUri) == observed
    }

    /** Newest matching file record (stores order by `detected_at DESC`), if any. */
    fun findExisting(
        candidates: List<QuarantineRecord>,
        sha256: String?,
        sourcePath: String?,
        sourceUri: String?
    ): QuarantineRecord? = candidates.firstOrNull { isSameCase(it, sha256, sourcePath, sourceUri) }

    /**
     * Update-in-place for a re-observation: new vault copy, new timestamps, QUARANTINED with the
     * original (again) on the device. Null arguments keep the previously known value.
     */
    fun reobserved(
        existing: QuarantineRecord,
        sha256: String?,
        label: String?,
        engine: String?,
        sizeBytes: Long?,
        scanOrigin: String?,
        vaultFileName: String?,
        sourcePath: String?,
        sourceUri: String?,
        nowMillis: Long
    ): QuarantineRecord = existing.copy(
        label = label?.take(120)?.takeIf { it.isNotBlank() } ?: existing.label,
        sha256 = sha256 ?: existing.sha256,
        engine = engine?.takeIf { it.isNotBlank() } ?: existing.engine,
        sizeBytes = sizeBytes ?: existing.sizeBytes,
        scanOrigin = scanOrigin ?: existing.scanOrigin,
        vaultFileName = vaultFileName ?: existing.vaultFileName,
        sourcePath = sourcePath ?: existing.sourcePath,
        sourceUri = sourceUri ?: existing.sourceUri,
        verdict = "KNOWN_BAD",
        detectedAtMillis = nowMillis,
        updatedAtMillis = nowMillis,
        state = QuarantineState.QUARANTINED,
        failureCode = null,
        residue = OriginalResidue.ORIGINAL_PRESENT,
        cutResult = null
    )
}
