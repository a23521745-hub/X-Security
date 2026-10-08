package org.xsecurity.scanner.quarantine

/**
 * Residue flag of a file-vault record: is the ORIGINAL file still on the device?
 *
 * The encrypted vault copy is created non-destructively by automation; the original is only
 * ever removed after an explicit user tap ([VaultCutEngine.cut]). Until that happens the record
 * carries [ORIGINAL_PRESENT] and the UI must say so. Package (soft-quarantine) records carry no
 * residue flag at all.
 */
enum class OriginalResidue { ORIGINAL_PRESENT, ORIGINAL_REMOVED }

/**
 * Honest, user-facing classification of a quarantine record. Pure Kotlin so the
 * "never claim a full quarantine while the original is intact" rule is unit-testable.
 */
enum class QuarantineDisplayState {
    DETECTED,
    PENDING,

    /** Installed package: best-effort soft containment (disable/stop); wording stays "best effort". */
    PACKAGE_CONTAINED_BEST_EFFORT,

    /** File: encrypted copy in the vault, ORIGINAL STILL ON DEVICE. Never a "quarantined" claim. */
    FILE_COPY_SAVED_ORIGINAL_PRESENT,

    /** File: encrypted copy in the vault AND the original was removed. The only full claim. */
    FILE_QUARANTINED_ORIGINAL_REMOVED,

    RESTORED,

    /** Package uninstalled, or file record deleted while the original was already gone. */
    DELETED,

    /** File record deleted by the user, but the original file was never removed. */
    FILE_COPY_DELETED_ORIGINAL_PRESENT,

    FAILED,
    CANCELLED
}

object QuarantineHonesty {
    /** Pseudo package name used by file-vault records (no installed package behind them). */
    const val FILE_VAULT_PACKAGE = "file-vault"

    fun isFileRecord(record: QuarantineRecord): Boolean = record.packageName == FILE_VAULT_PACKAGE

    /**
     * Residue to reason about. File records written before the residue column existed never
     * removed anything, so a missing value is reported as [OriginalResidue.ORIGINAL_PRESENT];
     * assuming removal would be exactly the dishonest claim this rule forbids.
     */
    fun effectiveResidue(record: QuarantineRecord): OriginalResidue? =
        if (!isFileRecord(record)) null else record.residue ?: OriginalResidue.ORIGINAL_PRESENT

    fun displayState(record: QuarantineRecord): QuarantineDisplayState {
        val file = isFileRecord(record)
        val residue = effectiveResidue(record)
        return when (record.state) {
            QuarantineState.DETECTED -> QuarantineDisplayState.DETECTED
            QuarantineState.PENDING -> QuarantineDisplayState.PENDING
            QuarantineState.QUARANTINED -> when {
                !file -> QuarantineDisplayState.PACKAGE_CONTAINED_BEST_EFFORT
                residue == OriginalResidue.ORIGINAL_REMOVED -> QuarantineDisplayState.FILE_QUARANTINED_ORIGINAL_REMOVED
                else -> QuarantineDisplayState.FILE_COPY_SAVED_ORIGINAL_PRESENT
            }
            QuarantineState.RESTORED -> QuarantineDisplayState.RESTORED
            QuarantineState.DELETED -> when {
                file && residue == OriginalResidue.ORIGINAL_PRESENT -> QuarantineDisplayState.FILE_COPY_DELETED_ORIGINAL_PRESENT
                else -> QuarantineDisplayState.DELETED
            }
            QuarantineState.FAILED -> QuarantineDisplayState.FAILED
            QuarantineState.CANCELLED -> QuarantineDisplayState.CANCELLED
        }
    }

    /** Only one display state may tell the user "this threat is fully quarantined". */
    fun claimsFullQuarantine(state: QuarantineDisplayState): Boolean =
        state == QuarantineDisplayState.FILE_QUARANTINED_ORIGINAL_REMOVED

    /** HONESTY RULE: a full-quarantine claim is legal only when the original is gone. */
    fun mayClaimFullQuarantine(record: QuarantineRecord): Boolean =
        claimsFullQuarantine(displayState(record)) && effectiveResidue(record) == OriginalResidue.ORIGINAL_REMOVED

    /** The user still owes a tap: vault copy exists, original is present. */
    fun originalRemovalPending(record: QuarantineRecord): Boolean =
        isFileRecord(record) && record.state == QuarantineState.QUARANTINED &&
            effectiveResidue(record) == OriginalResidue.ORIGINAL_PRESENT

    /** Can the engine even try to remove the original (we know where it is)? */
    fun originalLocationKnown(record: QuarantineRecord): Boolean =
        !record.sourcePath.isNullOrBlank() || !record.sourceUri.isNullOrBlank()
}
