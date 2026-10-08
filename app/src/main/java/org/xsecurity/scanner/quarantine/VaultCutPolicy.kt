package org.xsecurity.scanner.quarantine

/**
 * Pure decision table for removing the ORIGINAL file after its encrypted vault copy has been
 * verified ("cut" half of cut-and-paste quarantine). No Android types, so the matrix is unit-tested.
 *
 * Rules (owner amendment):
 *  - Removal only ever runs after the user's one-tap in-app confirmation; automation stages only.
 *  - With All Files Access (API 30+) or the legacy WRITE permission (API <= 29) the delete is a
 *    silent direct delete; without it the same tap is routed through a system confirmation
 *    (MediaStore.createDeleteRequest on 30+, RecoverableSecurityException prompt on 29).
 *  - A SAF document URI with a live write grant can be deleted through its provider.
 *  - Nothing is ever deleted silently when no permitted route exists; the record stays
 *    ORIGINAL_PRESENT with a retry action.
 */
object VaultCutPolicy {
    const val SDK_Q = 29
    const val SDK_R = 30

    enum class Route {
        /** java.io.File delete (app-private path, All Files Access, or legacy WRITE). */
        DIRECT_DELETE,

        /** DocumentsContract.deleteDocument on a SAF URI whose write grant is still alive. */
        DOCUMENT_PROVIDER_DELETE,

        /** ContentResolver.delete on a MediaStore row (API <= 28 with WRITE; no prompt). */
        RESOLVER_DELETE,

        /** MediaStore.createDeleteRequest system dialog (API 30+). */
        SYSTEM_DELETE_REQUEST,

        /** API 29: ContentResolver.delete -> RecoverableSecurityException -> system prompt -> retry. */
        RECOVERABLE_SECURITY_PROMPT
    }

    data class Capabilities(
        val sdkInt: Int,
        /** All Files Access (30+) or WRITE_EXTERNAL_STORAGE (<= 29). */
        val directWriteAccess: Boolean,
        val pathKnown: Boolean,
        /** Path lives under one of our own app-private directories: always deletable. */
        val pathIsAppPrivate: Boolean,
        /** SAF document URI known and a write grant is currently held. */
        val documentGrantAlive: Boolean,
        /** A MediaStore item URI could be resolved for the original. */
        val mediaUriAvailable: Boolean
    )

    /** Ordered list of routes to attempt; empty means no permitted route exists right now. */
    fun routes(capabilities: Capabilities): List<Route> {
        val routes = ArrayList<Route>(4)
        if (capabilities.pathKnown && (capabilities.pathIsAppPrivate || capabilities.directWriteAccess)) {
            routes += Route.DIRECT_DELETE
        }
        if (capabilities.documentGrantAlive) routes += Route.DOCUMENT_PROVIDER_DELETE
        if (capabilities.mediaUriAvailable) {
            when {
                capabilities.sdkInt >= SDK_R -> routes += Route.SYSTEM_DELETE_REQUEST
                capabilities.sdkInt == SDK_Q -> {
                    if (capabilities.directWriteAccess) routes += Route.RESOLVER_DELETE
                    routes += Route.RECOVERABLE_SECURITY_PROMPT
                }
                capabilities.directWriteAccess -> routes += Route.RESOLVER_DELETE
            }
        }
        return routes
    }

    fun needsUserConfirmation(route: Route): Boolean =
        route == Route.SYSTEM_DELETE_REQUEST || route == Route.RECOVERABLE_SECURITY_PROMPT

    /** Why no route exists: the honest hint shown next to the retry action. */
    fun unavailableReason(capabilities: Capabilities): String = when {
        !capabilities.pathKnown && !capabilities.documentGrantAlive && !capabilities.mediaUriAvailable ->
            CutResultCodes.FAILED_LOCATION_UNKNOWN
        else -> CutResultCodes.FAILED_PERMISSION
    }
}

/** Stable, content-free outcome codes stored in [QuarantineRecord.cutResult] and audited. */
object CutResultCodes {
    const val REMOVED_DIRECT = "removed_direct_delete"
    const val REMOVED_DOCUMENT_PROVIDER = "removed_document_provider"
    const val REMOVED_RESOLVER = "removed_media_resolver"
    const val REMOVED_SYSTEM_DIALOG = "removed_system_dialog"
    const val REMOVED_ALREADY_ABSENT = "removed_already_absent"

    const val AWAITING_USER = "awaiting_system_confirmation"
    const val DENIED_BY_USER = "denied_by_user"

    const val FAILED_VAULT_VERIFY = "vault_verify_failed"
    const val FAILED_VAULT_MISSING = "vault_entry_missing"
    const val FAILED_ORIGINAL_CHANGED = "original_changed_since_scan"
    const val FAILED_DELETE = "delete_failed"
    const val FAILED_PERMISSION = "permission_missing"
    const val FAILED_LOCATION_UNKNOWN = "location_unknown"
    const val FAILED_STILL_PRESENT = "still_present_after_confirmation"
    const val FAILED_RECORD_NOT_FOUND = "record_not_found"
    const val FAILED_NOT_FILE_RECORD = "not_a_file_record"
    const val FAILED_NOT_QUARANTINED = "record_not_quarantined"

    const val RESTORE_DECRYPT_FAILED = "vault_decrypt_failed"
    const val RESTORE_HASH_MISMATCH = "vault_hash_mismatch"
    const val RESTORE_WRITE_FAILED = "restore_write_failed"

    val removedCodes: Set<String> = setOf(
        REMOVED_DIRECT, REMOVED_DOCUMENT_PROVIDER, REMOVED_RESOLVER, REMOVED_SYSTEM_DIALOG, REMOVED_ALREADY_ABSENT
    )

    fun isRemoved(code: String?): Boolean = code != null && code in removedCodes
}
