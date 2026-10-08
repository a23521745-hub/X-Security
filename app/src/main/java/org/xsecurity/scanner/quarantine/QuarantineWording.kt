package org.xsecurity.scanner.quarantine

/**
 * String-resource KEYS used for file-quarantine wording, kept Android-free so a JVM test can
 * read both `strings.xml` files and enforce the honesty rule on the actual texts:
 * every key in [originalPresentKeys] must say the original is still on the device and must not
 * claim a quarantine/containment; only [originalRemovedKeys] may make the full claim.
 * The Android side resolves keys to `R.string` ids in [QuarantineFileNotifications.resolve].
 */
object QuarantineWording {
    // Display states (Quarantine screen)
    const val KEY_STATE_COPY_SAVED_ORIGINAL_PRESENT = "quarantine_display_copy_saved_original_present"
    const val KEY_STATE_QUARANTINED_ORIGINAL_REMOVED = "quarantine_display_quarantined_original_removed"
    const val KEY_STATE_COPY_DELETED_ORIGINAL_PRESENT = "quarantine_display_copy_deleted_original_present"
    const val KEY_RESIDUE_PRESENT = "quarantine_residue_present"
    const val KEY_RESIDUE_REMOVED = "quarantine_residue_removed"

    // Notifications
    const val KEY_NOTIF_STAGED_TITLE = "quarantine_file_staged_title"
    const val KEY_NOTIF_STAGED_BODY = "quarantine_file_staged_body"
    const val KEY_NOTIF_REMOVED_TITLE = "quarantine_file_removed_title"
    const val KEY_NOTIF_REMOVED_BODY = "quarantine_file_removed_body"
    const val KEY_ACTION_DELETE_NOW = "quarantine_file_action_delete_now"
    const val KEY_ACTION_OPEN_QUARANTINE = "autopilot_open_quarantine"

    // Scan-result line shown right after an L2 staging
    const val KEY_SCAN_RESULT_STAGED = "autopilot_file_vaulted"

    // Cut activity results
    const val KEY_CUT_RESULT_REMOVED = "quarantine_cut_result_removed"
    const val KEY_CUT_RESULT_DENIED = "quarantine_cut_result_denied"
    const val KEY_CUT_RESULT_FAILED = "quarantine_cut_result_failed"

    // Record identity: the list shows the real file name/path/size; the hash only lives in detail.
    const val KEY_LIST_PATH = "quarantine_file_path"
    const val KEY_LIST_SIZE = "quarantine_file_size"
    const val KEY_UNKNOWN_FILE = "quarantine_unknown_file"
    const val KEY_VALUE_UNKNOWN = "quarantine_value_unknown"
    const val KEY_DETAILS_OPEN = "quarantine_details_open"
    const val KEY_DETAIL_TITLE = "quarantine_detail_title"
    const val KEY_DETAIL_CLOSE = "quarantine_detail_close"
    const val KEY_DETAIL_NAME = "quarantine_detail_name"
    const val KEY_DETAIL_PATH = "quarantine_detail_path"
    const val KEY_DETAIL_SIZE = "quarantine_detail_size"
    const val KEY_DETAIL_DATE = "quarantine_detail_date"
    const val KEY_DETAIL_VERDICT = "quarantine_detail_verdict"
    const val KEY_DETAIL_ENGINE = "quarantine_detail_engine"
    const val KEY_DETAIL_SHA256 = "quarantine_detail_sha256"
    const val KEY_DETAIL_RESIDUE = "quarantine_detail_residue"
    const val KEY_DETAIL_VAULT_ID = "quarantine_detail_vault_id"
    const val KEY_DETAIL_ORIGIN = "quarantine_detail_origin"

    // Why the original is still there (shown next to "Delete now")
    const val KEY_HINT_DENIED = "quarantine_cut_hint_denied"
    const val KEY_HINT_PERMISSION = "quarantine_cut_hint_permission"
    const val KEY_HINT_LOCATION_UNKNOWN = "quarantine_cut_hint_location_unknown"
    const val KEY_HINT_CHANGED = "quarantine_cut_hint_changed"
    const val KEY_HINT_VAULT = "quarantine_cut_hint_vault"
    const val KEY_HINT_STILL_PRESENT = "quarantine_cut_hint_still_present"
    const val KEY_HINT_DELETE_FAILED = "quarantine_cut_hint_delete_failed"
    const val KEY_HINT_AWAITING = "quarantine_cut_hint_awaiting"

    /** Texts that describe a record whose ORIGINAL IS STILL ON THE DEVICE. */
    val originalPresentKeys: Set<String> = setOf(
        KEY_STATE_COPY_SAVED_ORIGINAL_PRESENT,
        KEY_STATE_COPY_DELETED_ORIGINAL_PRESENT,
        KEY_RESIDUE_PRESENT,
        KEY_NOTIF_STAGED_TITLE,
        KEY_NOTIF_STAGED_BODY,
        KEY_SCAN_RESULT_STAGED,
        KEY_CUT_RESULT_DENIED,
        KEY_CUT_RESULT_FAILED
    )

    /** Texts that may claim the file is quarantined because the original was removed. */
    val originalRemovedKeys: Set<String> = setOf(
        KEY_STATE_QUARANTINED_ORIGINAL_REMOVED,
        KEY_RESIDUE_REMOVED,
        KEY_NOTIF_REMOVED_TITLE,
        KEY_NOTIF_REMOVED_BODY,
        KEY_CUT_RESULT_REMOVED
    )

    /** Failure hints: shown while the original is present, so they may never claim containment either. */
    val hintKeys: Set<String> = setOf(
        KEY_HINT_DENIED, KEY_HINT_PERMISSION, KEY_HINT_LOCATION_UNKNOWN, KEY_HINT_CHANGED,
        KEY_HINT_VAULT, KEY_HINT_STILL_PRESENT, KEY_HINT_DELETE_FAILED, KEY_HINT_AWAITING
    )

    /** Record identity list/detail texts (P0: real name/path/size in the list; hash only in detail). */
    val recordIdentityKeys: Set<String> = setOf(
        KEY_LIST_PATH, KEY_LIST_SIZE, KEY_UNKNOWN_FILE, KEY_VALUE_UNKNOWN,
        KEY_DETAILS_OPEN, KEY_DETAIL_TITLE, KEY_DETAIL_CLOSE, KEY_DETAIL_NAME, KEY_DETAIL_PATH,
        KEY_DETAIL_SIZE, KEY_DETAIL_DATE, KEY_DETAIL_VERDICT, KEY_DETAIL_ENGINE, KEY_DETAIL_SHA256,
        KEY_DETAIL_RESIDUE, KEY_DETAIL_VAULT_ID, KEY_DETAIL_ORIGIN
    )

    val allKeys: Set<String> = originalPresentKeys + originalRemovedKeys + hintKeys +
        recordIdentityKeys + QuarantineFormat.originKeys.values +
        setOf(KEY_ACTION_DELETE_NOW, KEY_ACTION_OPEN_QUARANTINE)

    /** Key for the state line of a file record; null for states that keep the legacy label. */
    fun stateKey(display: QuarantineDisplayState): String? = when (display) {
        QuarantineDisplayState.FILE_COPY_SAVED_ORIGINAL_PRESENT -> KEY_STATE_COPY_SAVED_ORIGINAL_PRESENT
        QuarantineDisplayState.FILE_QUARANTINED_ORIGINAL_REMOVED -> KEY_STATE_QUARANTINED_ORIGINAL_REMOVED
        QuarantineDisplayState.FILE_COPY_DELETED_ORIGINAL_PRESENT -> KEY_STATE_COPY_DELETED_ORIGINAL_PRESENT
        else -> null
    }

    fun residueKey(residue: OriginalResidue): String = when (residue) {
        OriginalResidue.ORIGINAL_PRESENT -> KEY_RESIDUE_PRESENT
        OriginalResidue.ORIGINAL_REMOVED -> KEY_RESIDUE_REMOVED
    }

    /** Hint explaining why the original is still present, from the last cut result code. */
    fun hintKey(cutResult: String?): String? = when (cutResult) {
        null -> null
        CutResultCodes.DENIED_BY_USER -> KEY_HINT_DENIED
        CutResultCodes.FAILED_PERMISSION -> KEY_HINT_PERMISSION
        CutResultCodes.FAILED_LOCATION_UNKNOWN -> KEY_HINT_LOCATION_UNKNOWN
        CutResultCodes.FAILED_ORIGINAL_CHANGED -> KEY_HINT_CHANGED
        CutResultCodes.FAILED_VAULT_VERIFY, CutResultCodes.FAILED_VAULT_MISSING -> KEY_HINT_VAULT
        CutResultCodes.FAILED_STILL_PRESENT -> KEY_HINT_STILL_PRESENT
        CutResultCodes.AWAITING_USER -> KEY_HINT_AWAITING
        CutResultCodes.FAILED_DELETE -> KEY_HINT_DELETE_FAILED
        else -> if (CutResultCodes.isRemoved(cutResult)) null else KEY_HINT_DELETE_FAILED
    }

    /** Notification title/body keys for a file record, by residue. Never a full claim while present. */
    fun notificationKeys(record: QuarantineRecord): Pair<String, String> =
        if (QuarantineHonesty.mayClaimFullQuarantine(record)) KEY_NOTIF_REMOVED_TITLE to KEY_NOTIF_REMOVED_BODY
        else KEY_NOTIF_STAGED_TITLE to KEY_NOTIF_STAGED_BODY
}
