package org.xsecurity.scanner.quarantine

/** Persisted state for an encrypted, best-effort soft-quarantine record. */
enum class QuarantineState { DETECTED, PENDING, QUARANTINED, RESTORED, DELETED, FAILED, CANCELLED }

enum class QuarantineActor { AUTOMATION, USER_ACTION, PLATFORM_OBSERVATION }

data class QuarantineRecord(
    val id: String,
    val packageName: String,
    val label: String,
    val sha256: String?,
    val verdict: String,
    val engine: String,
    val detectedAtMillis: Long,
    val updatedAtMillis: Long,
    val state: QuarantineState = QuarantineState.DETECTED,
    val failureCode: String? = null,
    val vaultFileName: String? = null,
    val restoreInfo: String? = null,
    val bypassUntilMillis: Long? = null,
    /** File-vault records only: is the original file still on the device? See [QuarantineHonesty]. */
    val residue: OriginalResidue? = null,
    /** Original location as seen at scan time (content:// or file:// URI string); app-private DB only. */
    val sourceUri: String? = null,
    /** Resolved absolute path of the original when known (needed for cut + move-back restore). */
    val sourcePath: String? = null,
    /** Outcome code of the most recent cut attempt (see [CutResultCodes]); null before the first tap. */
    val cutResult: String? = null
) {
    val isFileRecord: Boolean get() = packageName == QuarantineHonesty.FILE_VAULT_PACKAGE
}

sealed class QuarantineTransitionResult {
    data class Accepted(val record: QuarantineRecord) : QuarantineTransitionResult()
    data class Rejected(val code: String) : QuarantineTransitionResult()
}

/** Pure transition table; all destructive/removal states require an explicit user action. */
object QuarantineStateMachine {
    fun transition(
        record: QuarantineRecord,
        to: QuarantineState,
        nowMillis: Long,
        actor: QuarantineActor,
        failureCode: String? = null
    ): QuarantineTransitionResult {
        if (record.state == to) return QuarantineTransitionResult.Accepted(record.copy(updatedAtMillis = nowMillis))

        if (to == QuarantineState.DELETED && actor != QuarantineActor.USER_ACTION) {
            return QuarantineTransitionResult.Rejected("deleted_requires_user_action")
        }
        if (to == QuarantineState.RESTORED && actor != QuarantineActor.USER_ACTION) {
            return QuarantineTransitionResult.Rejected("restore_requires_user_action")
        }
        if (to == QuarantineState.CANCELLED && actor != QuarantineActor.USER_ACTION) {
            return QuarantineTransitionResult.Rejected("cancel_requires_user_action")
        }

        val allowed = when (record.state) {
            QuarantineState.DETECTED -> to == QuarantineState.PENDING || to == QuarantineState.FAILED
            QuarantineState.PENDING -> to == QuarantineState.QUARANTINED || to == QuarantineState.FAILED ||
                to == QuarantineState.CANCELLED || to == QuarantineState.DELETED
            QuarantineState.QUARANTINED -> to == QuarantineState.RESTORED || to == QuarantineState.DELETED
            QuarantineState.FAILED -> to == QuarantineState.PENDING || to == QuarantineState.RESTORED ||
                to == QuarantineState.DELETED
            QuarantineState.RESTORED, QuarantineState.DELETED, QuarantineState.CANCELLED -> false
        }
        if (!allowed) return QuarantineTransitionResult.Rejected("invalid_${record.state.name.lowercase()}_to_${to.name.lowercase()}")
        if (to == QuarantineState.FAILED && failureCode.isNullOrBlank()) {
            return QuarantineTransitionResult.Rejected("failed_state_requires_failure_code")
        }
        return QuarantineTransitionResult.Accepted(
            record.copy(
                state = to,
                updatedAtMillis = nowMillis,
                failureCode = if (to == QuarantineState.FAILED) failureCode else null
            )
        )
    }
}

/** A bypass is never permanent and can never exceed the fixed 24-hour maximum. */
data class QuarantineBypass(
    val packageName: String,
    val issuedAtMillis: Long,
    val expiresAtMillis: Long,
    val reasonCode: String = "user_allowed_temporarily"
) {
    val isActive: Boolean get() = isActiveAt(System.currentTimeMillis())
    fun isActiveAt(nowMillis: Long): Boolean = nowMillis < expiresAtMillis

    companion object {
        const val MAX_DURATION_MILLIS: Long = 24L * 60L * 60L * 1000L

        fun issue(packageName: String, nowMillis: Long, requestedDurationMillis: Long): QuarantineBypass? {
            if (packageName.isBlank() || requestedDurationMillis <= 0L) return null
            val duration = requestedDurationMillis.coerceAtMost(MAX_DURATION_MILLIS)
            return QuarantineBypass(
                packageName = packageName,
                issuedAtMillis = nowMillis,
                expiresAtMillis = nowMillis + duration
            )
        }
    }
}
