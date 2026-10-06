package org.xsecurity.scanner.quarantine

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.xsecurity.scanner.autopilot.AuditLog
import org.xsecurity.scanner.autopilot.AuditRecord
import org.xsecurity.scanner.autopilot.AutopilotSettings
import org.xsecurity.scanner.autopilot.SecurityEvent
import org.xsecurity.scanner.autopilot.SecuritySignal
import org.xsecurity.scanner.autopilot.SystemPackageSafelist
import java.util.UUID

/** SQLite-backed quarantine metadata plus a read-only UI StateFlow. */
object QuarantineRepository {
    private val lock = Any()
    private val _records = MutableStateFlow<List<QuarantineRecord>>(emptyList())
    val records: StateFlow<List<QuarantineRecord>> = _records.asStateFlow()

    @Volatile
    private var database: QuarantineDatabase? = null

    fun restore(context: Context) = synchronized(lock) {
        _records.value = db(context).all()
    }

    fun newRecord(
        packageName: String,
        label: String,
        sha256: String?,
        verdict: String,
        engine: String,
        nowMillis: Long = System.currentTimeMillis(),
        vaultFileName: String? = null,
        restoreInfo: String? = null
    ): QuarantineRecord = QuarantineRecord(
        id = UUID.randomUUID().toString(),
        packageName = packageName,
        label = label.ifBlank { packageName },
        sha256 = sha256,
        verdict = verdict,
        engine = engine,
        detectedAtMillis = nowMillis,
        updatedAtMillis = nowMillis,
        state = QuarantineState.DETECTED,
        vaultFileName = vaultFileName,
        restoreInfo = restoreInfo
    )

    fun insert(context: Context, record: QuarantineRecord) = synchronized(lock) {
        db(context).save(record)
        publish(context)
    }

    fun transition(
        context: Context,
        id: String,
        state: QuarantineState,
        actor: QuarantineActor,
        nowMillis: Long = System.currentTimeMillis(),
        failureCode: String? = null
    ): QuarantineTransitionResult = synchronized(lock) {
        val store = db(context)
        val current = store.find(id)
            ?: return@synchronized QuarantineTransitionResult.Rejected("record_not_found")
        when (val result = QuarantineStateMachine.transition(current, state, nowMillis, actor, failureCode)) {
            is QuarantineTransitionResult.Accepted -> {
                store.save(result.record)
                publish(context)
                result
            }
            is QuarantineTransitionResult.Rejected -> result
        }
    }

    fun updateRestoreInfo(context: Context, id: String, restoreInfo: String, nowMillis: Long = System.currentTimeMillis()) =
        synchronized(lock) {
            val store = db(context)
            val current = store.find(id) ?: return@synchronized false
            store.save(current.copy(restoreInfo = restoreInfo, updatedAtMillis = nowMillis))
            publish(context)
            true
        }

    fun record(context: Context, id: String): QuarantineRecord? = synchronized(lock) { db(context).find(id) }

    fun recordsForPackage(context: Context, packageName: String): List<QuarantineRecord> =
        synchronized(lock) { db(context).findByPackage(packageName) }

    fun activeBypass(context: Context, packageName: String, nowMillis: Long = System.currentTimeMillis()): QuarantineBypass? =
        synchronized(lock) { db(context).activeBypass(packageName, nowMillis) }

    /** User override is durable only after an audit line has been synced to disk. */
    fun addTimeboxedBypass(
        context: Context,
        packageName: String,
        requestedDurationMillis: Long = QuarantineBypass.MAX_DURATION_MILLIS,
        nowMillis: Long = System.currentTimeMillis()
    ): QuarantineBypass? = synchronized(lock) {
        if (packageName.isBlank() || SystemPackageSafelist.isSystemPackage(context, packageName)) return@synchronized null
        val bypass = QuarantineBypass.issue(packageName, nowMillis, requestedDurationMillis) ?: return@synchronized null
        val audit = AuditRecord(
            id = UUID.randomUUID().toString(),
            timestampMillis = nowMillis,
            eventType = SecurityEvent.Type.MANUAL.name,
            packageName = packageName,
            isSystemPackage = false,
            eventOccurredAtMillis = nowMillis,
            signals = listOf(
                SecuritySignal(
                    provider = SecuritySignal.ProviderId.LIFECYCLE,
                    verdict = SecuritySignal.Verdict.UNKNOWN,
                    risk = SecuritySignal.Risk.LOW,
                    reasonCode = "user_bypass_timeboxed_24h"
                )
            ),
            decisionAction = "USER_BYPASS",
            decisionReason = "temporary_allow_until_${bypass.expiresAtMillis}",
            autonomyLevel = AutopilotSettings.level(context).name
        )
        if (!AuditLog.append(context, audit)) return@synchronized null
        try {
            db(context).saveBypass(bypass)
        } catch (_: Exception) {
            return@synchronized null
        }
        bypass
    }

    private fun publish(context: Context) {
        _records.value = db(context).all()
    }

    private fun db(context: Context): QuarantineDatabase =
        database ?: synchronized(this) {
            database ?: QuarantineDatabase(context.applicationContext).also { database = it }
        }
}
