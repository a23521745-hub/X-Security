package org.xsecurity.scanner.autopilot

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.util.UUID

/** A content-free, append-only decision record. */
data class AuditRecord(
    val id: String,
    val timestampMillis: Long,
    val eventType: String,
    val packageName: String?,
    val isSystemPackage: Boolean,
    val eventOccurredAtMillis: Long,
    val signals: List<SecuritySignal>,
    val decisionAction: String,
    val decisionReason: String,
    val autonomyLevel: String
) {
    companion object {
        fun from(
            event: SecurityEvent,
            signals: List<SecuritySignal>,
            decision: PolicyDecision,
            autonomy: AutonomyLevel,
            timestampMillis: Long = System.currentTimeMillis()
        ): AuditRecord = AuditRecord(
            id = UUID.randomUUID().toString(),
            timestampMillis = timestampMillis,
            eventType = event.type.name,
            packageName = event.packageName,
            isSystemPackage = event.isSystemPackage,
            eventOccurredAtMillis = event.occurredAtMillis,
            signals = signals.toList(),
            decisionAction = decision.action.name,
            decisionReason = decision.reasonCode,
            autonomyLevel = autonomy.name
        )
    }
}

/**
 * Local append-only JSONL audit store. There is intentionally no clear, update,
 * or truncate operation. Arbitrary text is not accepted by [AuditRecord].
 */
object AuditLog {
    const val FILE_NAME = "autopilot-audit.jsonl"
    private val lock = Any()

    fun file(context: Context): File = File(File(context.filesDir, "autopilot"), FILE_NAME)

    /** Returns false on storage failure; callers must not execute automation without a durable audit. */
    fun append(context: Context, record: AuditRecord): Boolean = synchronized(lock) {
        val target = file(context.applicationContext)
        try {
            target.parentFile?.mkdirs()
            FileOutputStream(target, true).use { stream ->
                val line = encode(record) + "\n"
                stream.write(line.toByteArray(Charsets.UTF_8))
                stream.fd.sync()
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    /** Most recent valid records; reading never rewrites the audit file. */
    fun read(context: Context, limit: Int = 500): List<AuditRecord> {
        val target = file(context.applicationContext)
        if (!target.isFile || limit <= 0) return emptyList()
        return runCatching {
            target.useLines { lines ->
                lines.mapNotNull { line -> runCatching { decode(line) }.getOrNull() }
                    .toList()
                    .takeLast(limit)
                    .asReversed()
            }
        }.getOrDefault(emptyList())
    }

    fun encode(record: AuditRecord): String {
        val signals = JSONArray()
        record.signals.forEach { signal ->
            signals.put(
                JSONObject()
                    .put("provider", signal.provider.name)
                    .put("verdict", signal.verdict.name)
                    .put("risk", signal.risk.name)
                    .put("reason", signal.reasonCode)
            )
        }
        return JSONObject()
            .put("id", record.id)
            .put("timestamp", record.timestampMillis)
            .put("event", record.eventType)
            .put("package", record.packageName ?: JSONObject.NULL)
            .put("system", record.isSystemPackage)
            .put("occurredAt", record.eventOccurredAtMillis)
            .put("signals", signals)
            .put("decision", record.decisionAction)
            .put("reason", record.decisionReason)
            .put("autonomy", record.autonomyLevel)
            .toString()
    }

    fun decode(raw: String): AuditRecord {
        val json = JSONObject(raw)
        val signalsArray = json.optJSONArray("signals") ?: JSONArray()
        val signals = ArrayList<SecuritySignal>(signalsArray.length())
        for (index in 0 until signalsArray.length()) {
            val item = signalsArray.optJSONObject(index) ?: continue
            signals += SecuritySignal(
                provider = SecuritySignal.ProviderId.valueOf(item.getString("provider")),
                verdict = SecuritySignal.Verdict.valueOf(item.getString("verdict")),
                risk = SecuritySignal.Risk.valueOf(item.getString("risk")),
                reasonCode = item.getString("reason")
            )
        }
        return AuditRecord(
            id = json.getString("id"),
            timestampMillis = json.getLong("timestamp"),
            eventType = json.getString("event"),
            packageName = if (json.isNull("package")) null else json.getString("package"),
            isSystemPackage = json.optBoolean("system"),
            eventOccurredAtMillis = json.optLong("occurredAt"),
            signals = signals,
            decisionAction = json.getString("decision"),
            decisionReason = json.getString("reason"),
            autonomyLevel = json.getString("autonomy")
        )
    }
}
