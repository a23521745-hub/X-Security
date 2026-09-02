package org.xsecurity.scanner.device

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import org.xsecurity.scanner.engine.ScanStatus
import org.xsecurity.scanner.engine.ThreatMatch

enum class DeviceScanPhase { IDLE, RUNNING, DONE, FAILED }

data class DeviceScanState(
    val phase: DeviceScanPhase = DeviceScanPhase.IDLE,
    val total: Int = 0,
    val scanned: Int = 0,
    val currentLabel: String? = null,
    val entries: List<AppScanEntry> = emptyList(),
    val finishedAt: Long = 0L,
    val message: String? = null,
    /** Kullanici "uygulama listesini neden okuyoruz" aciklamasini bir kez onayladi. */
    val rationaleAccepted: Boolean = false
) {
    val isRunning: Boolean get() = phase == DeviceScanPhase.RUNNING
    val progress: Float get() = if (total <= 0) 0f else (scanned.toFloat() / total.toFloat()).coerceIn(0f, 1f)
    val infected: List<AppScanEntry> get() = entries.filter { it.isInfected }
    val failed: List<AppScanEntry> get() = entries.filter { it.isFailed }
}

/**
 * Kurulu uygulama taramasinin durumu: bellek-ici StateFlow + son sonuc listesi
 * SharedPreferences'ta JSON. Ozet (tek [org.xsecurity.scanner.engine.ScanResult])
 * ayrica mevcut [org.xsecurity.scanner.data.ScanStore]'a islenir; bu nesne yalnizca
 * uygulama-basina ayrintiyi tasir.
 */
object DeviceScanStore {

    private const val PREFS = "xsec_device_scan"
    private const val KEY_ENTRIES_JSON = "entries_json"
    private const val KEY_FINISHED_AT = "finished_at"
    private const val KEY_RATIONALE = "rationale_accepted"
    private const val MAX_PERSISTED = 400

    private val _state = MutableStateFlow(DeviceScanState())
    val state: StateFlow<DeviceScanState> = _state.asStateFlow()

    fun restore(context: Context) {
        if (_state.value.isRunning) return
        val prefs = prefs(context)
        val entries = prefs.getString(KEY_ENTRIES_JSON, null)
            ?.let { runCatching { decodeEntries(it) }.getOrNull() }
            .orEmpty()
        val finishedAt = prefs.getLong(KEY_FINISHED_AT, 0L)
        _state.value = _state.value.copy(
            phase = if (entries.isEmpty() && finishedAt == 0L) DeviceScanPhase.IDLE else DeviceScanPhase.DONE,
            entries = entries,
            finishedAt = finishedAt,
            total = entries.size,
            scanned = entries.size,
            rationaleAccepted = prefs.getBoolean(KEY_RATIONALE, false)
        )
    }

    fun acceptRationale(context: Context) {
        prefs(context).edit { putBoolean(KEY_RATIONALE, true) }
        _state.value = _state.value.copy(rationaleAccepted = true)
    }

    fun markStarted(total: Int) {
        _state.value = DeviceScanState(
            phase = DeviceScanPhase.RUNNING,
            total = total,
            rationaleAccepted = _state.value.rationaleAccepted
        )
    }

    fun markProgress(scanned: Int, currentLabel: String?, entries: List<AppScanEntry>) {
        val current = _state.value
        if (!current.isRunning) return
        _state.value = current.copy(scanned = scanned, currentLabel = currentLabel, entries = entries)
    }

    fun publish(context: Context, entries: List<AppScanEntry>, message: String? = null) {
        val finishedAt = System.currentTimeMillis()
        prefs(context).edit {
            putString(KEY_ENTRIES_JSON, encodeEntries(entries.take(MAX_PERSISTED)))
            putLong(KEY_FINISHED_AT, finishedAt)
        }
        _state.value = DeviceScanState(
            phase = DeviceScanPhase.DONE,
            total = entries.size,
            scanned = entries.size,
            entries = entries,
            finishedAt = finishedAt,
            message = message,
            rationaleAccepted = _state.value.rationaleAccepted
        )
    }

    fun markFailed(message: String) {
        _state.value = _state.value.copy(phase = DeviceScanPhase.FAILED, currentLabel = null, message = message)
    }

    /** Iptal: liste korunur, calisiyor gorunumu kaldirilir. */
    fun reset() {
        val current = _state.value
        _state.value = current.copy(
            phase = if (current.entries.isEmpty()) DeviceScanPhase.IDLE else DeviceScanPhase.DONE,
            currentLabel = null,
            message = null
        )
    }

    /** Kaldirma sonrasi listeden dus (kullanici sistem ekranindan geri dondugunde). */
    fun removePackage(context: Context, packageName: String) {
        val current = _state.value
        val remaining = current.entries.filterNot { it.packageName == packageName }
        if (remaining.size == current.entries.size) return
        prefs(context).edit { putString(KEY_ENTRIES_JSON, encodeEntries(remaining.take(MAX_PERSISTED))) }
        _state.value = current.copy(entries = remaining, total = remaining.size, scanned = minOf(current.scanned, remaining.size))
    }

    fun encodeEntries(entries: List<AppScanEntry>): String {
        val array = JSONArray()
        entries.forEach { entry ->
            val item = JSONObject()
            item.put("package", entry.packageName)
            item.put("label", entry.label)
            item.put("status", entry.status.name)
            item.put("sha256", entry.sha256 ?: "")
            item.put("error", entry.errorMessage ?: "")
            item.put("version", entry.versionName ?: "")
            val threats = JSONArray()
            entry.threats.forEach { threat ->
                val t = JSONObject()
                t.put("engine", threat.engine)
                t.put("name", threat.name)
                t.put("detail", threat.detail ?: "")
                threats.put(t)
            }
            item.put("threats", threats)
            array.put(item)
        }
        return array.toString()
    }

    fun decodeEntries(raw: String): List<AppScanEntry> {
        val array = JSONArray(raw)
        val out = ArrayList<AppScanEntry>(array.length())
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i) ?: continue
            val threatArray = item.optJSONArray("threats") ?: JSONArray()
            val threats = ArrayList<ThreatMatch>(threatArray.length())
            for (j in 0 until threatArray.length()) {
                val t = threatArray.optJSONObject(j) ?: continue
                threats += ThreatMatch(
                    engine = t.optString("engine"),
                    name = t.optString("name"),
                    detail = t.optString("detail").ifEmpty { null }
                )
            }
            val status = runCatching { ScanStatus.valueOf(item.optString("status", ScanStatus.FAILED.name)) }
                .getOrDefault(ScanStatus.FAILED)
            out += AppScanEntry(
                packageName = item.optString("package"),
                label = item.optString("label"),
                status = status,
                threats = threats,
                sha256 = item.optString("sha256").ifEmpty { null },
                errorMessage = item.optString("error").ifEmpty { null },
                versionName = item.optString("version").ifEmpty { null }
            )
        }
        return out
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
