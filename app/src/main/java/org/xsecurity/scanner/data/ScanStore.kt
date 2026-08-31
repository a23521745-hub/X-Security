package org.xsecurity.scanner.data

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.engine.ScanStatus
import org.xsecurity.scanner.engine.ThreatMatch

enum class ScanPhase { IDLE, QUEUED, SCANNING, DONE, FAILED }

data class EngineInfo(
    val yaraRules: Int,
    val yaraPatterns: Int,
    val clamSignatures: Int,
    val hashSignatures: Int = 0,
    val yaraSource: String?,
    val clamSource: String?,
    val hashSource: String? = null,
    val warnings: List<String>
) {
    val isReady: Boolean get() = yaraPatterns > 0 || clamSignatures > 0 || hashSignatures > 0

    companion object {
        fun from(
            engine: org.xsecurity.scanner.engine.ApkScannerEngine,
            yaraPath: String?,
            clamPath: String?,
            hashPath: String? = null,
            extraWarnings: List<String> = emptyList()
        ): EngineInfo = EngineInfo(
            yaraRules = engine.yaraStats.ruleCount,
            yaraPatterns = engine.yaraPatternCount,
            clamSignatures = engine.clamAvSignatureCount,
            hashSignatures = engine.hashSignatureCount,
            yaraSource = yaraPath,
            clamSource = clamPath,
            hashSource = hashPath,
            warnings = engine.warnings + extraWarnings
        )
    }
}

data class ScanUiState(
    val phase: ScanPhase = ScanPhase.IDLE,
    val progress: Float = 0f,
    val lastResult: ScanResult? = null,
    val engine: EngineInfo? = null,
    val message: String? = null,
    val finishedAt: Long = 0L,
    val scannedFiles: Int = 0
)

/**
 * Sonucun saklandigi + arayuzun beslendigi tek nokta.
 *
 * Onceki surumde `ApkScanWorker` sonucu yalnizca `outputData`'ya yaziyordu; onu okuyan
 * hicbir bilesen yoktu (UI da sabit "temiz" metinleri gosteriyordu). Sonuc artik
 * bellek-ici StateFlow + SharedPreferences'ta JSON olarak tutuluyor; boylece
 * tarama bittiginde arayuz gercek veriyi gosteriyor ve uygulama yeniden baslatildiginda
 * son sonuc korunuyor.
 */
object ScanStore {

    private const val PREFS = "xsec_results"
    private const val KEY_LAST_JSON = "last_result_json"
    private const val KEY_FINISHED_AT = "finished_at"
    private const val KEY_SCANNED_FILES = "scanned_files"

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    fun markQueued(context: Context, message: String? = null) {
        ensureRestored(context)
        _state.value = _state.value.copy(phase = ScanPhase.QUEUED, progress = 0f, message = message)
    }

    fun markScanning(context: Context) {
        ensureRestored(context)
        _state.value = _state.value.copy(phase = ScanPhase.SCANNING, progress = 0f, message = null)
    }

    fun setProgress(fraction: Float) {
        val current = _state.value
        if (current.phase != ScanPhase.SCANNING && current.phase != ScanPhase.QUEUED) return
        val clamped = fraction.coerceIn(0f, 1f)
        if (kotlin.math.abs(clamped - current.progress) < 0.01f && clamped < 1f) return
        _state.value = current.copy(phase = ScanPhase.SCANNING, progress = clamped)
    }

    fun markFailed(context: Context, message: String) {
        ensureRestored(context)
        _state.value = _state.value.copy(phase = ScanPhase.FAILED, progress = 0f, message = message)
    }

    fun publishEngine(info: EngineInfo?) {
        _state.value = _state.value.copy(engine = info)
    }

    /** Motor basariyla yuklendi: onceki hata gorunumunu temizle. */
    fun markEngineReady() {
        val current = _state.value
        _state.value = current.copy(
            phase = if (current.phase == ScanPhase.FAILED) ScanPhase.IDLE else current.phase,
            message = null
        )
    }

    /** Secim iptali gibi durumlarda gecici mesaji kaldir. */
    fun clearMessage() {
        _state.value = _state.value.copy(message = null)
    }

    /** Iptal durumunda akisi IDLE'a cevirir; persist edilen son sonuc korunur. */
    fun reset() {
        _state.value = _state.value.copy(phase = ScanPhase.IDLE, progress = 0f, message = null)
    }

    fun publishResult(context: Context, result: ScanResult) {
        val prefs = prefs(context)
        val total = prefs.getInt(KEY_SCANNED_FILES, 0) + 1
        val finishedAt = System.currentTimeMillis()
        prefs.edit {
            putString(KEY_LAST_JSON, encode(result))
            putLong(KEY_FINISHED_AT, finishedAt)
            putInt(KEY_SCANNED_FILES, total)
        }
        _state.value = ScanUiState(
            phase = if (result.isComplete) ScanPhase.DONE else ScanPhase.FAILED,
            progress = 1f,
            lastResult = result,
            engine = _state.value.engine,
            message = result.errorMessage,
            finishedAt = finishedAt,
            scannedFiles = total
        )
    }

    private var restored = false

    private fun ensureRestored(context: Context) {
        if (restored) return
        restored = true
        restore(context)
    }

    fun restore(context: Context) {
        val prefs = prefs(context)
        val json = prefs.getString(KEY_LAST_JSON, null)
        val decoded = json?.let { runCatching { decode(it) }.getOrNull() }
        _state.value = _state.value.copy(
            lastResult = decoded ?: _state.value.lastResult,
            finishedAt = prefs.getLong(KEY_FINISHED_AT, 0L),
            scannedFiles = prefs.getInt(KEY_SCANNED_FILES, 0)
        )
    }

    fun encode(result: ScanResult): String {
        val root = JSONObject()
        root.put("status", result.status.name)
        root.put("filePath", result.filePath)
        root.put("fileName", result.fileName)
        root.put("fileSize", result.fileSize)
        root.put("sha256", result.sha256 ?: "")
        root.put("bytesScanned", result.bytesScanned)
        root.put("durationMillis", result.durationMillis)
        root.put("errorMessage", result.errorMessage ?: "")
        val warnings = JSONArray()
        result.engineWarnings.forEach { warnings.put(it) }
        root.put("warnings", warnings)
        val threats = JSONArray()
        result.threats.forEach { threat ->
            val item = JSONObject()
            item.put("engine", threat.engine)
            item.put("name", threat.name)
            item.put("detail", threat.detail ?: "")
            item.put("position", threat.position ?: -1L)
            threats.put(item)
        }
        root.put("threats", threats)
        return root.toString()
    }

    fun decode(raw: String): ScanResult? {
        val root = JSONObject(raw)
        val status = runCatching { ScanStatus.valueOf(root.optString("status", ScanStatus.FAILED.name)) }
            .getOrDefault(ScanStatus.FAILED)
        val warningsArray = root.optJSONArray("warnings") ?: JSONArray()
        val warnings = ArrayList<String>(warningsArray.length())
        for (i in 0 until warningsArray.length()) warnings += warningsArray.optString(i)
        val threatArray = root.optJSONArray("threats") ?: JSONArray()
        val threats = ArrayList<ThreatMatch>(threatArray.length())
        for (i in 0 until threatArray.length()) {
            val item = threatArray.optJSONObject(i) ?: continue
            threats += ThreatMatch(
                engine = item.optString("engine"),
                name = item.optString("name"),
                detail = item.optString("detail").ifEmpty { null },
                position = item.optLong("position", -1L).takeIf { it >= 0L }
            )
        }
        return ScanResult(
            status = status,
            filePath = root.optString("filePath"),
            fileName = root.optString("fileName"),
            fileSize = root.optLong("fileSize"),
            sha256 = root.optString("sha256").ifEmpty { null },
            threats = threats,
            bytesScanned = root.optLong("bytesScanned"),
            durationMillis = root.optLong("durationMillis"),
            engineWarnings = warnings,
            errorMessage = root.optString("errorMessage").ifEmpty { null }
        )
    }

    private fun prefs(context: Context): android.content.SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
