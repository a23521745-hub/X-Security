package org.xsecurity.scanner.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import org.xsecurity.scanner.engine.ThreatMatch
import java.io.File

/**
 * Tarama gecmisinin kayit tipi; UI filtre chipleriyle birebir eslesir.
 *  - DEVICE         : "Tumunu tara" (DeviceScanWorker)
 *  - FILE           : kullanici secilen dosyayi taramasi (ApkScanWorker)
 *  - INSTALL_SHIELD : kurulum ani kalkan taramasi (PackageScanWorker)
 *  - REALTIME       : "her zaman acik" indirme korumasinin tetikledigi tarama
 */
enum class ScanHistoryType { DEVICE, FILE, INSTALL_SHIELD, REALTIME }

/** Gecmis kaydinda saklanan tek tehdit (motor + ad + detay). */
data class ScanHistoryThreat(
    val engine: String,
    val name: String,
    val detail: String? = null
)

/** Gecmis kaydindaki işaretli uygulama (paket + etiket + tehdit adlari). */
data class ScanHistoryFlaggedApp(
    val packageName: String,
    val label: String,
    val threatNames: List<String> = emptyList()
)

/**
 * Tek bir tamamlanmis taramanin kalici ozeti.
 *
 * Alanlar bilerek "veri dolu" tutulur: dogrudan bir [org.xsecurity.scanner.engine.ScanResult]
 * ya da cihaz taramasi girdi listesinden uretilir (bkz. [threatsOf]/[counters]
 * yardimcilari). Uzun listeler kodlama asamasinda ust sinirla kessilir ki dosya
 * buyumesin ve eski cihazlarda decode hizi etkilenmesin.
 */
data class ScanHistoryEntry(
    val timestamp: Long,
    val type: ScanHistoryType,
    val trigger: String,
    val title: String,
    val status: String,
    val durationMillis: Long,
    val bytesScanned: Long,
    val appsScanned: Int = 0,
    val appsFlagged: Int = 0,
    val appsCached: Int = 0,
    val threatCount: Int = 0,
    val threats: List<ScanHistoryThreat> = emptyList(),
    val flaggedApps: List<ScanHistoryFlaggedApp> = emptyList(),
    val engineCounters: Map<String, Int> = emptyMap(),
    val warnings: List<String> = emptyList()
) {
    val isThreats: Boolean get() = status == "THREATS_FOUND"
    val isFailed: Boolean get() = status == "FAILED"
}

/**
 * Tarama gecmisi: bellek-ici StateFlow + `filesDir/scan-history.json`.
 *
 * Musteri diger store'larla ayni (StateFlow + restore/record/clear) ama kalicilik
 * dosyada: en fazla [MAX_ENTRIES] kayıt, en yenisin onunde, eski olanlar duser.
 * Yazi atomiktir (tmp + rename); bozuk dosya bos gecmis sayilir.
 *
 * Not: [org.xsecurity.scanner.data.ScanStore]'a dokunulmaz — o "son tarama"yi
 * tasiyor; bu store ise TUM tamamlanan taramalarin listesini.
 */
object ScanHistoryStore {

    const val FILE_NAME = "scan-history.json"
    const val MAX_ENTRIES = 200
    const val MAX_THREATS = 50
    const val MAX_FLAGGED_APPS = 30
    const val MAX_WARNINGS = 20

    const val TRIGGER_MANUAL = "manual"
    const val TRIGGER_FILE_PICKER = "file_picker"
    const val TRIGGER_DOWNLOAD_WATCH = "download_watch"
    const val TRIGGER_INSTALL_SHIELD = "install_shield"

    const val COUNTER_YARA_RULES = "yaraRules"
    const val COUNTER_YARA_PATTERNS = "yaraPatterns"
    const val COUNTER_CLAM_SIGNATURES = "clamSignatures"
    const val COUNTER_HASH_SIGNATURES = "hashSignatures"

    /** Coklu worker (kalkan + dosya) ayni anda kayit yazabilir; yariya kesilmez. */
    private val lock = Any()

    private val _entries = MutableStateFlow<List<ScanHistoryEntry>>(emptyList())
    val entries: StateFlow<List<ScanHistoryEntry>> = _entries.asStateFlow()

    fun file(context: Context): File = File(context.filesDir, FILE_NAME)

    fun restore(context: Context) {
        restore(File(context.filesDir, FILE_NAME))
    }

    fun restore(file: File) {
        synchronized(lock) {
            _entries.value = load(file)
        }
    }

    fun load(file: File): List<ScanHistoryEntry> {
        if (!file.isFile) return emptyList()
        val decoded = runCatching { decode(file.readText()) }.getOrDefault(emptyList())
        return decoded.take(MAX_ENTRIES)
    }

    /** En yenisin onune ekler; [MAX_ENTRIES] ustunu en eski kayitlardan keser. */
    fun record(context: Context, entry: ScanHistoryEntry) {
        record(File(context.filesDir, FILE_NAME), entry)
    }

    fun record(file: File, entry: ScanHistoryEntry) {
        synchronized(lock) {
            val current = _entries.value.toMutableList()
            current.add(0, entry)
            while (current.size > MAX_ENTRIES) {
                current.removeAt(current.size - 1)
            }
            _entries.value = current
            persist(file, current)
        }
    }

    fun clear(context: Context) {
        clear(File(context.filesDir, FILE_NAME))
    }

    fun clear(file: File) {
        synchronized(lock) {
            _entries.value = emptyList()
            runCatching { if (file.exists()) file.delete() }
        }
    }

    /** Tarama anindaki motor sayimlarini gecmis kaydina tasir. */
    fun counters(info: EngineInfo?): Map<String, Int> {
        if (info == null) return emptyMap()
        return mapOf(
            COUNTER_YARA_RULES to info.yaraRules,
            COUNTER_YARA_PATTERNS to info.yaraPatterns,
            COUNTER_CLAM_SIGNATURES to info.clamSignatures,
            COUNTER_HASH_SIGNATURES to info.hashSignatures
        )
    }

    /** [ThreatMatch] listesini gecmis kaydinin tehdit modeline cevirir (ust sinir [MAX_THREATS]). */
    fun threatsOf(threats: List<ThreatMatch>): List<ScanHistoryThreat> =
        threats.take(MAX_THREATS).map { ScanHistoryThreat(it.engine, it.name, it.detail) }

    fun encode(entries: List<ScanHistoryEntry>): String {
        val array = JSONArray()
        entries.forEach { entry ->
            val item = JSONObject()
            item.put("timestamp", entry.timestamp)
            item.put("type", entry.type.name)
            item.put("trigger", entry.trigger)
            item.put("title", entry.title)
            item.put("status", entry.status)
            item.put("duration", entry.durationMillis)
            item.put("bytes", entry.bytesScanned)
            item.put("appsScanned", entry.appsScanned)
            item.put("appsFlagged", entry.appsFlagged)
            item.put("appsCached", entry.appsCached)
            item.put("threatCount", entry.threatCount)

            val threats = JSONArray()
            entry.threats.take(MAX_THREATS).forEach { threat ->
                val t = JSONObject()
                t.put("engine", threat.engine)
                t.put("name", threat.name)
                t.put("detail", threat.detail ?: "")
                threats.put(t)
            }
            item.put("threats", threats)

            val flagged = JSONArray()
            entry.flaggedApps.take(MAX_FLAGGED_APPS).forEach { app ->
                val names = JSONArray()
                app.threatNames.forEach { names.put(it) }
                val f = JSONObject()
                f.put("package", app.packageName)
                f.put("label", app.label)
                f.put("threats", names)
                flagged.put(f)
            }
            item.put("flaggedApps", flagged)

            val counters = JSONObject()
            entry.engineCounters.forEach { (key, value) -> counters.put(key, value) }
            item.put("engineCounters", counters)

            val warnings = JSONArray()
            entry.warnings.take(MAX_WARNINGS).forEach { warnings.put(it) }
            item.put("warnings", warnings)

            array.put(item)
        }
        return array.toString()
    }

    fun decode(raw: String): List<ScanHistoryEntry> {
        val array = JSONArray(raw)
        val out = ArrayList<ScanHistoryEntry>(array.length())
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i) ?: continue
            val type = runCatching {
                ScanHistoryType.valueOf(item.optString("type", ScanHistoryType.FILE.name))
            }.getOrDefault(ScanHistoryType.FILE)

            val threats = ArrayList<ScanHistoryThreat>()
            val threatArray = item.optJSONArray("threats") ?: JSONArray()
            for (j in 0 until threatArray.length()) {
                val t = threatArray.optJSONObject(j) ?: continue
                threats += ScanHistoryThreat(
                    engine = t.optString("engine"),
                    name = t.optString("name"),
                    detail = t.optString("detail").ifEmpty { null }
                )
            }

            val flaggedApps = ArrayList<ScanHistoryFlaggedApp>()
            val flaggedArray = item.optJSONArray("flaggedApps") ?: JSONArray()
            for (j in 0 until flaggedArray.length()) {
                val f = flaggedArray.optJSONObject(j) ?: continue
                val names = ArrayList<String>()
                val nameArray = f.optJSONArray("threats") ?: JSONArray()
                for (k in 0 until nameArray.length()) names += nameArray.optString(k)
                flaggedApps += ScanHistoryFlaggedApp(
                    packageName = f.optString("package"),
                    label = f.optString("label"),
                    threatNames = names
                )
            }

            val counters = LinkedHashMap<String, Int>()
            val countersObject = item.optJSONObject("engineCounters")
            if (countersObject != null) {
                for (key in countersObject.keys()) {
                    counters[key] = countersObject.optInt(key)
                }
            }

            val warnings = ArrayList<String>()
            val warningArray = item.optJSONArray("warnings") ?: JSONArray()
            for (j in 0 until warningArray.length()) warnings += warningArray.optString(j)

            out += ScanHistoryEntry(
                timestamp = item.optLong("timestamp"),
                type = type,
                trigger = item.optString("trigger", ""),
                title = item.optString("title"),
                status = item.optString("status", "FAILED"),
                durationMillis = item.optLong("duration"),
                bytesScanned = item.optLong("bytes"),
                appsScanned = item.optInt("appsScanned"),
                appsFlagged = item.optInt("appsFlagged"),
                appsCached = item.optInt("appsCached"),
                threatCount = item.optInt("threatCount"),
                threats = threats,
                flaggedApps = flaggedApps,
                engineCounters = counters,
                warnings = warnings
            )
        }
        return out
    }

    private fun persist(file: File, entries: List<ScanHistoryEntry>) {
        try {
            val directory = file.parentFile
            if (directory != null && !directory.isDirectory) directory.mkdirs()
            val tmp = File(directory, file.name + ".tmp")
            tmp.writeText(encode(entries))
            if (!tmp.renameTo(file)) {
                if (file.exists()) file.delete()
                if (!tmp.renameTo(file)) tmp.copyTo(file, overwrite = true)
            }
        } catch (_: Exception) {
            // Kalicilama hatasi taramayi bozmaz; bellek-ici liste gecerli kalir.
        }
    }
}
