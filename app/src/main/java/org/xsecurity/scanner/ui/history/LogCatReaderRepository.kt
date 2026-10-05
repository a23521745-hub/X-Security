package org.xsecurity.scanner.ui.history

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * "Gelişmiş (Canlı LogCat)" sekmesinin tek log satırı.
 *
 * @param timestamp `logcat -v time` damgası ("10-05 12:34:56.789"), yoksa "".
 * @param level V/D/I/W/E (bilinmiyorsa '?').
 */
data class LogEntry(
    val timestamp: String,
    val level: Char,
    val tag: String,
    val pid: Int?,
    val tid: Int?,
    val message: String,
    val raw: String
)

/**
 * `logcat -v time` satır çözümleyicisi (**saf**, android.jar gerektirmez).
 *
 * Gerçek biçim (threadtime ile aynı satır yapısı):
 * `10-05 12:34:56.789 1234 5678 I TAG: ileti`
 * Bazı cihazlar TID yazmaz; kısa (brief) biçime ve ham-satır geri dönüşüne de
 * dayanıklıdır — amaç eşleşen satırı kaçırmamak, biçim katılığı değil.
 */
object LogCatParser {

    /** Şartnamedeki izlenen uygulama etiketleri. */
    val WATCHED_TAGS: Set<String> = setOf(
        "XSecurityEngine",
        "XSecurityEDR",
        "ClamAvScanner",
        "YaraScanner",
        "OtaVerifier"
    )

    // "MM-DD HH:MM:SS.mmm [PID [TID]] SEVİYE TAG[(PID)]: ileti"
    private val TIME_LINE = Regex(
        """^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(?:(\d+)\s+(?:(\d+)\s+)?)?([VDIWEFU])\s+(\S+?)(?:\(\s*(\d+)\))?:\s?(.*)$"""
    )

    // Kısa biçim geri dönüşü: "I/TAG(PID): ileti"
    private val BRIEF_LINE = Regex("""^([VDIWEFU])/(\S+?)\(\s*(\d+)\):\s?(.*)$""")

    fun isWatched(tag: String?): Boolean = tag != null && WATCHED_TAGS.contains(tag)

    fun parseLine(line: String?): LogEntry? {
        if (line.isNullOrEmpty()) return null
        TIME_LINE.matchEntire(line)?.let { match ->
            val timestamp = match.groupValues[1]
            val pid = match.groupValues[2].toIntOrNull()
            val tid = match.groupValues[3].toIntOrNull()
            val level = match.groupValues[4].firstOrNull() ?: '?'
            val tag = match.groupValues[5]
            val message = match.groupValues[7]
            return LogEntry(timestamp, level, tag, pid, tid, message, line)
        }
        BRIEF_LINE.matchEntire(line)?.let { match ->
            val level = match.groupValues[1].firstOrNull() ?: '?'
            val tag = match.groupValues[2]
            val pid = match.groupValues[3].toIntOrNull()
            return LogEntry("", level, tag, pid, null, match.groupValues[4], line)
        }
        // Biçim tanınmadıysa bile izlenen etiket geçiyorsa satırı kurtar.
        val hit = WATCHED_TAGS.firstOrNull { line.contains(it) } ?: return null
        return LogEntry("", '?', hit, null, null, line, line)
    }
}

/**
 * Arka plan logcat okuyucu: `logcat -v time *:V` sürecini çalıştırıp izlenen
 * etiketleri [entries] akışına (`StateFlow<List<LogEntry>>`) aktarır.
 *
 * Yaşam döngüsü notu: projede ViewModel altyapısı yoktur ve derleme
 * yapılandırmasına dokunulmamasına karar verilmiştir; bu yüzden
 * `ViewModel.onCleared` eşdeğeri [LogCatViewer] içindeki `DisposableEffect`
 * ile sağlanır — kompozisyon bitince [stop] çağrılır, `Process.destroy()`
 * garantilenir (sızıntı yok). Duraklatma da süreci öldürür (pil dostu);
 * sürdürme yeni süreç başlatır.
 *
 * Güvenlik notu: `READ_LOGS` olmadan logcat yalnızca kendi sürecimizin
 * satırlarını verir; izlenen etiketlerin tamamı kendi sürecimizden geldiği
 * için ek izin gerekmez ve başka uygulamanın logu görünmez.
 *
 * @param scope okuma korutininin sahibi (UI: `rememberCoroutineScope()`).
 */
class LogCatReaderRepository(private val scope: CoroutineScope) {

    private val lock = Any()
    private var job: Job? = null
    private var process: Process? = null

    private val _entries = MutableStateFlow<List<LogEntry>>(emptyList())
    val entries: StateFlow<List<LogEntry>> = _entries.asStateFlow()

    private val _running = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _running.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    /** Okumayı başlat (çalışıyorsa no-op). */
    fun start() {
        synchronized(lock) {
            if (job?.isActive == true) return
            _error.value = null
            job = scope.launch(Dispatchers.IO) { runReader() }
            _running.value = true
        }
    }

    /**
     * Okumayı durdurup logcat sürecini öldürür ([Process.destroy]). Her
     * durumda güvenlidir; birden çok kez çağrılabilir.
     */
    fun stop() {
        val currentJob: Job?
        val currentProcess: Process?
        synchronized(lock) {
            currentJob = job
            currentProcess = process
            job = null
            process = null
            _running.value = false
        }
        runCatching { currentJob?.cancel() }
        runCatching { currentProcess?.destroy() }
    }

    /** Ekrandaki listeyi temizler (süreç çalışmaya devam eder). */
    fun clear() {
        _entries.value = emptyList()
    }

    private suspend fun runReader() {
        // Şartnamedeki komutun dizi biçimi (kabuk ayrıştırmasız, eşdeğer):
        // "logcat -v time *:V".
        val proc = try {
            Runtime.getRuntime().exec(arrayOf("logcat", "-v", "time", "*:V"))
        } catch (error: Exception) {
            _error.value = error.message ?: error.toString()
            synchronized(lock) {
                job = null
                _running.value = false
            }
            return
        }
        synchronized(lock) {
            // stop() araya girdiyse süreci hemen öldür.
            if (job?.isActive != true) {
                runCatching { proc.destroy() }
                return
            }
            process = proc
        }
        try {
            proc.inputStream.bufferedReader().use { reader ->
                while (scope.coroutineContext.isActive) {
                    val line = try {
                        reader.readLine()
                    } catch (_: Exception) {
                        null
                    } ?: break
                    val entry = LogCatParser.parseLine(line) ?: continue
                    if (!LogCatParser.isWatched(entry.tag)) continue
                    _entries.update { current -> (current + entry).takeLast(MAX_ENTRIES) }
                }
            }
        } finally {
            runCatching { proc.destroy() }
            synchronized(lock) {
                if (process === proc) process = null
                _running.value = false
            }
        }
    }

    companion object {
        /** Bellek üst sınırı: kayan pencere (eski satırlar düşer). */
        const val MAX_ENTRIES = 1000
    }
}
