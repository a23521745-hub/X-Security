package org.xsecurity.scanner.edr

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import java.io.File

/**
 * EDR uyarilarinin zaman damgalari: dashboard kartindaki "son 24 saatte kac
 * uyari" sayaci buradan beslenir.
 *
 * Desen [org.xsecurity.scanner.data.ScanHistoryStore] ile ayni (bellek-ici
 * StateFlow + `filesDir` altinda JSON), ama tek boyutlu veri oldugu icin codec
 * sayi dizisinden ibarettir. Kayit [BehavioralEdrService.showAlert] icinden
 * tek satirla yapilir; okuma/yazma hatalari sessizce yutulur (uyari sayaci
 * hicbir zaman bildirimi ya da taramayi bozmaz).
 */
object EdrAlertStore {

    const val FILE_NAME = "edr-alerts.json"

    /** Son 24 saat penceresi (kart bu aralikta sayar). */
    const val WINDOW_MILLIS = 24L * 60L * 60L * 1000L

    /** Kalici dosya ust siniri; fazlasi en eskiden budanir. */
    const val MAX_ALERTS = 200

    private val lock = Any()

    private val _count24h = MutableStateFlow(0)
    val count24h: StateFlow<Int> = _count24h.asStateFlow()

    fun file(context: Context): File = File(context.filesDir, FILE_NAME)

    fun restore(context: Context) {
        restore(File(context.filesDir, FILE_NAME), System.currentTimeMillis())
    }

    fun restore(file: File, now: Long) {
        synchronized(lock) {
            val timestamps = prune(load(file), now - WINDOW_MILLIS)
            persistQuietly(file, timestamps)
            _count24h.value = countWithin(timestamps, now - WINDOW_MILLIS)
        }
    }

    fun record(context: Context) {
        record(File(context.filesDir, FILE_NAME), System.currentTimeMillis())
    }

    fun record(file: File, now: Long) {
        synchronized(lock) {
            val timestamps = (load(file) + now).takeLast(MAX_ALERTS)
            val pruned = prune(timestamps, now - WINDOW_MILLIS)
            persistQuietly(file, pruned)
            _count24h.value = countWithin(pruned, now - WINDOW_MILLIS)
        }
    }

    /** Saf: pencere disindaki damgalari atar (siralamayi korur). */
    fun prune(timestamps: List<Long>, cutoff: Long): List<Long> =
        timestamps.filter { it >= cutoff }.takeLast(MAX_ALERTS)

    /** Saf: pencere icindeki damga sayisi. */
    fun countWithin(timestamps: List<Long>, cutoff: Long): Int =
        timestamps.count { it >= cutoff }

    fun encode(timestamps: List<Long>): String {
        val array = JSONArray()
        timestamps.forEach { array.put(it) }
        return array.toString()
    }

    fun decode(raw: String): List<Long> {
        val array = JSONArray(raw)
        val out = ArrayList<Long>(array.length())
        for (i in 0 until array.length()) {
            out += array.optLong(i, Long.MIN_VALUE)
        }
        return out.filter { it != Long.MIN_VALUE }
    }

    private fun load(file: File): List<Long> {
        if (!file.isFile) return emptyList()
        return runCatching { decode(file.readText()) }.getOrDefault(emptyList())
    }

    private fun persistQuietly(file: File, timestamps: List<Long>) {
        try {
            val directory = file.parentFile
            if (directory != null && !directory.isDirectory) directory.mkdirs()
            val tmp = File(directory, file.name + ".tmp")
            tmp.writeText(encode(timestamps))
            if (!tmp.renameTo(file)) {
                if (file.exists()) file.delete()
                if (!tmp.renameTo(file)) tmp.copyTo(file, overwrite = true)
            }
        } catch (_: Exception) {
            // Sayac kaliciligi kritik degil; bellek-ici deger gecerli kalir.
        }
    }
}
