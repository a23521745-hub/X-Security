package org.xsecurity.scanner.device

/**
 * Download/ klasoru izleyicisinin **saf** karar mantigi (FileObserver ince kalir).
 *
 *  - Yalnizca `.apk` (ve `.apks`/`.xapk` paketleri) ilgilendirir; tarayicilarin gecici
 *    adlari (`.crdownload`, `.part`, `.tmp`, `.download`) ve gizli dosyalar atlanir.
 *  - Yalnizca **yazma kapandiginda** (`CLOSE_WRITE`) ya da gecici addan nihai ada
 *    **tasindiginda** (`MOVED_TO`) taranir; yarim dosya asla taranmaz.
 *  - Ayni dosya (yol + boyut + mtime) kisa surede iki kez gelirse tek tarama yapilir.
 */
object DownloadWatchPolicy {

    /** `android.os.FileObserver` mask sabitleri (android.jar'a bagimli olmadan test icin). */
    const val EVENT_CLOSE_WRITE = 0x00000008
    const val EVENT_MOVED_TO = 0x00000080

    /**
     * Izleyicinin abone oldugu olay seti (0x88). NOT: `RealtimeProtectionService` maskeyi
     * cagri yerinde acikca `FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO` olarak kurar
     * (lint'in WrongConstant kontrolu baska siniftan sabit zinciri kabul etmiyor); buradaki
     * degerler SDK sabitleriyle birebir ayni tutulmalidir.
     */
    const val WATCH_MASK = EVENT_CLOSE_WRITE or EVENT_MOVED_TO

    private val APK_SUFFIXES = listOf(".apk", ".apks", ".xapk")
    private val TEMP_SUFFIXES = listOf(".crdownload", ".part", ".tmp", ".download", ".partial")

    /** Dosya adi tarama adayi mi? */
    fun isCandidateName(name: String?): Boolean {
        if (name.isNullOrBlank()) return false
        val trimmed = name.substringAfterLast('/')
        if (trimmed.startsWith(".")) return false
        val lower = trimmed.lowercase()
        if (TEMP_SUFFIXES.any { lower.endsWith(it) }) return false
        return APK_SUFFIXES.any { lower.endsWith(it) }
    }

    /** Olay + ad birlikte tarama gerektiriyor mu? */
    fun shouldScan(event: Int, name: String?): Boolean {
        val relevant = (event and EVENT_CLOSE_WRITE) != 0 || (event and EVENT_MOVED_TO) != 0
        return relevant && isCandidateName(name)
    }

    /** Kisa sureli tekrar engelleyici (ayni dosya, ayni boyut+mtime). */
    class Deduplicator(private val windowMillis: Long = 30_000L) {
        private val seen = LinkedHashMap<String, Long>()

        @Synchronized
        fun accept(path: String, size: Long, modifiedAt: Long, now: Long): Boolean {
            val iterator = seen.entries.iterator()
            while (iterator.hasNext()) {
                if (now - iterator.next().value > windowMillis) iterator.remove() else break
            }
            val key = "$path|$size|$modifiedAt"
            if (seen.containsKey(key)) return false
            seen[key] = now
            return true
        }
    }
}
