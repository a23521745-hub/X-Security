package org.xsecurity.scanner.engine

import java.io.File
import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * APK/ZIP **icerik** tarayicisi.
 *
 * Neden var? Gercek bir APK'da `classes.dex`, `AndroidManifest.xml` ve `resources.arsc`
 * neredeyse her zaman **DEFLATE ile sikistirilmis** olarak durur. Yalnizca dosyanin ham
 * baytlarini tarayan bir motor, dex icindeki `com/metasploit/...` gibi dizgi kanitlarini
 * hic goremeyecekti ("temiz" sanilan msfvenom ciktilarinin sebebi buydu). Bu sinif,
 * imza eslestirmeyi ZIP girdilerinin **acilmis (decompress edilmis) icerigine** tasir.
 *
 * Guvenlik/ kaynak duruslari:
 *  - Girdiler acilirken toplam butce ([MAX_TOTAL_ENTRY_BYTES]) ve girdi basina ust sinir
 *    ([MAX_ENTRY_BYTES]) uygulanir; zip-bomb karsisinda butce asilirsa kalan girdiler
 *    atlanir ve bu **uyari olarak raporlanir** (sessiz eksik tarama yok).
 *  - Girdiler oncelik sirasina gore taranir (dex/manifest once) ki butce erken kesilse
 *    bile en degerli kanitlar once okunsun.
 *  - Hatali/bozuk ZIP durumunda istisna firlatilmaz: ham-bayt turu korunur ve sorun
 *    uyari listesine yazilir.
 *  - `ZipFile` yalnizca [withEntries] blogu icinde aciktir; girdi akislari blogun sonunda
 *    kapanir.
 */
object ApkContentScanner {

    /**
     * Taranabilir tek bir ZIP girdisi. [open] her cagrildiginda bagimsiz bir acilmis akis
     * uretir (yeni inflater); akisin omru cagiranin `use` bloguna aittir.
     */
    class EntrySource(val name: String, val declaredSize: Long, val open: () -> InputStream)

    /** Planlama/atlama bilgisi; motor bunu rapor uyarisina cevirir. */
    class Notes(
        val entries: Int,
        val plannedBytes: Long,
        val problems: List<String>
    )

    /** Tum ZIP girdilerinin acilmis toplami icin butce (64 MiB). */
    const val MAX_TOTAL_ENTRY_BYTES: Long = 64L * 1024L * 1024L

    /** Tek bir girdinin acilmis boyutu icin ust sinir (32 MiB). */
    const val MAX_ENTRY_BYTES: Long = 32L * 1024L * 1024L

    /** Taranacak en fazla girdi sayisi. */
    const val MAX_ENTRIES: Int = 384

    /** Dosya bir ZIP kabi mi? (PK\x03\x04 yerel dosya basligi.) */
    fun looksLikeZip(file: File): Boolean = try {
        file.inputStream().buffered().use { stream ->
            val header = ByteArray(4)
            var offset = 0
            while (offset < 4) {
                val read = stream.read(header, offset, 4 - offset)
                if (read < 0) break
                offset += read
            }
            offset == 4 &&
                header[0] == 0x50.toByte() && header[1] == 0x4B.toByte() &&
                header[2] == 0x03.toByte() && header[3] == 0x04.toByte()
        }
    } catch (_: Throwable) {
        false
    }

    /**
     * ZIP girdilerini acilmis akislar olarak [block]'a sunar. Dosya ZIP degilse veya
     * acilamiyorsa block **bos liste ile** cagrilir (ham-bayt turu her zaman korunur).
     *
     * Not: `InputStream.readNBytes` bilincli olarak kullanilmiyor; o yontem eski
     * Android API duzeylerinde (33 oncesi) yok.
     */
    fun <T> withEntries(
        file: File,
        budget: Long = MAX_TOTAL_ENTRY_BYTES,
        maxEntryBytes: Long = MAX_ENTRY_BYTES,
        maxEntries: Int = MAX_ENTRIES,
        block: (List<EntrySource>, Notes) -> T
    ): T {
        if (!looksLikeZip(file)) return block(emptyList(), Notes(0, 0L, emptyList()))

        val zip = try {
            ZipFile(file)
        } catch (error: Throwable) {
            return block(
                emptyList(),
                Notes(
                    0,
                    0L,
                    listOf(
                        "APK content could not be opened (invalid ZIP); only raw bytes were scanned" +
                            " (${error.message ?: error.javaClass.simpleName})."
                    )
                )
            )
        }

        try {
            val all = zip.entries().toList().filter { !it.isDirectory }
            val ordered = all.sortedWith(compareBy { entry: ZipEntry -> priorityRank(entry.name) })

            val chosen = ArrayList<EntrySource>(minOf(ordered.size, maxEntries))
            val problems = ArrayList<String>()
            var planned = 0L
            var skippedLarge = 0
            var skippedBudget = 0
            var skippedCount = 0

            for (entry in ordered) {
                if (chosen.size >= maxEntries) {
                    skippedCount++
                    continue
                }
                val size = entry.size // -1 = bildirilmemis
                if (size > maxEntryBytes) {
                    skippedLarge++
                    continue
                }
                if (size > 0L && planned + size > budget) {
                    skippedBudget++
                    continue
                }
                chosen += EntrySource(entry.name, size) { zip.getInputStream(entry).buffered() }
                if (size > 0L) planned += size
            }

            if (skippedLarge > 0) {
                problems += "ZIP content scan skipped $skippedLarge entry(ies) above the per-entry limit " +
                    "(${maxEntryBytes / (1024L * 1024L)} MiB)."
            }
            if (skippedBudget > 0) {
                problems += "ZIP content scan skipped $skippedBudget entry(ies) above the total content budget " +
                    "(${budget / (1024L * 1024L)} MiB); APK content was scanned partially."
            }
            if (skippedCount > 0) {
                problems += "ZIP content scan skipped $skippedCount entry(ies) above the entry-count limit ($maxEntries)."
            }

            return block(chosen, Notes(chosen.size, planned, problems))
        } finally {
            runCatching { zip.close() }
        }
    }

    /** En degerli girdiler (dex, manifest, varliklar) once taranir. */
    private val PRIORITY_PREFIXES = arrayOf(
        "classes",
        "AndroidManifest.xml",
        "assets/",
        "META-INF/",
        "lib/",
        "res/raw/"
    )

    private fun priorityRank(name: String): Int {
        val index = PRIORITY_PREFIXES.indexOfFirst { name.startsWith(it) }
        return if (index < 0) PRIORITY_PREFIXES.size else index
    }
}
