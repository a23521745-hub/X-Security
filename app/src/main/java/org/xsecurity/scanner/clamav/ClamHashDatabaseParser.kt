package org.xsecurity.scanner.clamav

import org.xsecurity.scanner.core.SignatureDatabaseException
import java.io.File

/**
 * ClamAV **hash** veritabani okuyucu (`.hdb`/`.hsb` ailesi).
 *
 * Satir formati: `hash:boyut:isim`
 *  - `hash` 32/40/64 kucuk-buyuk harf hex bayt; UZUNLUK algoritmayi belirler
 *    (32 = MD5, 40 = SHA-1, 64 = SHA-256) — tıpkı ClamAV `.hsb`'de oldugu gibi.
 *    Bu yuzden tek dosyada uc algoritma bir arada yasayabilir.
 *  - `boyut` dosyanin bayt cinsinden boyutu; eslesme icin zorunlu kosuldur.
 *    `*` ya da `-1` = boyut bilinmiyor (sayacla raporlanir; hash eslesmesi yeterlidir).
 *  - `isim` satirin kalani (iki nokta icerebilir); ClamAV isimlendirme gelenegi
 *    `Android.Stalkerware.X` gibidir.
 *
 * Neden var? ClamAV ekosistemindeki imzalarin (Hypatia'nin da beslendigi
 * main/daily `.h*b` setleri) BYUK KISMI dosya-hash'imizdir; desen (`.ndb`) degil.
 * Hash imzasi tum dosyanin ozetiyle eslesir: yanlis pozitif pratikte imkansizdir
 * ama dosyanin tek bayti bile degisse kacar — o isi desen katmani (YARA/.ndb)
 * tamamlar.
 *
 * Bilincli olarak desteklenmeyenler (sayacla raporlanir, sessiz elenmez):
 *  - PE-bolum (segment) hash dosyalari (`.mdb`/`.msb` semantigi) — APK tarayicisi
 *    icin anlamli degil; bu satirlar butun-dosya hash'i gibi OKUNMAZ.
 */
class ClamHashDatabaseParser(private val maxEntries: Int = DEFAULT_MAX_ENTRIES) {

    enum class Algorithm(val hexLength: Int, val digestName: String) {
        MD5(32, "MD5"),
        SHA_1(40, "SHA-1"),
        SHA_256(64, "SHA-256");

        companion object {
            /** Hex uzunlugundan algoritma; taninmayan uzunluk `null`. */
            fun forHexLength(length: Int): Algorithm? = values().firstOrNull { it.hexLength == length }
        }
    }

    class Signature(
        val algorithm: Algorithm,
        val hashHex: String,
        /** Beklenen dosya boyutu; `-1` = bilinmiyor (hash yeterli). */
        val sizeBytes: Long,
        val name: String
    )

    class Stats(
        val totalLines: Int = 0,
        val loaded: Int = 0,
        val malformed: Int = 0,
        val duplicates: Int = 0,
        val md5: Int = 0,
        val sha1: Int = 0,
        val sha256: Int = 0,
        val unknownSize: Int = 0,
        val problems: List<String> = emptyList()
    )

    class Database internal constructor(
        val signatures: Map<String, Signature>,
        val stats: Stats,
        val sourcePath: String?
    ) {
        val size: Int get() = signatures.size

        /** Ozet hex'i (kucuk harf) icin imza; yoksa `null`. */
        fun lookup(hashHex: String): Signature? = signatures[hashHex.lowercase()]
    }

    fun parse(hsbFile: File): Database {
        if (!hsbFile.isFile) {
            throw SignatureDatabaseException("ClamAV hash database file not found: ${hsbFile.absolutePath}")
        }
        val lines = try {
            hsbFile.readLines(Charsets.UTF_8)
        } catch (error: Exception) {
            throw SignatureDatabaseException("ClamAV hash database could not be read: ${hsbFile.absolutePath}", error)
        }
        val database = parseLines(lines)
        if (database.size == 0 && database.stats.totalLines > 0) {
            throw SignatureDatabaseException(
                "No scannable hash signatures loaded (${hsbFile.name}: ${database.stats.totalLines} lines, " +
                    "${database.stats.malformed} malformed)" +
                    if (database.stats.problems.isEmpty()) "" else " | examples: ${database.stats.problems.take(3).joinToString(" / ")}"
            )
        }
        return Database(database.signatures, database.stats, hsbFile.absolutePath)
    }

    /** Test edilebilirlik icin dosya- bagimsiz giris noktasi. */
    fun parseLines(lines: List<String>): Database {
        val signatures = LinkedHashMap<String, Signature>()
        var totalLines = 0
        var malformed = 0
        var duplicates = 0
        var md5 = 0
        var sha1 = 0
        var sha256 = 0
        var unknownSize = 0
        val problems = ArrayList<String>()

        for (raw in lines) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            totalLines++
            if (signatures.size >= maxEntries) {
                throw SignatureDatabaseException(
                    "ClamAV hash database exceeds the entry limit ($maxEntries); refusing to load more"
                )
            }

            val parts = line.split(':', limit = 3)
            if (parts.size < 3) {
                malformed++
                if (problems.size < MAX_PROBLEMS) problems += "atlandi (alan sayisi): ${line.take(80)}"
                continue
            }

            val hashHex = parts[0].trim().lowercase()
            val algorithm = Algorithm.forHexLength(hashHex.length)
            if (algorithm == null || !hashHex.all { it in '0'..'9' || it in 'a'..'f' }) {
                malformed++
                if (problems.size < MAX_PROBLEMS) problems += "atlandi (hash): ${line.take(80)}"
                continue
            }

            val sizeField = parts[1].trim()
            val size: Long
            when {
                sizeField == "*" || sizeField == "-1" || sizeField.isEmpty() -> {
                    size = -1L
                }
                else -> {
                    val parsed = sizeField.toLongOrNull()
                    if (parsed == null || parsed < 0L) {
                        malformed++
                        if (problems.size < MAX_PROBLEMS) problems += "atlandi (boyut): ${line.take(80)}"
                        continue
                    }
                    size = parsed
                }
            }

            val name = parts[2].trim()
            if (name.isEmpty()) {
                malformed++
                if (problems.size < MAX_PROBLEMS) problems += "atlandi (isim): ${line.take(80)}"
                continue
            }

            if (signatures.containsKey(hashHex)) {
                duplicates++
                continue
            }

            signatures[hashHex] = Signature(algorithm, hashHex, size, name)
            if (size < 0L) unknownSize++
            when (algorithm) {
                Algorithm.MD5 -> md5++
                Algorithm.SHA_1 -> sha1++
                Algorithm.SHA_256 -> sha256++
            }
        }

        return Database(
            signatures = signatures,
            stats = Stats(
                totalLines = totalLines,
                loaded = signatures.size,
                malformed = malformed,
                duplicates = duplicates,
                md5 = md5,
                sha1 = sha1,
                sha256 = sha256,
                unknownSize = unknownSize,
                problems = problems
            ),
            sourcePath = null
        )
    }

    companion object {
        /**
         * Bellek korumasi: 200.000 giris ~ 40-60 MB HashMap demektir; mobil icin
         * gercekci hedef ~50-100K Android-secilmis hash'tir (bkz. definitions/README.md).
         */
        const val DEFAULT_MAX_ENTRIES: Int = 200_000

        private const val MAX_PROBLEMS = 20

        /**
         * Birden fazla hash veritabanini (kuratorluk + topluluk kaynaklari) tek
         * veritabaninda birlestirir. Ayni hash iki dosyada da varsa **birincil**
         * (kuratorluk/imzali kanal) kazanir — topluluk icerigi onu gecersiz kilamaz.
         */
        fun merge(primary: Database, others: List<Database>): Database {
            if (others.isEmpty()) return primary
            val merged = LinkedHashMap<String, Signature>(primary.signatures)
            var md5 = primary.stats.md5
            var sha1 = primary.stats.sha1
            var sha256 = primary.stats.sha256
            var duplicates = primary.stats.duplicates
            val problems = ArrayList(primary.stats.problems)

            for (other in others) {
                for ((key, signature) in other.signatures) {
                    if (merged.containsKey(key)) {
                        duplicates++
                        continue
                    }
                    merged[key] = signature
                    when (signature.algorithm) {
                        Algorithm.MD5 -> md5++
                        Algorithm.SHA_1 -> sha1++
                        Algorithm.SHA_256 -> sha256++
                    }
                }
            }

            return Database(
                signatures = merged,
                stats = Stats(
                    totalLines = primary.stats.totalLines + others.sumOf { it.stats.totalLines },
                    loaded = merged.size,
                    malformed = primary.stats.malformed + others.sumOf { it.stats.malformed },
                    duplicates = duplicates,
                    md5 = md5,
                    sha1 = sha1,
                    sha256 = sha256,
                    unknownSize = primary.stats.unknownSize + others.sumOf { it.stats.unknownSize },
                    problems = problems
                ),
                sourcePath = primary.sourcePath
            )
        }
    }
}
