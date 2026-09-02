package org.xsecurity.scanner.definitions

import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.ota.ApkDownloader
import org.xsecurity.scanner.ota.UrlPolicy
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Tek bir tanim dosyasini (rules.yar / signatures.ndb) indirir.
 *
 * [org.xsecurity.scanner.ota.ApkDownloader] kadar kapsamli degildir ve olmasina da
 * gerek yok: tanim dosyalari kucuktur (bkz. [DefinitionsConfig.MAX_FILE_BYTES]),
 * bu yuzden resume yerine "ya tamamen iner ya da bastan denenir" politikasi yeterli.
 *
 * Guvenlik:
 *  - yonlendirmeler dahil her adres [UrlPolicy] izin listesinden gecer,
 *  - `Content-Length` ve gerceklesen bayt sayisi beklenen boyutla karsilastirilir,
 *  - SHA-256 manifestteki degerle eslesmeyen dosya **kurulmadan silinir}.
 */
class DefinitionsDownloader(private val config: DefinitionsConfig) {

    sealed class Result {
        data class Success(val file: File, val sha256: String, val bytes: Long) : Result()
        data class Failure(val message: String) : Result()
    }

    /**
     * @param target indirilen dosyanin yerlesecegi kesin hedef (".download" gecici
     *   dosyasi uzerinden atomik olarak yerlesir).
     */
    fun download(
        url: String,
        expectedSha256: String,
        expectedSize: Long,
        target: File,
        onProgress: (Float) -> Unit = {}
    ): Result {
        var current = url.trim()
        var temp: File? = null
        try {
            repeat(ApkDownloader.MAX_REDIRECTS + 1) {
                val policy = UrlPolicy.check(current, config.allowedHosts)
                if (!policy.allowed) {
                    return Result.Failure(policy.reason ?: "adrese izin yok: $current")
                }

                val connection = try {
                    URL(current).openConnection() as? HttpURLConnection
                } catch (_: Throwable) {
                    null
                } ?: return Result.Failure("baglanti kurulamadi: $current")

                try {
                    connection.instanceFollowRedirects = false
                    connection.connectTimeout = ApkDownloader.DEFAULT_CONNECT_TIMEOUT_MS
                    connection.readTimeout = ApkDownloader.DEFAULT_READ_TIMEOUT_MS
                    connection.requestMethod = "GET"

                    val code = try {
                        connection.responseCode
                    } catch (error: Throwable) {
                        return Result.Failure("ag hatasi: ${error.message ?: "yanit yok"}")
                    }

                    if (code in 300..399) {
                        val location = connection.getHeaderField("Location")
                        runCatching { connection.disconnect() }
                        if (location.isNullOrBlank()) {
                            return Result.Failure("yonlendirme hedefi eksik")
                        }
                        current = location
                        return@repeat
                    }
                    if (code != HttpURLConnection.HTTP_OK) {
                        return Result.Failure("HTTP $code")
                    }

                    if (connection.contentLengthLong > expectedSize) {
                        return Result.Failure("dosya beklenen boyuttan buyuk: $current")
                    }

                    val staged = File(target.parentFile, target.name + ".part")
                    temp = staged
                    if (staged.isFile) staged.delete()
                    var total = 0L
                    connection.inputStream.use { input ->
                        staged.outputStream().use { output ->
                            val buffer = ByteArray(64 * 1024)
                            while (true) {
                                val read = input.read(buffer)
                                if (read < 0) break
                                total += read
                                if (total > expectedSize) {
                                    return Result.Failure("dosya beklenen boyutu asti: $current")
                                }
                                output.write(buffer, 0, read)
                                if (expectedSize > 0L) {
                                    onProgress((total.toFloat() / expectedSize.toFloat()).coerceIn(0f, 1f))
                                }
                            }
                        }
                    }
                    if (total != expectedSize) {
                        return Result.Failure("dosya eksik indi ($total / $expectedSize bayt)")
                    }

                    val sha256 = Digest.sha256Hex(staged)
                    if (!sha256.equals(expectedSha256, ignoreCase = true)) {
                        return Result.Failure("SHA-256 uyusmadi: ${fileLabel(target)}")
                    }

                    if (target.isFile) target.delete()
                    if (!staged.renameTo(target)) {
                        return Result.Failure("indirilen dosya yerlestirilemedi: ${target.absolutePath}")
                    }
                    return Result.Success(file = target, sha256 = sha256.lowercase(), bytes = total)
                } finally {
                    runCatching { connection.disconnect() }
                }
            }
            return Result.Failure("cok fazla yonlendirme")
        } catch (error: Exception) {
            return Result.Failure(error.message ?: "indirme basarisiz: $url")
        } finally {
            // Basari durumunda .part zaten hedefe tasinmis olur; burada yalnizca
            // yarida kalan kopyalar temizlenir.
            temp?.let { leftover ->
                if (leftover.isFile) runCatching { leftover.delete() }
            }
        }
    }

    private fun fileLabel(target: File): String = target.name
}
