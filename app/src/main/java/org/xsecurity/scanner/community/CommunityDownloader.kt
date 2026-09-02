package org.xsecurity.scanner.community

import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.ota.ApkDownloader
import org.xsecurity.scanner.ota.UrlPolicy
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Topluluk kaynaklarini indiren hafif istemci.
 *
 * [org.xsecurity.scanner.definitions.DefinitionsDownloader]'dan farklari:
 *  - Icerigin SHA-256'i **onceden bilinmez** (kaynak repo kendi icerigini bizim
 *    manifestimizle yayinlamaz); bu yuzden guven, izinli host + https + bicim
 *    dogrulamasi + boyut/tavan sinirlarina dayanir.
 *  - Oncekinden kucuk tavan: topluluk dosyalari 1-2 MB olcegindedir.
 *
 * Test edilebilirlik: [Fetcher] arayuzu ile sarilmistir; birim testler sahte
 * fetcher ile ag baglantisi olmadan kosar.
 */
interface Fetcher {
    /** @throws java.io.IOException ag/HTTP/bicim hatasinda */
    fun fetch(url: String): ByteArray
}

class CommunityDownloader : Fetcher {

    class Payload(val bytes: ByteArray, val sha256: String)

    override fun fetch(url: String): ByteArray {
        var current = url.trim()
        var redirects = 0
        while (true) {
            val policy = UrlPolicy.check(current, ALLOWED_HOSTS)
            if (!policy.allowed) {
                throw java.io.IOException(policy.reason ?: "adrese izin yok: $current")
            }
            val connection = try {
                URL(current).openConnection() as? HttpURLConnection
            } catch (_: Throwable) {
                null
            } ?: throw java.io.IOException("baglanti kurulamadi: $current")

            try {
                connection.instanceFollowRedirects = false
                connection.connectTimeout = ApkDownloader.DEFAULT_CONNECT_TIMEOUT_MS
                connection.readTimeout = ApkDownloader.DEFAULT_READ_TIMEOUT_MS
                connection.setRequestProperty("User-Agent", "X-Security-Definitions/1")
                connection.requestMethod = "GET"

                val code = try {
                    connection.responseCode
                } catch (error: Throwable) {
                    throw java.io.IOException("ag hatasi: ${error.message ?: "yanit yok"}")
                }
                if (code in 300..399) {
                    val location = connection.getHeaderField("Location")
                    if (location.isNullOrBlank()) throw java.io.IOException("yonlendirme hedefi eksik")
                    if (++redirects > ApkDownloader.MAX_REDIRECTS) throw java.io.IOException("cok fazla yonlendirme")
                    current = location
                    continue
                }
                if (code != HttpURLConnection.HTTP_OK) {
                    throw java.io.IOException("HTTP $code: $current")
                }

                val declared = connection.contentLengthLong
                if (declared > MAX_PAYLOAD_BYTES) {
                    throw java.io.IOException("kaynak cok buyuk ($declared bayt; tavan $MAX_PAYLOAD_BYTES)")
                }

                val output = ByteArrayOutputStream(minOf(declared.coerceAtLeast(1024L), 1024L * 1024L).toInt())
                connection.inputStream.use { input ->
                    val buffer = ByteArray(16 * 1024)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        if (output.size() > MAX_PAYLOAD_BYTES) {
                            throw java.io.IOException("kaynak tavani asti ($MAX_PAYLOAD_BYTES bayt)")
                        }
                    }
                }
                return output.toByteArray()
            } finally {
                connection.disconnect()
            }
        }
    }

    fun fetchWithSha(url: String): Payload {
        val bytes = fetch(url)
        return Payload(bytes, Digest.sha256Hex(bytes))
    }

    companion object {
        /**
         * Topluluk kaynaklari icin host izin listesi. Kayit defteri APK'ya gomulu
         * oldugu icin URL'ler zaten bizim kontrolumuzde; bu liste savunma derinligi:
         * bir kayit defteri hatasi bile uygulamayi rastgele sunuculara gonderemez.
         */
        val ALLOWED_HOSTS: Set<String> = setOf(
            "raw.githubusercontent.com",
            "github.com",
            "objects.githubusercontent.com",
            "codeload.github.com"
        )

        /** Topluluk kaynaklari icerin makul tavan: samples.csv ~1 MB, rules.yar ~50 KB. */
        const val MAX_PAYLOAD_BYTES: Long = 16L * 1024L * 1024L
    }
}
