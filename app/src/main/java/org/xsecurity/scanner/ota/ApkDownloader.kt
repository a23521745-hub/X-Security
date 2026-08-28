package org.xsecurity.scanner.ota

import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Imzali manifestteki APK'yi indirir ve [ApkVerifier] ile akista dogrular.
 *
 * Ag guvenligi:
 *  - Yalnizca https; her baglanti ve her yonlendirme [UrlPolicy]'den tekrar gecer.
 *  - Otomatik yonlendirme takibi **kapali** (`instanceFollowRedirects=false`); bir
 *    `Location` alindiginda hedef once izin listesinden gecer, en fazla [MAX_REDIRECTS]
 *    adima izin verilir. Boylece manifeste sizmis bir URL, izinli sunucu uzerinden
 *    baska bir host'a yonlendirip APK teslim edemez.
 *  - Icerik uzunlugu bildirilmisse, bu da manifestteki boyutla karsilastirilir.
 */
class ApkDownloader(
    private val config: OtaConfig,
    private val connectTimeoutMs: Int = DEFAULT_CONNECT_TIMEOUT_MS,
    private val readTimeoutMs: Int = DEFAULT_READ_TIMEOUT_MS
) {

    sealed class Result {
        data class Success(val file: File, val bytes: Long, val sha256: String) : Result()
        data class Failure(val message: String) : Result()
    }

    fun download(info: UpdateInfo, target: File, onProgress: (Float) -> Unit = {}): Result {
        val policy = UrlPolicy.check(info.apkUrl, effectiveHosts())
        if (!policy.allowed) return Result.Failure(policy.reason ?: "APK adresine izin yok")

        var connection = openConnection(info.apkUrl) ?: return Result.Failure("APK sunucusuna bağlanılamadı")
        var redirects = 0
        try {
            while (true) {
                val code = runCatching { connection.responseCode }.getOrElse {
                    return Result.Failure("Ağ hatası: ${it.message ?: "bağlantı kurulamadı"}")
                }
                if (code in 300..399) {
                    if (redirects >= MAX_REDIRECTS) return Result.Failure("Çok fazla yönlendirme")
                    val location = connection.getHeaderField("Location")
                    connection.disconnect()
                    if (location.isNullOrBlank()) return Result.Failure("Yönlendirme hedefi eksik")
                    val redirectPolicy = UrlPolicy.check(location, effectiveHosts())
                    if (!redirectPolicy.allowed) {
                        return Result.Failure(redirectPolicy.reason ?: "Yönlendirme hedefine izin yok")
                    }
                    connection = openConnection(location)
                        ?: return Result.Failure("Yönlendirme hedefine bağlanılamadı")
                    redirects++
                    continue
                }
                if (code != HttpURLConnection.HTTP_OK) {
                    return Result.Failure("APK indirilemedi: HTTP $code")
                }

                val contentLength = connection.contentLengthLong
                if (contentLength > 0L && info.apkSizeBytes > 0L && contentLength != info.apkSizeBytes) {
                    return Result.Failure(
                        "Sunucunun bildirdiği boyut manifestle uyuşmuyor ($contentLength ≠ ${info.apkSizeBytes})"
                    )
                }

                val verified = connection.inputStream.use { stream ->
                    ApkVerifier.verifyToFile(
                        input = stream,
                        expectedSha256 = info.apkSha256,
                        expectedSize = info.apkSizeBytes,
                        maxBytes = config.maxApkBytes,
                        target = target,
                        onProgress = onProgress
                    )
                }
                return when (verified) {
                    is ApkVerifier.Result.Success ->
                        Result.Success(verified.file, verified.bytes, verified.sha256)
                    is ApkVerifier.Result.Failure -> Result.Failure(verified.message)
                }
            }
        } finally {
            runCatching { connection.disconnect() }
        }
    }

    private fun openConnection(urlString: String): HttpURLConnection? {
        val url = try {
            URL(urlString)
        } catch (_: Throwable) {
            return null
        }
        if (url.protocol.lowercase() != "https") return null
        return (runCatching { url.openConnection() }.getOrNull() as? HttpURLConnection)?.apply {
            instanceFollowRedirects = false
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
            requestMethod = "GET"
            setRequestProperty("Accept", "application/vnd.android.package-archive, */*")
        }
    }

    private fun effectiveHosts(): Set<String> {
        if (config.allowedHosts.isNotEmpty()) return config.allowedHosts
        val manifestHost = runCatching { URL(config.manifestUrl).host }.getOrNull()
        return setOfNotNull(manifestHost?.takeIf { it.isNotBlank() })
    }

    companion object {
        const val MAX_REDIRECTS = 3
        const val DEFAULT_CONNECT_TIMEOUT_MS = 20_000
        const val DEFAULT_READ_TIMEOUT_MS = 60_000
    }
}
