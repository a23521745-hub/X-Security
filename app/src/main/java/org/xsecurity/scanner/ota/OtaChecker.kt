package org.xsecurity.scanner.ota

import java.net.HttpURLConnection
import java.net.URL

/**
 * Guncel olup olmadigini kontrol eder:
 *
 *  1. [OtaConfig] gecerli mi?
 *  2. Manifest (`update.json`) ve ayni adresteki ayrık imza (`update.json.sig`)
 *     yalnizca https + izinli host uzerinden indirilir.
 *  3. Imza, manifestin **ham baytlari** uzerinde RSA-SHA256 veya Ed25519 ile
 *     dogrulanir. Dogrulama basarisiz ise manifest **hic ayrıştırılmadan** reddedilir.
 *  4. Ancak o noktadan sonra [UpdateInfo] ayristirilir ve `apkUrl` politikadan gecer.
 *  5. Manifestin `minSdk` alani cihazin Android surumunden yuksekse guncelleme reddedilir.
 *  6. `versionCode` cihazdakinden yuksek degilse guncelleme yoktur (downgrade engellenir).
 *
 * Ag ve ayristirma mantigi ayridir: karar veren saf [evaluate] JVM birim testlerinde
 * ag olmadan calistirilir.
 */
class OtaChecker(private val config: OtaConfig) {

    sealed class Outcome {
        data class UpdateAvailable(val info: UpdateInfo) : Outcome()
        object UpToDate : Outcome()
        data class NotConfigured(val message: String) : Outcome()
        data class Error(val message: String) : Outcome()
    }

    /**
     * @param currentVersionCode yuklu surumun versionCode'u.
     * @param deviceSdk cihazin Build.VERSION.SDK_INT'i (0 = bilinmiyor; minSdk kontrolu atlanir).
     */
    fun check(currentVersionCode: Long, deviceSdk: Int = 0): Outcome {
        if (!config.isConfigured) {
            return Outcome.NotConfigured("OTA sunucu adresi yapılandırılmamış; güncelleme kontrolü devre dışı.")
        }

        val manifestPolicy = UrlPolicy.check(config.manifestUrl, hosts())
        if (!manifestPolicy.allowed) {
            return Outcome.Error(manifestPolicy.reason ?: "Manifest adresine izin yok")
        }

        val publicKey = try {
            SignatureVerifier.loadPublicKey(config.publicKeyPem)
        } catch (error: Throwable) {
            return Outcome.Error("Gömülü doğrulama anahtarı geçersiz: ${error.message}")
        }

        val manifestUrl = config.manifestUrl.trim()
        val manifestBytes = HttpsFetch.get(manifestUrl, OtaConfig.MAX_MANIFEST_BYTES, hosts())
            .getOrElse { return Outcome.Error(it.message ?: "Manifest indirilemedi") }

        // Imza dosyasi: manifest URL'ine ".sig" eklenerek bulunur (ayni host, ayni politikadan gecer).
        val signatureUrl = if (manifestUrl.endsWith("/")) "${manifestUrl}update.json.sig" else "$manifestUrl.sig"
        val signatureBytes = HttpsFetch.get(signatureUrl, OtaConfig.MAX_MANIFEST_BYTES, hosts())
            .getOrElse { return Outcome.Error(it.message ?: "Manifest imzası indirilemedi") }

        return evaluate(
            manifestBytes = manifestBytes,
            signatureBytes = signatureBytes,
            publicKey = publicKey,
            currentVersionCode = currentVersionCode,
            hosts = hosts(),
            deviceSdk = deviceSdk
        )
    }

    private fun hosts(): Set<String> {
        if (config.allowedHosts.isNotEmpty()) return config.allowedHosts
        val host = runCatching { URL(config.manifestUrl).host }.getOrNull()
        return setOfNotNull(host?.takeIf { it.isNotBlank() })
    }

    companion object {
        /**
         * Saf karar fonksiyonu (ag/Android yok) — birim testleri burayi hedefler.
         * Once imzayi dogrular, sonra ayristirir; siralama bilinçlidir.
         *
         * @param deviceSdk cihazin API seviyesi; 0 = bilinmiyor (minSdk kontrolu atlanir).
         */
        fun evaluate(
            manifestBytes: ByteArray,
            signatureBytes: ByteArray,
            publicKey: java.security.PublicKey,
            currentVersionCode: Long,
            hosts: Set<String>,
            deviceSdk: Int = 0
        ): Outcome {
            if (manifestBytes.isEmpty()) return Outcome.Error("Manifest boş")
            if (signatureBytes.isEmpty()) return Outcome.Error("Manifest imzası boş")

            val signatureOk = SignatureVerifier.verify(publicKey, manifestBytes, signatureBytes)
            if (!signatureOk) {
                return Outcome.Error("Manifest imzası doğrulanamadı — içerik reddedildi")
            }

            val info = try {
                UpdateInfo.parse(manifestBytes)
            } catch (error: Throwable) {
                return Outcome.Error("Manifest ayrıştırılamadı: ${error.message}")
            }

            val apkPolicy = UrlPolicy.check(info.apkUrl, hosts)
            if (!apkPolicy.allowed) {
                return Outcome.Error(apkPolicy.reason ?: "APK adresine izin yok")
            }
            if (info.apkSizeBytes > OtaConfig.MAX_APK_BYTES) {
                return Outcome.Error("APK, izin verilen boyut sınırını aşıyor")
            }
            if (deviceSdk > 0 && info.minSdk > deviceSdk) {
                return Outcome.Error(
                    "Güncelleme bu Android sürümünü desteklemiyor (en az API ${info.minSdk} gerekiyor, " +
                        "cihazda API $deviceSdk var)"
                )
            }
            if (info.versionCode <= currentVersionCode) {
                return Outcome.UpToDate
            }
            return Outcome.UpdateAvailable(info)
        }
    }
}

/** Kucuk metin dosyalari (manifest, imza) icin https indirici; yonlendirmeler politika ile sinirli. */
internal object HttpsFetch {

    fun get(urlString: String, maxBytes: Long, allowedHosts: Set<String>): Result<ByteArray> {
        var url = urlString.trim()
        repeat(ApkDownloader.MAX_REDIRECTS + 1) {
            val policy = UrlPolicy.check(url, allowedHosts)
            if (!policy.allowed) return Result.failure(IllegalStateException(policy.reason ?: "adrese izin yok"))

            val connection = try {
                (URL(url).openConnection() as? HttpURLConnection)
            } catch (_: Throwable) {
                null
            } ?: return Result.failure(IllegalStateException("bağlantı kurulamadı"))

            try {
                connection.instanceFollowRedirects = false
                connection.connectTimeout = ApkDownloader.DEFAULT_CONNECT_TIMEOUT_MS
                connection.readTimeout = ApkDownloader.DEFAULT_READ_TIMEOUT_MS
                connection.requestMethod = "GET"

                val code = try {
                    connection.responseCode
                } catch (error: Throwable) {
                    return Result.failure(IllegalStateException("ağ hatası: ${error.message ?: "yanıt yok"}"))
                }

                if (code in 300..399) {
                    val location = connection.getHeaderField("Location")
                    // Yonlendirmeyi izlemeden once bu baglantiyi kapat.
                    runCatching { connection.disconnect() }
                    if (location.isNullOrBlank()) {
                        return Result.failure(IllegalStateException("yönlendirme hedefi eksik"))
                    }
                    url = location
                    return@repeat
                }
                if (code != HttpURLConnection.HTTP_OK) {
                    return Result.failure(IllegalStateException("HTTP $code"))
                }

                val length = connection.contentLengthLong // -1 = bilinmiyor
                if (length > maxBytes) {
                    return Result.failure(IllegalStateException("dosya çok büyük"))
                }

                val bytes = connection.inputStream.use { stream ->
                    val buffer = ByteArray(64 * 1024)
                    val out = java.io.ByteArrayOutputStream()
                    var total = 0L
                    while (true) {
                        val read = stream.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > maxBytes) {
                            return Result.failure(IllegalStateException("dosya boyut sınırını aştı"))
                        }
                        out.write(buffer, 0, read)
                    }
                    out.toByteArray()
                }
                if (bytes.isEmpty()) return Result.failure(IllegalStateException("boş yanıt"))
                return Result.success(bytes)
            } finally {
                runCatching { connection.disconnect() }
            }
        }
        return Result.failure(IllegalStateException("çok fazla yönlendirme"))
    }
}
