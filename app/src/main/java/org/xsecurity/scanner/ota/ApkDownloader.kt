package org.xsecurity.scanner.ota

import org.xsecurity.scanner.core.Digest.toHexString
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Imzali manifestteki APK'yi **kesintiye dayanikli** (resumable) indirir ve
 * akista SHA-256 ile dogrular.
 *
 * Dayaniklilik (resume) tasarimi:
 *  - Indirme, hedefin yanindaki `<isim>.part` dosyasina yazilir; ancak tum
 *    dogrulamalardan gectikten sonra atomik olarak hedefe tasınır (rename).
 *    Yarım dosya ASLA kuruluma sunulmaz.
 *  - Isleme `<part> bayt` kadar indirilmis devam varsa sunucuya
 *    `Range: bytes=<part>-` ve (varsa kayitli ETag ile) `If-Range` gonderilir:
 *      * `206 Partial Content` -> mevcut kisim korunur, kaldigi yerden devam,
 *      * `200 OK`              -> sunucu temsili degistirmis; sifirdan baslanir,
 *      * `416 Range Not Satisfiable` ve part zaten tamse -> yalnizca dogrulama yapilir.
 *  - Ag hatasi/kesinti durumunda (akis erken biter, baglanti kopar) `.part`
 *    **silinmez**; WorkManager tekrar denediginde ayni dosya kaldigi yerden devam eder.
 *  - Butunluk hatalarinda (hash uyusmazligi, sinir tasan indirme) `.part` ve ETag
 *    kaydi silinir: bozuk veriyle devam edilmez.
 *
 * Ag guvenligi:
 *  - Yalnizca https; her baglanti ve her yonlendirme [UrlPolicy]'den tekrar gecer.
 *  - Otomatik yonlendirme takibi **kapali** (`instanceFollowRedirects=false`); bir
 *    `Location` alindiginda hedef once izin listesinden gecer, en fazla [MAX_REDIRECTS]
 *    adima izin verilir. Boylece manifeste sizmis bir URL, izinli sunucu uzerinden
 *    baska bir host'a yonlendirip APK teslim edemez.
 *  - Akis sirasindaki sert boyut sinirlari (manifest boyutu + [OtaConfig.maxApkBytes])
 *    ve son SHA-256 kontrolu, sunucunun bildirdigi uzunluktan bağımsız olarak
 *    dosyanin gercek butunlugunu garanti eder.
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

        target.parentFile?.mkdirs()
        val part = File(target.parentFile, target.name + PART_SUFFIX)
        val etagFile = File(target.parentFile, target.name + ETAG_SUFFIX)

        // Idempotent indirme: hedef zaten tam ve hash'i dogruysa aga cikmadan basari don.
        if (target.isFile && info.apkSizeBytes > 0L && target.length() == info.apkSizeBytes) {
            val verified = ApkVerifier.verifyFile(
                target, info.apkSha256, info.apkSizeBytes, config.maxApkBytes
            )
            if (verified is ApkVerifier.Result.Success) {
                onProgress(1f)
                return Result.Success(target, verified.bytes, verified.sha256)
            }
            // Hedef bozuk/farkli: temizle ve bastan indir.
            runCatching { target.delete() }
        }

        // Bozuk/kakismis durum temizligi: beklenen boyuttan buyuk part anlamsizdir.
        var existing = if (part.isFile) part.length() else 0L
        if (existing > 0L && info.apkSizeBytes > 0L && existing > info.apkSizeBytes) {
            runCatching { part.delete() }
            runCatching { etagFile.delete() }
            existing = 0L
        }

        // Part zaten tamamlanmis gorunuyorsa: indirme degil, yalnizca dogrulama.
        if (existing > 0L && existing == info.apkSizeBytes) {
            return finalizeVerified(info, part, target, etagFile, onProgress)
        }

        val etag = if (etagFile.isFile) {
            runCatching { etagFile.readText().trim() }.getOrNull().orEmpty()
        } else {
            ""
        }

        var url = info.apkUrl
        var redirects = 0
        while (true) {
            val connection = openConnection(url, rangeFrom = existing, ifRange = etag)
                ?: return Result.Failure("APK sunucusuna bağlanılamadı")

            val code = try {
                connection.responseCode
            } catch (error: Throwable) {
                runCatching { connection.disconnect() }
                // Ag kesintisi: kismi dosya kalir, bir sonraki deneme devam eder.
                return Result.Failure(
                    "Ağ hatası: ${error.message ?: "bağlantı kurulamadı"} — indirme yeniden denendiğinde kaldığı yerden devam eder"
                )
            }

            if (code in 300..399) {
                if (redirects >= MAX_REDIRECTS) {
                    runCatching { connection.disconnect() }
                    return Result.Failure("Çok fazla yönlendirme")
                }
                val location = connection.getHeaderField("Location")
                runCatching { connection.disconnect() }
                if (location.isNullOrBlank()) return Result.Failure("Yönlendirme hedefi eksik")
                val redirectPolicy = UrlPolicy.check(location, effectiveHosts())
                if (!redirectPolicy.allowed) {
                    return Result.Failure(redirectPolicy.reason ?: "Yönlendirme hedefine izin yok")
                }
                url = location
                redirects++
                continue
            }

            if (code == HTTP_RANGE_NOT_SATISFIABLE) {
                runCatching { connection.disconnect() }
                if (existing <= 0L) {
                    // Aralik istemeden 416 protokol ihlalidir; guvenli tarafta kal.
                    return Result.Failure("APK indirilemedi: HTTP 416")
                }
                return when (resumeMode(existing, info.apkSizeBytes, code)) {
                    ResumeMode.FINALIZE_EXISTING ->
                        finalizeVerified(info, part, target, etagFile, onProgress)
                    else ->
                        // Sunucu araligi reddediyor ve part tamsa da degil: temiz basla.
                        restartFromScratch(info, target, part, etagFile, onProgress)
                }
            }

            if (code != HttpURLConnection.HTTP_OK && code != HTTP_PARTIAL_CONTENT) {
                runCatching { connection.disconnect() }
                return Result.Failure("APK indirilemedi: HTTP $code")
            }

            if (code == HTTP_PARTIAL_CONTENT && existing <= 0L) {
                runCatching { connection.disconnect() }
                return Result.Failure("Sunucu beklenmedik kısmi yanıt döndürdü (206) — indirme reddedildi")
            }

            // 206 -> mevcut part'in uzerine devam; 200 -> temsil degismis, bastan yaz.
            val append = code == HTTP_PARTIAL_CONTENT && existing > 0L
            // Bu noktadan sonra akis kullanilacak; hata yolu baglantiyi kapatir.
            return streamToPart(
                info = info,
                connection = connection,
                part = part,
                etagFile = etagFile,
                target = target,
                append = append,
                existingBytes = if (append) existing else 0L,
                onProgress = onProgress
            )
        }
    }

    // --- Akis ve dogrulama --------------------------------------------------

    /**
     * Agdan gelen baytlari `.part` dosyasina yazar; bu sirada:
     *  - devam modunda once mevcut kismi SHA-256 ozetine katir,
     *  - [OtaConfig.maxApkBytes] ve manifestteki boyuta karsi sert sinir,
     *  - akis sonunda tam SHA-256 eslesmesi
     * kontrol edilir. Basari: atomik rename ile hedefe gecis.
     */
    private fun streamToPart(
        info: UpdateInfo,
        connection: HttpURLConnection,
        part: File,
        etagFile: File,
        target: File,
        append: Boolean,
        existingBytes: Long,
        onProgress: (Float) -> Unit
    ): Result {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER)
        var total = 0L

        try {
            connection.inputStream.use { stream ->
                java.io.FileOutputStream(part, append).use { output ->
                    if (append && existingBytes > 0L) {
                        // Ozeti mevcut kismi okuyarak tohumla.
                        part.inputStream().use { existingStream ->
                            while (true) {
                                val read = existingStream.read(buffer)
                                if (read < 0) break
                                if (read > 0) digest.update(buffer, 0, read)
                            }
                        }
                    }

                    // Sunucunun bildirdigi ETag'i hemen kalici hale getir: ayni
                    // temsil icin bir sonraki deneme If-Range ile guvenli devam eder.
                    saveEtag(etagFile, connection.getHeaderField("ETag"))

                    while (true) {
                        val read = stream.read(buffer)
                        if (read < 0) break
                        if (read == 0) continue
                        total += read
                        val absolute = existingBytes + total
                        if (absolute > config.maxApkBytes) {
                            return deletePartAndFail(
                                part, etagFile,
                                "APK, izin verilen boyut sinirini aştı (${config.maxApkBytes} bayt)"
                            )
                        }
                        if (info.apkSizeBytes > 0L && absolute > info.apkSizeBytes) {
                            return deletePartAndFail(
                                part, etagFile,
                                "APK, manifestte bildirilen boyuttan büyük (${info.apkSizeBytes} bayt)"
                            )
                        }
                        digest.update(buffer, 0, read)
                        output.write(buffer, 0, read)
                        if (info.apkSizeBytes > 0L) {
                            onProgress((absolute.toFloat() / info.apkSizeBytes.toFloat()).coerceIn(0f, 1f))
                        }
                    }
                }
            }

            val absolute = existingBytes + total
            if (absolute <= 0L) return deletePartAndFail(part, etagFile, "İndirilen APK boş")
            if (info.apkSizeBytes > 0L && absolute != info.apkSizeBytes) {
                // Akis beklenenden erken/uzun bitti. Bu cogunlukla bir ag kesintisidir:
                // kismi dosya resume icin KORUNUR; hash kontrolu tamamlanmamis dosyada
                // anlamsizdir. (Tasan indirme durumunda yukaridaki sert sinir zaten
                // part'i silmisti.)
                return Result.Failure(
                    "İndirme tamamlanamadı: beklenen ${info.apkSizeBytes} bayt, alınan $absolute bayt — " +
                        "yeniden denendiğinde kaldığı yerden devam edilir"
                )
            }

            val actualSha = digest.digest().toHexString()
            if (!actualSha.equals(info.apkSha256, ignoreCase = true)) {
                return deletePartAndFail(part, etagFile, "APK SHA-256 eşleşmedi — indirme reddedildi")
            }

            // Tum kontroller gecti: atomik gecis + temizlik.
            runCatching { if (target.exists()) target.delete() }
            if (!part.renameTo(target)) {
                return deletePartAndFail(part, etagFile, "İndirilen dosya yerine taşınamadı")
            }
            runCatching { etagFile.delete() }
            onProgress(1f)
            return Result.Success(target, absolute, actualSha)
        } catch (error: IOException) {
            // Ag kesintisi: kismi dosya KASITLI olarak korunur (resume icin).
            return Result.Failure(
                "İndirme kesintiye uğradı: ${error.message ?: "ağ hatası"} — yeniden denendiğinde kaldığı yerden devam edilir"
            )
        } catch (error: Throwable) {
            // Bilinmeyen hata: durumu guvenli tarafta birak.
            runCatching { connection.disconnect() }
            return deletePartAndFail(part, etagFile, error.message ?: "APK doğrulanamadı")
        } finally {
            runCatching { connection.disconnect() }
        }
    }

    /** `.part` zaten tam boyuttaysa: hash dogrulamasi + atomik tasinma. */
    private fun finalizeVerified(
        info: UpdateInfo,
        part: File,
        target: File,
        etagFile: File,
        onProgress: (Float) -> Unit
    ): Result {
        onProgress(1f)
        val verified = ApkVerifier.verifyFile(part, info.apkSha256, info.apkSizeBytes, config.maxApkBytes)
        return when (verified) {
            is ApkVerifier.Result.Success -> {
                runCatching { if (target.exists()) target.delete() }
                if (part.renameTo(target)) {
                    runCatching { etagFile.delete() }
                    Result.Success(target, verified.bytes, verified.sha256)
                } else {
                    deletePartAndFail(part, etagFile, "İndirilen dosya yerine taşınamadı")
                }
            }
            is ApkVerifier.Result.Failure ->
                deletePartAndFail(part, etagFile, verified.message)
        }
    }

    /** Part'i temizleyip tek seferde bastan indirir (sunucu Range'i reddettiyse). */
    private fun restartFromScratch(
        info: UpdateInfo,
        target: File,
        part: File,
        etagFile: File,
        onProgress: (Float) -> Unit
    ): Result {
        runCatching { part.delete() }
        runCatching { etagFile.delete() }
        return download(info, target, onProgress)
    }

    private fun deletePartAndFail(part: File, etagFile: File, message: String): Result {
        runCatching { if (part.exists()) part.delete() }
        runCatching { if (etagFile.exists()) etagFile.delete() }
        return Result.Failure(message)
    }

    /** Sunucu ETag'ini yan dosyaya yazar; ETag yoksa eski kaydi temizler. */
    private fun saveEtag(etagFile: File, header: String?) {
        if (header.isNullOrBlank()) {
            runCatching { etagFile.delete() }
            return
        }
        runCatching { etagFile.writeText(header.trim()) }
    }

    private fun openConnection(urlString: String, rangeFrom: Long, ifRange: String): HttpURLConnection? {
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
            if (rangeFrom > 0L) {
                setRequestProperty("Range", "bytes=$rangeFrom-")
                if (ifRange.isNotBlank()) {
                    setRequestProperty("If-Range", ifRange)
                }
            }
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

        /** Kesik dosya uzantisi; ancak dogrulamadan sonra hedefe tasınır. */
        const val PART_SUFFIX = ".part"
        const val ETAG_SUFFIX = ".etag"

        private const val HTTP_PARTIAL_CONTENT = 206
        private const val HTTP_RANGE_NOT_SATISFIABLE = 416
        private const val BUFFER = 64 * 1024

        /**
         * Saf karar fonksiyonu: mevcut `.part` uzunlugu ve sunucu yanit koduna gore
         * indirmenin nasil surdurulecegini soyler (birim testlerinin hedefi).
         */
        internal fun resumeMode(existingBytes: Long, expectedSize: Long, responseCode: Int): ResumeMode = when {
            existingBytes <= 0L -> ResumeMode.RESTART
            responseCode == HTTP_PARTIAL_CONTENT -> ResumeMode.APPEND
            responseCode == HTTP_RANGE_NOT_SATISFIABLE &&
                expectedSize > 0L && existingBytes == expectedSize -> ResumeMode.FINALIZE_EXISTING
            else -> ResumeMode.RESTART
        }
    }

    internal enum class ResumeMode {
        /** Mevcut `.part`'in uzerine devam (206 Partial Content). */
        APPEND,

        /** Part'i at, bastan indir (200 OK / gecersiz aralik). */
        RESTART,

        /** Part tamamlanmis; yalnizca butunluk dogrulamasi yapilir. */
        FINALIZE_EXISTING
    }
}
