package org.xsecurity.scanner.definitions

import org.xsecurity.scanner.ota.HttpsFetch
import org.xsecurity.scanner.ota.OtaConfig
import org.xsecurity.scanner.ota.SignatureVerifier
import org.xsecurity.scanner.ota.UrlPolicy
import java.security.PublicKey

/**
 * Tanim paketinin guncel olup olmadigini kontrol eder — [org.xsecurity.scanner.ota.OtaChecker]'in
 * tanim kanali kardesi:
 *
 *  1. [DefinitionsConfig] gecerli mi?
 *  2. Manifest (`definitions.json`) ve ayni adresteki ayrik imzasi
 *     (`definitions.json.sig`) yalnizca https + izinli host uzerinden indirilir.
 *  3. Imza, manifestin **ham baytlari** uzerinde RSA-SHA256 ile dogrulanir;
 *     basarisizsa manifest hic ayristirilmadan reddedilir.
 *  4. Ayristirma sonrasi her dosyanin adresi politikadan gecer, boyutlari sinirlanir.
 *  5. `minAppVersionCode` cihazdaki surumden yuksekse paket reddedilir.
 *  6. `defVersion` yuklu olandan yuksek degilse guncelleme yoktur.
 *
 * Ag ve ayristirma mantigi ayridir: karar veren saf [evaluate] JVM birim
 * testlerinde ag olmadan calistirilir.
 */
class DefinitionsChecker(private val config: DefinitionsConfig) {

    sealed class Outcome {
        data class UpdateAvailable(val manifest: DefinitionsManifest) : Outcome()
        object UpToDate : Outcome()
        data class NotConfigured(val message: String) : Outcome()
        data class Error(val message: String) : Outcome()
    }

    /**
     * @param currentDefVersion yuklu tanim paketi surumu (0 = paket icerigi bilinmiyor).
     * @param currentAppVersionCode yuklu uygulamanin versionCode'u.
     */
    fun check(currentDefVersion: Int, currentAppVersionCode: Long): Outcome {
        if (!config.isConfigured) {
            return Outcome.NotConfigured(
                "Tanim kanali yapilandirilmamis; imza veritabani guncelleme kontrolu devre disi."
            )
        }

        val manifestPolicy = UrlPolicy.check(config.manifestUrl, hosts())
        if (!manifestPolicy.allowed) {
            return Outcome.Error(manifestPolicy.reason ?: "Tanim manifest adresine izin yok")
        }

        val publicKey = try {
            SignatureVerifier.loadPublicKey(config.publicKeyPem)
        } catch (error: Throwable) {
            return Outcome.Error("Gomulu dogrulama anahtari gecersiz: ${error.message}")
        }

        val manifestUrl = config.manifestUrl.trim()
        val manifestBytes = HttpsFetch.get(manifestUrl, OtaConfig.MAX_MANIFEST_BYTES, hosts())
            .getOrElse { return Outcome.Error(it.message ?: "Tanim manifesti indirilemedi") }

        // Imza dosyasi: manifest URL'ine ".sig" eklenerek bulunur (ayni host, ayni politika).
        val signatureUrl = "$manifestUrl.sig"
        val signatureBytes = HttpsFetch.get(signatureUrl, OtaConfig.MAX_MANIFEST_BYTES, hosts())
            .getOrElse { return Outcome.Error(it.message ?: "Tanim manifest imzasi indirilemedi") }

        return evaluate(
            manifestBytes = manifestBytes,
            signatureBytes = signatureBytes,
            publicKey = publicKey,
            currentDefVersion = currentDefVersion,
            currentAppVersionCode = currentAppVersionCode,
            hosts = hosts()
        )
    }

    private fun hosts(): Set<String> {
        if (config.allowedHosts.isNotEmpty()) return config.allowedHosts
        val host = runCatching { java.net.URL(config.manifestUrl).host }.getOrNull()
        return setOfNotNull(host?.takeIf { it.isNotBlank() })
    }

    companion object {

        /**
         * Saf karar fonksiyonu (ag/Android yok) — birim testleri burayi hedefler.
         * Once imzayi dogrular, sonra ayristirir; siralama bilinclidir.
         */
        fun evaluate(
            manifestBytes: ByteArray,
            signatureBytes: ByteArray,
            publicKey: PublicKey,
            currentDefVersion: Int,
            currentAppVersionCode: Long,
            hosts: Set<String>
        ): Outcome {
            if (manifestBytes.isEmpty()) return Outcome.Error("Tanim manifesti bos")
            if (signatureBytes.isEmpty()) return Outcome.Error("Tanim manifest imzasi bos")

            if (!SignatureVerifier.verify(publicKey, manifestBytes, signatureBytes)) {
                return Outcome.Error("Tanim manifest imzasi dogrulanamadi — icerik reddedildi")
            }

            val manifest = try {
                DefinitionsManifest.parse(manifestBytes)
            } catch (error: Throwable) {
                return Outcome.Error("Tanim manifesti ayristirilamadi: ${error.message}")
            }

            var totalBytes = 0L
            for (file in manifest.files) {
                val policy = UrlPolicy.check(file.url, hosts)
                if (!policy.allowed) {
                    return Outcome.Error(policy.reason ?: "Tanim dosyasi adresine izin yok: ${file.name}")
                }
                if (file.sizeBytes > DefinitionsConfig.MAX_FILE_BYTES) {
                    return Outcome.Error("Tanim dosyasi izin verilen boyut sinirini asiyor: ${file.name}")
                }
                totalBytes += file.sizeBytes
            }
            if (totalBytes > DefinitionsConfig.MAX_TOTAL_BYTES) {
                return Outcome.Error("Tanim paketi toplam boyut sinirini asiyor ($totalBytes bayt)")
            }

            if (manifest.minAppVersionCode > currentAppVersionCode) {
                return Outcome.Error(
                    "Tanim paketi daha yeni bir uygulamaya ihtiyaç duyuyor " +
                        "(versionCode ${manifest.minAppVersionCode} gerekli, cihazda $currentAppVersionCode var)"
                )
            }
            if (manifest.defVersion <= currentDefVersion) {
                return Outcome.UpToDate
            }
            return Outcome.UpdateAvailable(manifest)
        }
    }
}
