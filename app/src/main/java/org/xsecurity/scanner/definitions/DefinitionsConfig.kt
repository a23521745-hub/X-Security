package org.xsecurity.scanner.definitions

/**
 * Tanim kanalinin calisma zamani yapilandirmasi.
 *
 * Ayri bir BuildConfig alani **bilincli olarak yok**: tanim kanali, uygulama
 * guncellemesiyle ayni imza anahtarini ve ayni izinli host listesini kullanir
 * ve manifest adresi OTA manifest adresinden turetilir
 * (`.../releases/latest/download/update.json` ->
 *  `.../releases/latest/download/definitions.json`). Boylece:
 *  - yeni bir secret/env degiskeni gerekmez,
 *  - OTA kapaliysa tanim kanali da kapalidir,
 *  - tanim dosyalari ancak APK'nin zaten indirmeye izin verdigi hostlardan gelir.
 */
data class DefinitionsConfig(
    val manifestUrl: String,
    val publicKeyPem: String,
    val allowedHosts: Set<String>
) {
    val isConfigured: Boolean
        get() = manifestUrl.isNotBlank() && publicKeyPem.isNotBlank()

    companion object {

        /** Tanim manifestinin dosya adi (OTA manifestiyle ayni dizinde durur). */
        const val DEFINITIONS_FILE_NAME = "definitions.json"

        /** Tek bir tanim dosyasinin (rules.yar / signatures.ndb) izin verilen en buyuk boyutu. */
        const val MAX_FILE_BYTES: Long = 24L * 1024L * 1024L

        /** Tanim paketinin toplam izin verilen boyutu. */
        const val MAX_TOTAL_BYTES: Long = 32L * 1024L * 1024L

        /**
         * OTA yapilandirmasindan tanim kanali yapilandirmasi turetir.
         *
         * OTA manifest adresi bos ise tanim kanali da "yapilandirilmamis" olur
         * (yalnizca paketle gelen kuratorluk veritabani kullanilir).
         */
        fun derive(
            otaManifestUrl: String,
            otaPublicKeyPem: String,
            otaAllowedHostsCsv: String
        ): DefinitionsConfig {
            val trimmed = otaManifestUrl.trim()
            val manifestUrl = deriveManifestUrl(trimmed)
            val hosts = LinkedHashSet<String>()
            otaAllowedHostsCsv.split(',')
                .map { it.trim().lowercase() }
                .filter { it.isNotBlank() }
                .forEach(hosts::add)
            if (manifestUrl.isNotBlank()) {
                runCatching { java.net.URL(manifestUrl).host?.lowercase() }
                    .getOrNull()
                    ?.takeIf { it.isNotBlank() }
                    ?.let(hosts::add)
            }
            return DefinitionsConfig(
                manifestUrl = manifestUrl,
                publicKeyPem = otaPublicKeyPem,
                allowedHosts = hosts
            )
        }

        /** `https://host/a/b/update.json` -> `https://host/a/b/definitions.json`. */
        internal fun deriveManifestUrl(otaManifestUrl: String): String {
            if (otaManifestUrl.isBlank()) return ""
            val schemeEnd = otaManifestUrl.indexOf("://")
            if (schemeEnd < 0) return ""
            val lastSlash = otaManifestUrl.lastIndexOf('/')
            // yol bileseni hic yoksa ("https://host") turetilemez
            if (lastSlash <= schemeEnd + 2) return ""
            return otaManifestUrl.substring(0, lastSlash + 1) + DEFINITIONS_FILE_NAME
        }
    }
}
