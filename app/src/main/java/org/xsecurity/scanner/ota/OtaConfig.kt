package org.xsecurity.scanner.ota

/**
 * OTA istemcisinin calisma zamani yapilandirmasi.
 *
 * Degerler asla kaynaktan (kaynak kod/dal) gelmez; derleme zamaninda Gradle
 * properties / ortam degiskenlerinden `BuildConfig`'e enjekte edilir (bkz.
 * `app/build.gradle.kts` ve `tools/ota/README.md`). Boylece sunucu adresi ve dogrulama
 * anahtari depo disindan yonetilir.
 *
 * @property manifestUrl  `update.json`'in tam https adresi.
 * @property publicKeyPem manifest imzasini dogrulayan public anahtar
 *   (PEM ya da tek-parca base64). RSA-2048 (SHA256withRSA; tum cihazlar) veya
 *   Ed25519 (modern cihazlar) anahtari verilebilir — algoritma anahtarin turunden
 *   secilir. Bos birakilirsa kanal "yapilandirilmamis" sayilir ve OTA tamamen
 *   kapalidir (fail-closed, H-1); ornek-anahtar geri donusu YOKTUR.
 * @property allowedHosts manifest + APK indirmesine izin verilen ana bilgisayarlar.
 *   Bos birakilirsa [manifestUrl]'in host'u otomatik eklenir.
 */
data class OtaConfig(
    val manifestUrl: String,
    val publicKeyPem: String,
    val allowedHosts: Set<String>
) {
    val isConfigured: Boolean
        get() = manifestUrl.isNotBlank() && publicKeyPem.isNotBlank()

    /** Indirilen APK icin boyut ust siniri (savunma derinligi). */
    val maxApkBytes: Long get() = MAX_APK_BYTES

    companion object {
        /** Manifest imzasi icin indirilebilecek en buyuk dosya (JSON + imza). */
        const val MAX_MANIFEST_BYTES: Long = 256L * 1024L

        /** APK icin katı boyut siniri (~200 MiB); uzeri reddedilir. */
        const val MAX_APK_BYTES: Long = 200L * 1024L * 1024L
    }
}
