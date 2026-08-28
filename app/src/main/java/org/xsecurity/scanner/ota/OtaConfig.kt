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
 * @property publicKeyPem manifest imzasini dogrulayan RSA-2048 public anahtar
 *   (PEM ya da tek-parca base64). Bos ise [SAMPLE_PUBLIC_KEY_PEM] kullanilir.
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

        /**
         * GELISTIRME ORNEK anahtari. `tools/ota/ota-signing-dev-public.pem` ile eslestiği
         * icin `tools/ota/` altindaki ornek manifesti dogrular. Uretime alirken:
         *   1. `tools/ota/generate-ota-key.sh` ile yeni anahtar uretin,
         *   2. private anahtari **asla** depoya koymayin (offline saklayin),
         *   3. public anahtari `-PxsecOtaPublicKeyPem=...` / `XSEC_OTA_PUBLIC_KEY_PEM`
         *      ile derlemeye verin.
         */
        val SAMPLE_PUBLIC_KEY_PEM: String = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwFjJzcMiqNk9YO9naGxD
            6rGJLsFVqS2+hQhHa2hSKriXyqVOeNkgPzhT1P3A6n7k9kIlLWGeBREplglrvhlr
            qRv2ESh/0Y+E2IMBsVuQ/M9YLwfdjSpoHfjZcTz0qEAVxjw80js982lKTg9hcj18
            tW8waYij4GEw71aai23661Hgcfww5lhk50ijivALSgL4/HOrVwuLIu8PxCXHSq41
            eoakl250uG+HU3oEVkikBePti0FiFzMEB+6JCsFs6zix9YYrNPztaOF65Cf9TWoI
            Bt9s8pydHL4Y6JLNvoFs/1+6Fg3h0CzWuNweGm/L/LCxXEfq15D8SPSGZy7XmpVt
            3QIDAQAB
            -----END PUBLIC KEY-----
        """.trimIndent()
    }
}
