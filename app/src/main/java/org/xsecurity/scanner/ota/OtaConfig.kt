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
 *   secilir. Bos ise [SAMPLE_PUBLIC_KEY_PEM] kullanilir.
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
         * GELISTIRME ORNEK anahtari (RSA-2048). `tools/ota/ota-signing-dev-public.pem`
         * ile eslestigi
         * icin `tools/ota/` altindaki ornek manifesti dogrular. Uretime alirken:
         *   1. `tools/ota/generate-ota-key.sh` ile yeni anahtar uretin,
         *   2. private anahtari **asla** depoya koymayin (offline saklayin),
         *   3. public anahtari `-PxsecOtaPublicKeyPem=...` / `XSEC_OTA_PUBLIC_KEY_PEM`
         *      ile derlemeye verin.
         */
        val SAMPLE_PUBLIC_KEY_PEM: String = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtw43MZ13JzoRKrIgMv7Q
            wyg85532mFhs6tQcI0czOD4XUbWGAAxkf7zqFEcDx9HVdPQ7hIR3IJR/WkElihXa
            6RvfqkCqscP4qUADySgsPE7AH5gyrPtpa9E2LJXm45ZJOv0+rrQQfzCgrRP7KeRw
            poTK5DkXcwNIvfKbDFxP+EigoG4wkOP/fmTJiUe77qAIGaAQ5aWegfDyq+s5YeV5
            x9OiOIWODOXKi5zcnSbb+yb5hpWHxZ0YowM+iZXIG8GXD75PvpYZYV/Rhj9i40vI
            6yUEgkxmGV+wH3+IZtCjapxU8JIvk7ROmJPOOd2NSVAI2S4gQtINUFsVLVa7KpH9
            HwIDAQAB
            -----END PUBLIC KEY-----
        """.trimIndent()
    }
}
