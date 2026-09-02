package org.xsecurity.scanner.ota

import org.json.JSONObject

/**
 * Sunucudan gelen **imzali** guncelleme bildirimi (manifest).
 *
 * Guvenlik kontrati:
 *  - Bu sinif yalnizca [OtaChecker] icinde, manifestin RSA/Ed25519 imzasi
 *    dogrulandiktan SONRA uretilir. Imzasiz/bozuk manifest asla bu nesneye donusmez.
 *  - Imza, manifest dosyasinin **ham baytlari** uzerinden dogrulanir; kanoniklestirme
 *    yoktur (sunucu `update.json` dosyasini ne yayinladiysa istemci onu dogrular).
 *  - Alanlar beyaz listedir; bilinmeyen alanlar yok sayilir.
 *
 * Desteklenen manifest semasi (tumu denetlenir):
 * ```
 * {
 *   "versionCode": 5,                       // pozitif tamsayi; yukselmek zorunda
 *   "versionName": "0.93.0",                // bos olamaz
 *   "apkUrl": "https://updates.example.com/x-security/app-release.apk",
 *   "apkSha256": "<64 karakter kucuk harf hex>",
 *   "apkSizeBytes": 1234567,                // pozitif; boyut/is bütünlük kontrolü
 *   "minSdk": 26,                           // bu güncellemenin istedigi en dusuk API
 *   "forceUpdate": false,                   // zorunlu guncelleme bayragi
 *   "changelog": "- A dundu\n- B dundu",    // detayli degisiklik gunlugu (opsiyonel)
 *   "releaseNotes": "Kisa surum notu."      // kisa not (eski alan, hala destekli)
 * }
 * ```
 */
data class UpdateInfo(
    val versionCode: Long,
    val versionName: String,
    val apkUrl: String,
    val apkSha256: String,
    val apkSizeBytes: Long,
    val releaseNotes: String,
    val minSdk: Int,
    val forceUpdate: Boolean = false,
    val changelog: String = ""
) {
    /** Kullaniciya gosterilecek metin: varsa detayli changelog, yoksa kisa not. */
    val displayNotes: String get() = changelog.ifBlank { releaseNotes }

    fun toJson(): String = JSONObject().apply {
        put(FIELD_VERSION_CODE, versionCode)
        put(FIELD_VERSION_NAME, versionName)
        put(FIELD_APK_URL, apkUrl)
        put(FIELD_APK_SHA256, apkSha256)
        put(FIELD_APK_SIZE, apkSizeBytes)
        put(FIELD_RELEASE_NOTES, releaseNotes)
        put(FIELD_MIN_SDK, minSdk)
        put(FIELD_FORCE_UPDATE, forceUpdate)
        put(FIELD_CHANGELOG, changelog)
    }.toString()

    companion object {
        const val FIELD_VERSION_CODE = "versionCode"
        const val FIELD_VERSION_NAME = "versionName"
        const val FIELD_APK_URL = "apkUrl"
        const val FIELD_APK_SHA256 = "apkSha256"
        const val FIELD_APK_SIZE = "apkSizeBytes"
        const val FIELD_RELEASE_NOTES = "releaseNotes"
        const val FIELD_MIN_SDK = "minSdk"
        const val FIELD_FORCE_UPDATE = "forceUpdate"
        const val FIELD_CHANGELOG = "changelog"

        private val HEX64 = Regex("[0-9a-f]{64}")

        /**
         * Manifest baytlarini ayristirir. Eksik/gecersiz alan varsa
         * [IllegalArgumentException] firlatir; cagiran taraf bunu "manifest reddedildi"
         * olarak ele alir (asla sessizce varsayilan uretmez).
         *
         * `forceUpdate` ve `changelog` opsiyoneldir; eski manifestlerle geriye uyumludur.
         */
        fun parse(metadata: ByteArray): UpdateInfo {
            val root = JSONObject(String(metadata, Charsets.UTF_8))

            val versionCode = root.optLong(FIELD_VERSION_CODE, Long.MIN_VALUE)
            require(versionCode > 0L) { "versionCode gecerli bir pozitif tamsayi olmali" }

            val versionName = root.optString(FIELD_VERSION_NAME).trim()
            require(versionName.isNotBlank()) { "versionName bos olamaz" }

            val apkUrl = root.optString(FIELD_APK_URL).trim()
            require(apkUrl.isNotBlank()) { "apkUrl bos olamaz" }

            val sha256 = root.optString(FIELD_APK_SHA256).trim().lowercase()
            require(HEX64.matches(sha256)) { "apkSha256 tam olarak 64 kucuk harf hex karakter olmali" }

            val size = root.optLong(FIELD_APK_SIZE, Long.MIN_VALUE)
            require(size > 0L) { "apkSizeBytes gecerli bir pozitif sayi olmali" }

            val minSdk = root.optInt(FIELD_MIN_SDK, 0)
            require(minSdk >= 0) { "minSdk gecerli olmali" }

            return UpdateInfo(
                versionCode = versionCode,
                versionName = versionName,
                apkUrl = apkUrl,
                apkSha256 = sha256,
                apkSizeBytes = size,
                releaseNotes = root.optString(FIELD_RELEASE_NOTES).trim(),
                minSdk = minSdk,
                forceUpdate = root.optBoolean(FIELD_FORCE_UPDATE, false),
                changelog = root.optString(FIELD_CHANGELOG).trim()
            )
        }

        /** [OtaStore] kalicilama icin: kaydedilmis JSON'i geri okur. */
        fun fromJson(raw: String): UpdateInfo = parse(raw.toByteArray(Charsets.UTF_8))
    }
}
