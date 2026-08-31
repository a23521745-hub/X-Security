package org.xsecurity.scanner.definitions

import org.json.JSONArray
import org.json.JSONObject
import org.xsecurity.scanner.data.SignatureStore

/**
 * Sunucudan gelen **imzali** tanim paketi bildirimi (definitions.json).
 *
 * Guvenlik kontrati [org.xsecurity.scanner.ota.UpdateInfo] ile aynidir:
 *  - Bu sinif yalnizca [DefinitionsChecker] icinde, manifestin RSA-SHA256
 *    imzasi dogrulandiktan SONRA uretilir; imzasiz/bozuk manifest asla bu
 *    nesneye donusmez.
 *  - Imza, dosyanin **ham baytlari** uzerinden dogrulanir; kanoniklestirme yoktur.
 *  - Alanlar beyaz listedir; bilinmeyen alanlar yok sayilir, eksik/gecersiz
 *    alan ise [IllegalArgumentException] firlatir (cagiran "reddedildi" der).
 *
 * Desteklenen sema (tumu denetlenir):
 * ```
 * {
 *   "schemaVersion": 1,
 *   "defVersion": 3,                  // pozitif tamsayi; yukselmek zorunda
 *   "minAppVersionCode": 8,           // bu paketin istedigi en dusuk uygulama surumu
 *   "generatedAt": "2026-08-29T12:00:00Z",
 *   "files": [
 *     {
 *       "kind": "YARA",               // "YARA" | "CLAM_AV" | "CLAM_HASHES"; her tur en fazla bir kez
 *       "name": "rules.yar",
 *       "url": "https://github.com/.../rules.yar",
 *       "sha256": "<64 karakter kucuk harf hex>",
 *       "sizeBytes": 12345
 *     }
 *   ]
 * }
 * ```
 */
data class DefinitionsManifest(
    val schemaVersion: Int,
    val defVersion: Int,
    val minAppVersionCode: Long,
    val generatedAt: String,
    val files: List<FileEntry>
) {

    data class FileEntry(
        val kind: SignatureStore.Kind,
        val name: String,
        val url: String,
        val sha256: String,
        val sizeBytes: Long
    )

    fun toJson(): String = JSONObject().apply {
        put(FIELD_SCHEMA_VERSION, schemaVersion)
        put(FIELD_DEF_VERSION, defVersion)
        put(FIELD_MIN_APP_VERSION, minAppVersionCode)
        put(FIELD_GENERATED_AT, generatedAt)
        put(FIELD_FILES, JSONArray().apply {
            for (file in files) {
                put(JSONObject().apply {
                    put(FIELD_KIND, file.kind.name)
                    put(FIELD_NAME, file.name)
                    put(FIELD_URL, file.url)
                    put(FIELD_SHA256, file.sha256)
                    put(FIELD_SIZE, file.sizeBytes)
                })
            }
        })
    }.toString()

    companion object {
        const val FIELD_SCHEMA_VERSION = "schemaVersion"
        const val FIELD_DEF_VERSION = "defVersion"
        const val FIELD_MIN_APP_VERSION = "minAppVersionCode"
        const val FIELD_GENERATED_AT = "generatedAt"
        const val FIELD_FILES = "files"
        const val FIELD_KIND = "kind"
        const val FIELD_NAME = "name"
        const val FIELD_URL = "url"
        const val FIELD_SHA256 = "sha256"
        const val FIELD_SIZE = "sizeBytes"

        /** Bu istemcinin anladigi tek sema surumu. */
        const val CURRENT_SCHEMA_VERSION = 1

        private val HEX64 = Regex("[0-9a-f]{64}")

        fun parse(bytes: ByteArray): DefinitionsManifest {
            val root = JSONObject(String(bytes, Charsets.UTF_8))

            val schemaVersion = root.optInt(FIELD_SCHEMA_VERSION, 0)
            require(schemaVersion == CURRENT_SCHEMA_VERSION) {
                "schemaVersion $schemaVersion desteklenmiyor (beklenen: $CURRENT_SCHEMA_VERSION)"
            }

            val defVersion = root.optInt(FIELD_DEF_VERSION, 0)
            require(defVersion > 0) { "defVersion pozitif bir tamsayi olmali" }

            val minAppVersionCode = root.optLong(FIELD_MIN_APP_VERSION, 0L)
            require(minAppVersionCode >= 0L) { "minAppVersionCode gecerli olmali" }

            val filesArray = root.optJSONArray(FIELD_FILES)
                ?: throw IllegalArgumentException("files dizisi zorunludur")
            require(filesArray.length() > 0) { "files bos olamaz" }

            val files = ArrayList<FileEntry>(filesArray.length())
            val seenKinds = HashSet<SignatureStore.Kind>()
            for (index in 0 until filesArray.length()) {
                val entry = filesArray.getJSONObject(index)

                val kindName = entry.optString(FIELD_KIND).trim().uppercase()
                val kind = SignatureStore.Kind.values().firstOrNull { it.name == kindName }
                    ?: throw IllegalArgumentException("files[$index].kind bilinmiyor: $kindName")
                require(kind !in seenKinds) { "files[$index].kind ikinci kez verildi: $kindName" }
                seenKinds += kind

                val name = entry.optString(FIELD_NAME).trim()
                require(name.isNotBlank()) { "files[$index].name bos olamaz" }

                val url = entry.optString(FIELD_URL).trim()
                require(url.isNotBlank()) { "files[$index].url bos olamaz" }

                val sha256 = entry.optString(FIELD_SHA256).trim().lowercase()
                require(HEX64.matches(sha256)) {
                    "files[$index].sha256 tam olarak 64 kucuk harf hex karakter olmali"
                }

                val sizeBytes = entry.optLong(FIELD_SIZE, Long.MIN_VALUE)
                require(sizeBytes > 0L) { "files[$index].sizeBytes pozitif olmali" }

                files += FileEntry(
                    kind = kind,
                    name = name,
                    url = url,
                    sha256 = sha256,
                    sizeBytes = sizeBytes
                )
            }

            return DefinitionsManifest(
                schemaVersion = schemaVersion,
                defVersion = defVersion,
                minAppVersionCode = minAppVersionCode,
                generatedAt = root.optString(FIELD_GENERATED_AT).trim(),
                files = files
            )
        }

        /** [DefinitionsStore] kalicilama icin: kaydedilmis JSON'i geri okur. */
        fun fromJson(raw: String): DefinitionsManifest = parse(raw.toByteArray(Charsets.UTF_8))
    }
}
