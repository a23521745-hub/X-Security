package org.xsecurity.scanner.community

import android.content.Context
import org.json.JSONObject
import java.io.IOException

/**
 * **Dogrudan topluluk kaynaklari** kayit defteri.
 *
 * Imzali tanim kanali ([org.xsecurity.scanner.definitions]) bizim RSA anahtarimizla
 * imzalanan paketleri dagitir. Bu sinif ise farkli bir ihtiyaci karsilar: kullanicinin
 * "guncelle" dugmesine basmasiyla uygulamanin, **aktif bakimda olan topluluk
 * repolarindan** (bkz. assets/community-sources.json) dogrudan yeni imza/yar
 * indirmesi. Guvenlik modeli farklidir ve kartta acikca boyle beyan edilir:
 *
 *  - Kaynak listesi APK'ya **gomuludur** (URL'ler distan degistirilemez; degisiklik
 *    yalnizca imzali kanal guncellemesiyle gelir).
 *  - Tum baglantilar [org.xsecurity.scanner.ota.UrlPolicy] izin listesinden gecer
 *    (yalnizca https, yalnizca bilinen hostlar; yonlendirme bile yeniden denetlenir).
 *  - Inen icerik **bicim dogrulamasindan** gecer: hash kaynagi [EchapCsvToHsb] ile
 *    duz-metin .hsb satirlarina donusturulup [org.xsecurity.scanner.clamav.ClamHashDatabaseParser]
 *    ile ayristirilir; YARA kaynagi [org.xsecurity.scanner.yara.YaraRuleParser] ile
 *    sinanir. Ayristirilamayan icerik kurulmaz.
 *  - Kayit basina giris siniri ([maxEntries]) ve toplam indirime boyut siniri vardir.
 *
 * Boylece bir kaynak repo_su ele gecirilse bile saldirganin yapabilecekleri
 * sinirlidir: motor yalnizca dogrulanmis bicimdeki imza/kural metnini okur; kod
 * calistiramaz. Ticari anahtar gerektiren kaynaklar (MalwareBazaar/ThreatFox API'si
 * Auth-Key ister) bilincli olarak bu listeye alinmamistir.
 */
data class CommunitySource(
    val id: String,
    val kind: Kind,
    val label: String,
    val detail: String,
    val url: String,
    val namePrefix: String,
    val maxEntries: Int,
    val enabledByDefault: Boolean,
    val license: String,
    val attribution: String
) {

    enum class Kind {
        /** CSV indirip cihazda .hsb satirlarina cevirir (samples.csv bicimi). */
        HSB_FROM_CSV,

        /** Hazir YARA kural dosyasi; parser'in destekledigi alt kume sinanarak kurulur. */
        YARA
    }

    companion object {
        const val ASSET_PATH = "community-sources.json"

        /**
         * Kayit defterini APK assets'inden okur. Kayit defteri bizim kontrolumuzde
         * oldugu icin bilinmeyen tur/alan tasarlanmis bir sekilde reddedilir.
         */
        fun load(context: Context): List<CommunitySource> {
            val bytes = try {
                context.assets.open(ASSET_PATH).use { it.readBytes() }
            } catch (error: IOException) {
                throw IOException("Topluluk kaynaklari kayit defteri okunamadi: $ASSET_PATH", error)
            }
            return fromJson(String(bytes, Charsets.UTF_8))
        }

        fun fromJson(raw: String): List<CommunitySource> {
            val root = JSONObject(raw) // STRICT modda calisir; bozuk JSON exception firlatir
            val schemaVersion = root.optInt("schemaVersion", 0)
            require(schemaVersion == 1) { "community-sources schemaVersion desteklenmiyor: $schemaVersion" }
            val array = root.optJSONArray("sources")
                ?: throw IllegalArgumentException("community-sources: sources dizisi zorunlu")
            require(array.length() > 0) { "community-sources: en az bir kaynak tanimlanmali" }

            val out = ArrayList<CommunitySource>(array.length())
            val seen = HashSet<String>()
            for (index in 0 until array.length()) {
                val entry = array.getJSONObject(index)
                val id = entry.optString("id").trim()
                require(id.isNotBlank()) { "community-sources[$index].id bos olamaz" }
                require(id !in seen) { "community-sources[$index].id tekrar ediyor: $id" }
                seen += id

                val kindName = entry.optString("kind").trim().uppercase()
                val kind = Kind.values().firstOrNull { it.name == kindName }
                    ?: throw IllegalArgumentException("community-sources[$index].kind bilinmiyor: $kindName")

                val url = entry.optString("url").trim()
                require(url.startsWith("https://")) {
                    "community-sources[$index].url yalnizca https olabilir: $url"
                }
                val maxEntries = entry.optInt("maxEntries", 0)
                require(maxEntries in 1..ClamHashCap.HARD_LIMIT) {
                    "community-sources[$index].maxEntries 1..${ClamHashCap.HARD_LIMIT} araliginda olmali"
                }

                out += CommunitySource(
                    id = id,
                    kind = kind,
                    label = entry.optString("label").ifBlank { id },
                    detail = entry.optString("detail"),
                    url = url,
                    namePrefix = entry.optString("namePrefix"),
                    maxEntries = maxEntries,
                    enabledByDefault = entry.optBoolean("enabledByDefault", false),
                    license = entry.optString("license"),
                    attribution = entry.optString("attribution")
                )
            }
            return out
        }
    }
}

/** Kaynak basina uygulanacak mutlak tavan (motorun genel limitiyle uyumlu). */
object ClamHashCap {
    const val HARD_LIMIT: Int = 200_000
}
