package org.xsecurity.scanner.community

import org.xsecurity.scanner.clamav.ClamHashDatabaseParser
import org.xsecurity.scanner.core.SignatureDatabaseException
import org.xsecurity.scanner.yara.YaraRuleParser

/**
 * Ucuncu parti (topluluk) iceriginin ISLENMESI ve DOGRULANMASI — baglamsiz,
 * saf fonksiyonlar. Bu katman, indirilen baytlarin motor tarafindan yuklenebilir
 * oldugunu KANITLAMADAN hicbir icerigin disari cikmamasi gerektiginden sorumludur:
 *
 *  - HSB_FROM_CSV: CSV, .hsb satirlarina cevrilir ve bizzat [ClamHashDatabaseParser]
 *    ile ayristirilir (donusum ciktisi motor sozdizimine uymali).
 *  - YARA: icerik gecici dosyada [YaraRuleParser] ile sinanir; desteklenen alt
 *    kumeden hic kural cikmiyorsa icerik reddedilir.
 *
 * Ayristirma/boyut kurallari [CommunitySource]'in sinirlariyla (maxEntries) uyumludur.
 */
object CommunityValidator {

    class Validated(
        /** Hedef dosyaya atomik olarak yazilacak nihai icerik. */
        val content: String,
        val hashEntries: Int,
        val yaraRules: Int
    )

    fun validate(source: CommunitySource, payload: ByteArray): Validated = when (source.kind) {
        CommunitySource.Kind.HSB_FROM_CSV -> validateHashes(source, payload)
        CommunitySource.Kind.YARA -> validateYara(source, payload)
    }

    private fun validateHashes(source: CommunitySource, payload: ByteArray): Validated {
        val conversion = EchapCsvToHsb.convert(
            csvText = payload.decodeToString(),
            namePrefix = source.namePrefix,
            maxEntries = source.maxEntries
        )
        if (conversion.lines.isEmpty()) {
            throw SignatureDatabaseException(
                "${source.label}: CSV'de gecerli hash satiri yok " +
                    "(${conversion.skippedBadHash} bozuk, ${conversion.skippedNoName} isimsiz satir atlandi)"
            )
        }
        val database = ClamHashDatabaseParser().parseLines(conversion.lines)
        if (database.size == 0) {
            throw SignatureDatabaseException(
                "${source.label}: donusturulen satirlar hash veritabani olarak ayristirilamadi"
            )
        }
        return Validated(
            content = conversion.lines.joinToString("\n", postfix = "\n"),
            hashEntries = database.size,
            yaraRules = 0
        )
    }

    private fun validateYara(source: CommunitySource, payload: ByteArray): Validated {
        val text = payload.decodeToString()
        if (payload.size > YaraRuleParser.DEFAULT_MAX_SOURCE_BYTES) {
            throw SignatureDatabaseException(
                "${source.label}: YARA kaynagi boyut sinirini asiyor " +
                    "(${payload.size} > ${YaraRuleParser.DEFAULT_MAX_SOURCE_BYTES} bayt)"
            )
        }
        val parsed = YaraRuleParser().parseSource(text)
        if (parsed.rules.isEmpty()) {
            throw SignatureDatabaseException(
                "${source.label}: motorun destekledigi sozdiziminde kural cikmadi " +
                    "(${parsed.unparsableRules} ayristirilamayan, ${parsed.skippedRuleNames.size} atlanan)"
            )
        }
        if (parsed.rules.size > source.maxEntries) {
            throw SignatureDatabaseException(
                "${source.label}: kural sayisi tavani asiyo " +
                    "(${parsed.rules.size} > ${source.maxEntries})"
            )
        }
        return Validated(content = text, hashEntries = 0, yaraRules = parsed.rules.size)
    }
}
