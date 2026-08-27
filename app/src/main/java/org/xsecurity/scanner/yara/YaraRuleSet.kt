package org.xsecurity.scanner.yara

/**
 * YARA kural dosyasindan okunan sonuc + neyin kaybedildiginin dökümü.
 *
 * Onceki surum parse edilemeyen her seyi **sessizce** atiyordu. Artik sayaclar ve
 * insan-okur uyari listesi tasiniyor; UI/rapor bunlari gosteriyor.
 */
class YaraRuleSet(
    val rules: List<YaraRule>,
    /** Hic yuklenemeyen kural sayisi (parser hatasi, bos strings bolumu vb.). */
    val unparsableRules: Int = 0,
    /** Kurali koruyan ama bizce taranamayan string sayisi (regex, xor, base64, fullword). */
    val unsupportedStrings: Int = 0,
    /** `condition:` cozumlenemeyip `any of them` varsayilan kurallar. */
    val approximateConditions: Int = 0,
    /** Yalnizca `filesize`/`uint16` gibi desteklenmeyen kosullari olan, tamamen atlanan kurallar. */
    val skippedRuleNames: List<String> = emptyList(),
    val problems: List<String> = emptyList()
) {
    val ruleCount: Int get() = rules.size
    val isPartial: Boolean
        get() = unparsableRules > 0 || unsupportedStrings > 0 || approximateConditions > 0 || skippedRuleNames.isNotEmpty()

    companion object {
        val EMPTY = YaraRuleSet(emptyList())
    }
}
