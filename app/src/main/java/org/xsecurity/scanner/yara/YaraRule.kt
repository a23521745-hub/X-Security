package org.xsecurity.scanner.yara

/**
 * Parse edilmis YARA kurali.
 *
 * [approximateCondition] `true` ise `condition:` tam cozumlenememis ve muhafazakar bir
 * varsayilana (`any of them`) dusurulmustur. Boyle kurallar raporda ayrica sayilir;
 * kullanicuya "kural motoru sinirli" dedirtmek icin degil, hangi kuralların tam
 * anlamda taranmadigini gostermek icin.
 */
class YaraRule(
    val name: String,
    val strings: List<YaraString>,
    val condition: YaraCondition,
    val approximateCondition: Boolean = false,
    /** Kuralin `meta:` bolumunden alinan `description` varsa. */
    val description: String? = null
) {
    val stringIdentifiers: Set<String> = strings.map { it.identifier }.toSet()
}
