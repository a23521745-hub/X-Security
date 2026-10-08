package org.xsecurity.scanner.community

/**
 * AssoEchap `samples.csv` icerigini ClamAV `.hsb` satirlarina cevirir.
 *
 * CSV bicimi: `SHA256,Package Name,Certificate,Version,App` (bazi satirlarda son
 * alanlar bos olabilir; tirnak icinde virgul iceren alanlar da desteklenir).
 * Cikti satiri: `<sha256>:-1:<namePrefix><App>` — boyut CSV'de olmadigi icin
 * her zaman "bilinmiyor"dur; hash eslesmesi tek basina yeterlidir.
 *
 * `tools/definitions/update-hash-db.sh` betigindeki Python mantiginin birebir
 * Kotlin karsiligidir; iki tarafin ciktisi ayni satir setini uretir.
 */
object EchapCsvToHsb {

    class Conversion(
        val lines: List<String>,
        val totalRows: Int,
        val skippedBadHash: Int,
        val skippedNoName: Int,
        val duplicates: Int
    )

    private val HEX64 = Regex("[0-9a-fA-F]{64}")

    fun convert(csvText: String, namePrefix: String, maxEntries: Int): Conversion {
        val lines = ArrayList<String>(2048)
        val seen = HashSet<String>()
        var totalRows = 0
        var badHash = 0
        var noName = 0
        var duplicates = 0

        for (rawLine in csvText.lineSequence()) {
            if (rawLine.isBlank()) continue
            val fields = splitCsvLine(rawLine)
            if (fields.isEmpty()) continue

            val sha = fields[0].trim()
            if (!HEX64.matches(sha)) {
                // Baslik satiri ("SHA256,...") buraya duser ve atlanir.
                badHash++
                continue
            }
            val app = fields.getOrNull(4)?.trim() ?: ""
            if (app.isEmpty()) {
                noName++
                continue
            }
            totalRows++
            val key = sha.lowercase()
            if (key in seen) {
                duplicates++
                continue
            }
            seen += key
            val name = namePrefix + sanitize(app)
            lines += "$key:-1:$name"
            if (lines.size >= maxEntries) break
        }

        return Conversion(
            lines = lines,
            totalRows = totalRows,
            skippedBadHash = badHash,
            skippedNoName = noName,
            duplicates = duplicates
        )
    }

    /**
     * Tirnakli alanlari tanıyan minimal CSV ayirici (RFC-4180 alt kumesi:
     * `"a,b"`, `""` kacisi; ayristirilamayan satir bos liste dondurur).
     */
    internal fun splitCsvLine(line: String): List<String> {
        val out = ArrayList<String>(6)
        val current = StringBuilder()
        var inQuotes = false
        var index = 0
        var fieldStarted = false
        while (index <= line.length) {
            val ch = if (index < line.length) line[index] else ','
            when {
                ch == '"' && inQuotes && index + 1 < line.length && line[index + 1] == '"' -> {
                    current.append('"')
                    index++
                }
                ch == '"' -> {
                    inQuotes = !inQuotes
                    fieldStarted = true
                }
                ch == ',' && !inQuotes -> {
                    out += current.toString()
                    current.setLength(0)
                    fieldStarted = false
                }
                else -> {
                    if (index < line.length) {
                        if (ch != '\r') current.append(ch)
                        fieldStarted = true
                    }
                }
            }
            if (index >= line.length) break
            index++
        }
        if (inQuotes) return emptyList() // kapanmamis tirnak: satir bozuk
        if (current.isNotEmpty() || fieldStarted) out += current.toString()
        return out
    }

    /** Imza isminde satir bicimini bozan karakterleri eleyip boslugu temizler. */
    private fun sanitize(app: String): String =
        app.replace(Regex("[\\r\\n\\t:]"), "").trim().ifEmpty { "Unknown" }
}
