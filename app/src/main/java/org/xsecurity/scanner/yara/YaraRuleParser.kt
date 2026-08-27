package org.xsecurity.scanner.yara

import org.xsecurity.scanner.core.SignatureDatabaseException
import org.xsecurity.scanner.matcher.HexPatternCodec
import java.io.File

/**
 * YARA kural dosyasi cozumleyici.
 *
 * Onceki surum satir bazli kaba eslesmelerle (`startsWith("rule ")`, `line == "}"`)
 * calisiyordu; bu yuzden
 *  - `private rule` / `global rule` ile baslayan kurallar,
 *  - tek satira yazilmis kurallar,
 *  - hex (`{ ... }`) ve regex (`/ ... /`) string iceren kurallar,
 *  - `\xNN` kacis iceren stringler
 *  ya tamamen kayboluyor ya da bozuk kalip uretiyordu. Artik karakter duzeyinde,
 *  string/regex/yorum ayriminda bir gezginle parse ediliyor; cozumlenemeyen her sey
 *  sayacla raporlaniyor (sessiz eleme yok).
 */
class YaraRuleParser(
    private val maxSourceBytes: Long = DEFAULT_MAX_SOURCE_BYTES
) {

    fun parse(ruleFile: File): YaraRuleSet {
        if (!ruleFile.isFile) {
            throw SignatureDatabaseException("YARA rule file not found: ${ruleFile.absolutePath}")
        }
        val size = ruleFile.length()
        if (size > maxSourceBytes) {
            throw SignatureDatabaseException(
                "YARA rule file exceeds the size limit: $size > $maxSourceBytes bytes (${ruleFile.name})"
            )
        }
        val source = try {
            ruleFile.readText(Charsets.UTF_8)
        } catch (error: Exception) {
            throw SignatureDatabaseException("YARA rule file could not be read: ${ruleFile.absolutePath}", error)
        }
        val set = parseSource(source)
        if (set.rules.isEmpty()) {
            throw SignatureDatabaseException(
                "YARA file contains no scannable rules (${ruleFile.name}, $size bytes; " +
                    "unparsable rules=${set.unparsableRules}, unsupported strings=${set.unsupportedStrings})" +
                    problemSuffix(set)
            )
        }
        return set
    }

    fun parseSource(source: String): YaraRuleSet {
        val text = stripComments(source)
        val rules = ArrayList<YaraRule>()
        val problems = ArrayList<String>()
        val skipped = ArrayList<String>()
        var unparsable = 0
        var unsupportedStrings = 0
        var approximate = 0

        val cursor = Cursor(text)
        var depth = 0
        while (!cursor.atEnd) {
            val ch = cursor.peek()
            when {
                ch == '"' -> cursor.skipQuoted()
                ch == '{' -> {
                    depth++
                    cursor.advance()
                }
                ch == '}' -> {
                    if (depth > 0) depth--
                    cursor.advance()
                }
                depth == 0 && Cursor.isIdentStart(ch) -> {
                    val word = cursor.readWord()
                    if (word == "rule") {
                        when (val outcome = parseRule(cursor)) {
                            is RuleOutcome.Ok -> {
                                rules += outcome.rule
                                unsupportedStrings += outcome.unsupportedStrings
                                if (outcome.rule.approximateCondition) approximate++
                            }
                            is RuleOutcome.Failed -> {
                                unparsable++
                                unsupportedStrings += outcome.unsupportedStrings
                                outcome.ruleName?.let { skipped += it }
                                if (problems.size < MAX_PROBLEMS && outcome.reason != null) {
                                    problems += "${outcome.ruleName ?: "(isimsiz kural)"}: ${outcome.reason}"
                                }
                            }
                        }
                        depth = 0
                    } else if (word == "import" || word == "include") {
                        cursor.skipToLineEnd()
                    }
                    // private / global / abstract modifier'lari yok sayilir; sonraki
                    // yineleme "rule" kelimesini yakalar.
                }
                else -> cursor.advance()
            }
        }

        return YaraRuleSet(rules, unparsable, unsupportedStrings, approximate, skipped, problems)
    }

    // --- Kural govdesi ------------------------------------------------------

    private sealed class RuleOutcome {
        class Ok(val rule: YaraRule, val unsupportedStrings: Int) : RuleOutcome()
        class Failed(
            val ruleName: String?,
            val reason: String?,
            val unsupportedStrings: Int = 0
        ) : RuleOutcome()
    }

    private fun parseRule(c: Cursor): RuleOutcome {
        c.skipWhitespace()
        val name = c.readWord()
        if (name.isEmpty()) return RuleOutcome.Failed(null, "'rule' kelimesinden sonra kimlik okunamadi")

        c.skipWhitespace()
        if (c.peek() == ':') {
            // Etiketler: `rule Foo : tag1 tag2 {`
            c.advance()
            while (!c.atEnd && c.peek() != '{') c.advance()
        }
        c.skipWhitespace()
        if (c.peek() != '{') return RuleOutcome.Failed(name, "kural govdesi '{' ile baslamiyor")
        c.advance()
        val body = c.readBracedBody()
            ?: return RuleOutcome.Failed(name, "kural govdesi kapanis kiraji bulunamiyor")

        var stringsSection: String? = null
        var conditionSection: String? = null
        var description: String? = null
        for (section in splitSections(body)) {
            when (section.first) {
                "strings" -> stringsSection = section.second
                "condition" -> conditionSection = section.second
                "meta" -> description = findMetaString(section.second, "description") ?: description
            }
        }

        val stringsOutcome = stringsSection?.let { parseStringsSection(it) }
            ?: StringsOutcome(emptyList(), 0)
        if (stringsOutcome.strings.isEmpty()) {
            val reason = if (stringsSection == null) {
                "strings: bolumu yok"
            } else {
                "kuralda desteklenen string kalmadi (regex/xor/base64/fullword veya parse hatasi)"
            }
            return RuleOutcome.Failed(name, reason, stringsOutcome.unsupported)
        }

        val condition = parseCondition(conditionSection ?: "")
        val rule = YaraRule(
            name = name,
            strings = stringsOutcome.strings,
            condition = condition.condition,
            approximateCondition = condition.approximate,
            description = description
        )
        return RuleOutcome.Ok(rule, stringsOutcome.unsupported)
    }

    // --- strings: bolumu ---------------------------------------------------

    internal class StringsOutcome(
        val strings: List<YaraString>,
        val unsupported: Int
    )

    internal fun parseStringsSection(section: String): StringsOutcome {
        val c = Cursor(section)
        val out = ArrayList<YaraString>()
        var unsupported = 0

        while (!c.atEnd) {
            c.skipWhitespace()
            if (c.atEnd) break
            val ch = c.peek()
            if (ch == '}') {
                c.advance()
                continue
            }
            if (ch != '$') {
                if (Cursor.isIdentStart(ch)) c.readWord() else c.advance()
                continue
            }
            c.advance()
            val identifier = c.readWord()
            if (identifier.isEmpty()) {
                unsupported++
                c.skipToLineEnd()
                continue
            }
            c.skipWhitespace()
            val afterName = c.peek()
            if (afterName == '[' || afterName == '*') {
                // string dizileri: `$a[1] = "x"` / `$a* = { 41 }`
                unsupported++
                c.skipToLineEnd()
                continue
            }
            if (afterName != '=') {
                unsupported++
                c.skipToLineEnd()
                continue
            }
            c.advance()
            c.skipWhitespace()

            when (c.peek()) {
                '"' -> {
                    val bytes = c.readQuotedBytes()
                    if (bytes == null) {
                        unsupported++
                        c.skipToLineEnd()
                        continue
                    }
                    val mods = c.readModifiers()
                    if (mods.unsupportedName != null) {
                        unsupported++
                        continue
                    }
                    out += YaraString(
                        identifier = identifier,
                        bytes = bytes,
                        mask = null,
                        isText = true,
                        ascii = mods.ascii,
                        wide = mods.wide,
                        nocase = mods.nocase
                    )
                }
                '{' -> {
                    c.advance()
                    val hex = c.readUntilMatchingBrace()
                    if (hex == null) {
                        unsupported++
                        continue
                    }
                    if (HexPatternCodec.looksUnsupported(hex)) {
                        unsupported++
                        continue
                    }
                    val decoded = HexPatternCodec.decode(hex)
                    if (decoded == null) {
                        unsupported++
                        continue
                    }
                    val mods = c.readModifiers()
                    if (mods.unsupportedName != null) {
                        unsupported++
                        continue
                    }
                    out += YaraString(
                        identifier = identifier,
                        bytes = decoded.bytes,
                        mask = decoded.mask,
                        isText = false
                    )
                }
                '/' -> {
                    unsupported++
                    c.skipRegexLiteral()
                }
                else -> {
                    unsupported++
                    c.skipToLineEnd()
                }
            }
        }
        return StringsOutcome(out, unsupported)
    }

    // --- condition: bolumu -------------------------------------------------

    internal class ConditionOutcome(val condition: YaraCondition, val approximate: Boolean)

    internal fun parseCondition(section: String): ConditionOutcome {
        val tokens = tokenize(section)
        if (tokens.isEmpty()) return ConditionOutcome(YaraCondition.Never, false)

        val ofIndex = tokens.indexOfFirst { it.equals("of", ignoreCase = true) }
        if (ofIndex > 0) {
            val quantifier = tokens[ofIndex - 1]
            val tail = tokens.subList(ofIndex + 1, tokens.size)
            val isThem = tail.size == 1 && tail[0].equals("them", ignoreCase = true)
            if (isThem) {
                return when {
                    quantifier.equals("any", ignoreCase = true) -> ConditionOutcome(YaraCondition.AnyOfThem, false)
                    quantifier.equals("all", ignoreCase = true) -> ConditionOutcome(YaraCondition.AllOfThem, false)
                    quantifier.equals("none", ignoreCase = true) -> ConditionOutcome(YaraCondition.NoneOfThem, false)
                    else -> {
                        val n = quantifier.toIntOrNull()
                        if (n != null && n >= 0) {
                            ConditionOutcome(YaraCondition.CountOfThem(n), false)
                        } else {
                            approximateFallback()
                        }
                    }
                }
            }
            if (tail.size >= 3 && tail[0] == "(" && tail[tail.size - 1] == ")") {
                val selectors = tail.subList(1, tail.size - 1).filter { it != "," }
                if (selectors.isNotEmpty() && selectors.all { isSelectorToken(it) }) {
                    val cleaned = selectors.map { stripDollar(it) }
                    val mode = when {
                        quantifier.equals("any", ignoreCase = true) -> YaraCondition.OfThem.Mode.ANY
                        quantifier.equals("all", ignoreCase = true) -> YaraCondition.OfThem.Mode.ALL
                        quantifier.equals("none", ignoreCase = true) -> YaraCondition.OfThem.Mode.NONE
                        else -> null
                    }
                    if (mode != null) {
                        return ConditionOutcome(YaraCondition.OfThem(mode, 0, cleaned), false)
                    }
                    val n = quantifier.toIntOrNull()
                    if (n != null && n >= 0) {
                        return ConditionOutcome(
                            YaraCondition.OfThem(YaraCondition.OfThem.Mode.COUNT, n, cleaned),
                            false
                        )
                    }
                }
            }
            return approximateFallback()
        }

        // Duz boolean zinciri: $a and $b, $a or $b, not $a ...
        val terms = ArrayList<Term>()
        var operator: String? = null
        var index = 0
        var valid = true
        while (index < tokens.size) {
            var negated = false
            if (tokens[index].equals("not", ignoreCase = true)) {
                negated = true
                index++
            }
            if (index >= tokens.size) {
                valid = false
                break
            }
            val token = tokens[index]
            if (!isSelectorToken(token) || token.endsWith("*")) {
                valid = false
                break
            }
            terms += Term(stripDollar(token), negated)
            index++
            if (index < tokens.size) {
                val op = tokens[index]
                val normalised = when {
                    op.equals("and", ignoreCase = true) -> "and"
                    op.equals("or", ignoreCase = true) -> "or"
                    else -> null
                }
                if (normalised == null) {
                    valid = false
                    break
                }
                if (operator == null) {
                    operator = normalised
                } else if (operator != normalised) {
                    valid = false
                    break
                }
                index++
                if (index >= tokens.size) {
                    valid = false
                    break
                }
            }
        }
        if (!valid || terms.isEmpty()) return approximateFallback()
        return if (operator == "and") {
            ConditionOutcome(YaraCondition.AndTerms(terms), false)
        } else {
            ConditionOutcome(YaraCondition.OrTerms(terms), false)
        }
    }

    /**
     * Cozumlenemeyen kosul kurali dusturmek yerine muhafazakar `any of them` varsayilanina
     * dusurulur ve `approximateCondition` ile raporlanir.
     */
    private fun approximateFallback() = ConditionOutcome(YaraCondition.AnyOfThem, true)

    private fun isSelectorToken(token: String): Boolean {
        if (!token.startsWith("$") || token.length < 2) return false
        val body = if (token.endsWith("*")) token.substring(1, token.length - 1) else token.substring(1)
        if (body.isEmpty()) return false
        return body.all { it.isLetterOrDigit() || it == '_' }
    }

    private fun stripDollar(token: String): String = token.removePrefix("$").removeSuffix("*")

    private fun tokenize(text: String): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        for (ch in text) {
            if (ch == '$' || ch == '(' || ch == ')' || ch == ',' || ch == ';' || ch.isWhitespace()) {
                if (sb.isNotEmpty()) {
                    out += sb.toString()
                    sb.setLength(0)
                }
                when (ch) {
                    '$' -> sb.append('$')
                    '(', ')', ',' -> out += ch.toString()
                }
            } else {
                sb.append(ch)
            }
        }
        if (sb.isNotEmpty()) out += sb.toString()
        return out
    }

    // --- Meta -------------------------------------------------------------

    private fun findMetaString(section: String, key: String): String? {
        for (rawLine in section.lineSequence()) {
            val line = rawLine.trim()
            if (!line.startsWith(key, ignoreCase = true)) continue
            val afterKey = line.substring(key.length).trimStart()
            if (!afterKey.startsWith("=")) continue
            val value = afterKey.substring(1).trim()
            if (!value.startsWith("\"")) continue
            val bytes = Cursor.readQuoted(value, 0)?.first ?: continue
            return String(bytes, Charsets.UTF_8)
        }
        return null
    }

    // --- Gezgin -------------------------------------------------------------

    internal class Cursor(val text: String) {
        var i: Int = 0

        val atEnd: Boolean get() = i >= text.length
        fun peek(): Char = if (atEnd) ' ' else text[i]
        fun advance() {
            i++
        }

        fun skipWhitespace() {
            while (!atEnd && text[i].isWhitespace()) i++
        }

        fun skipToLineEnd() {
            while (!atEnd && text[i] != '\n') i++
        }

        fun readWord(): String {
            val start = i
            while (!atEnd && isIdentPart(text[i])) i++
            return text.substring(start, i)
        }

        fun skipQuoted() {
            i = skipQuotedIn(text, i)
        }

        /** '"' ile başlayan literalin baytlarini okur ve indeksi kapatandan sonrasina alir. */
        fun readQuotedBytes(): ByteArray? {
            if (peek() != '"') return null
            val result = readQuoted(text, i) ?: return null
            i = result.second
            return result.first
        }

        /**
         * '{' tuketilmis varsayimiyla esleşen '}'-a kadar govdeyi okur ve kiraci tuketir.
         * Tırnakli stringleri atlar, ic ice parantezleri sayar.
         */
        fun readBracedBody(): String? {
            val start = i
            var depth = 1
            while (!atEnd) {
                val ch = text[i]
                when {
                    ch == '"' -> i = skipQuotedIn(text, i)
                    ch == '{' -> {
                        depth++
                        i++
                    }
                    ch == '}' -> {
                        depth--
                        if (depth == 0) {
                            val body = text.substring(start, i)
                            i++
                            return body
                        }
                        i++
                    }
                    else -> i++
                }
            }
            return null
        }

        fun readUntilMatchingBrace(): String? {
            val start = i
            while (!atEnd) {
                if (text[i] == '}') {
                    val value = text.substring(start, i)
                    i++
                    return value
                }
                i++
            }
            return null
        }

        internal class Mods(
            val ascii: Boolean,
            val wide: Boolean,
            val nocase: Boolean,
            val unsupportedName: String?
        )

        /** `ascii wide nocase ...` modifier zincirini okur; taninmayanda indeksi geri alir. */
        fun readModifiers(): Mods {
            var ascii = false
            var wide = false
            var nocase = false
            var unsupported: String? = null
            while (true) {
                val mark = i
                skipWhitespace()
                if (atEnd || !isIdentStart(peek())) {
                    i = mark
                    break
                }
                val word = readWord()
                when (word.lowercase()) {
                    "ascii" -> ascii = true
                    "wide" -> wide = true
                    "nocase" -> nocase = true
                    "fullword", "xor", "base64", "base64wide" -> {
                        unsupported = word.lowercase()
                        i = mark
                    }
                    else -> i = mark
                }
                if (unsupported != null || i == mark) break
            }
            // YARA: ascii/wide hic verilmediyse varsayilan ascii'dir.
            val effectiveAscii = if (unsupported == null) (ascii || !wide) else false
            return Mods(
                ascii = effectiveAscii,
                wide = wide,
                nocase = nocase,
                unsupportedName = unsupported
            )
        }

        fun skipRegexLiteral() {
            if (peek() != '/') return
            advance()
            var escaped = false
            var inClass = false
            while (!atEnd) {
                val ch = text[i]
                i++
                if (escaped) {
                    escaped = false
                    continue
                }
                when {
                    ch == '\\' -> escaped = true
                    inClass && ch == ']' -> inClass = false
                    ch == '[' -> inClass = true
                    !inClass && ch == '/' -> return
                }
            }
        }

        companion object {
            fun isIdentPart(c: Char): Boolean = c.isLetterOrDigit() || c == '_'
            fun isIdentStart(c: Char): Boolean = c.isLetter() || c == '_'

            fun skipQuotedIn(s: String, from: Int): Int {
                if (from >= s.length || s[from] != '"') return from + 1
                var j = from + 1
                var escaped = false
                while (j < s.length) {
                    val ch = s[j]
                    if (escaped) {
                        escaped = false
                        j++
                        continue
                    }
                    when (ch) {
                        '\\' -> {
                            escaped = true
                            j++
                        }
                        '"' -> return j + 1
                        '\n' -> return j
                        else -> j++
                    }
                }
                return j
            }

            /** from: '"' indeksi. Kapanis kaclirsa veya kacis bozuksa null. */
            fun readQuoted(s: String, from: Int): Pair<ByteArray, Int>? {
                if (from >= s.length || s[from] != '"') return null
                val out = ArrayList<Int>()
                var j = from + 1
                while (j < s.length) {
                    val ch = s[j]
                    if (ch == '"') {
                        return ByteArray(out.size) { index -> out[index].toByte() } to (j + 1)
                    }
                    if (ch == '\n') return null
                    if (ch != '\\') {
                        appendChar(out, ch)
                        j++
                        continue
                    }
                    if (j + 1 >= s.length) return null
                    val e = s[j + 1]
                    j += 2
                    when (e) {
                        'n' -> out += '\n'.code
                        't' -> out += '\t'.code
                        'r' -> out += '\r'.code
                        'f' -> out += 12
                        'v' -> out += 11
                        'a' -> out += 7
                        'b' -> out += 8
                        '"' -> out += '"'.code
                        '\'' -> out += '\''.code
                        '\\' -> out += '\\'.code
                        'x' -> {
                            if (j + 1 >= s.length) return null
                            val hi = hexDigit(s[j])
                            val lo = hexDigit(s[j + 1])
                            if (hi < 0 || lo < 0) return null
                            out += (hi shl 4) or lo
                            j += 2
                        }
                        // YARA'da gecersiz bir kacis; tolerans gosterip literal aliyoruz.
                        else -> appendChar(out, e)
                    }
                }
                return null
            }

            private fun appendChar(out: MutableList<Int>, ch: Char) {
                if (ch.code < 0x80) {
                    out += ch.code
                } else {
                    for (b in ch.toString().encodeToByteArray()) out += b.toInt() and 0xFF
                }
            }

            private fun hexDigit(c: Char): Int = when (c) {
                in '0'..'9' -> c - '0'
                in 'a'..'f' -> c - 'a' + 10
                in 'A'..'F' -> c - 'A' + 10
                else -> -1
            }
        }
    }

    // --- Metin duzeyi yardimcilar -----------------------------------------

    /** Yorumlari kaldirir; tırnaklı stringlere dokunmaz. */
    internal fun stripComments(source: String): String {
        if (!source.contains("//") && !source.contains("/*")) return source
        val out = StringBuilder(source.length)
        var i = 0
        while (i < source.length) {
            val ch = source[i]
            when {
                ch == '"' -> {
                    val end = Cursor.skipQuotedIn(source, i)
                    out.append(source, i, end.coerceAtMost(source.length))
                    i = end
                }
                ch == '/' && i + 1 < source.length && source[i + 1] == '/' -> {
                    while (i < source.length && source[i] != '\n') i++
                    out.append('\n')
                }
                ch == '/' && i + 1 < source.length && source[i + 1] == '*' -> {
                    var j = i + 2
                    while (j + 1 < source.length && !(source[j] == '*' && source[j + 1] == '/')) j++
                    i = (j + 2).coerceAtMost(source.length)
                    out.append(' ')
                }
                else -> {
                    out.append(ch)
                    i++
                }
            }
        }
        return out.toString()
    }

    /** Govdeyi `label: icerik` parcalarina ayirir; string/regex icine girmez. */
    internal fun splitSections(body: String): List<Pair<String, String>> {
        val result = ArrayList<Pair<String, String>>()
        var i = 0
        var depth = 0
        var label: String? = null
        var sectionStart = 0
        val n = body.length
        while (i < n) {
            val ch = body[i]
            when {
                ch == '"' -> i = Cursor.skipQuotedIn(body, i)
                ch == '{' -> {
                    depth++
                    i++
                }
                ch == '}' -> {
                    if (depth > 0) depth--
                    i++
                }
                ch == '/' && isRegexContext(body, i) -> i = skipRegex(body, i)
                depth == 0 && Cursor.isIdentStart(ch) -> {
                    val start = i
                    var j = i
                    while (j < n && Cursor.isIdentPart(body[j])) j++
                    if (j < n && body[j] == ':' && (j + 1 >= n || body[j + 1] != ':')) {
                        if (label != null) {
                            result += label to body.substring(sectionStart, start).trim()
                        }
                        label = body.substring(start, j).lowercase()
                        sectionStart = j + 1
                        i = j + 1
                    } else {
                        i = j
                    }
                }
                else -> i++
            }
        }
        if (label != null) result += label to body.substring(sectionStart, n).trim()
        return result
    }

    /** '/' karakterinden once `=`/`(`/`,` gibi bir regex baglami var mi? */
    private fun isRegexContext(body: String, index: Int): Boolean {
        var j = index - 1
        while (j >= 0 && body[j].isWhitespace()) j--
        if (j < 0) return false
        return when (body[j]) {
            '=', '(', ',', '|', '&', '!', '?', ':' -> true
            else -> false
        }
    }

    private fun skipRegex(body: String, from: Int): Int {
        var j = from + 1
        var escaped = false
        while (j < body.length) {
            val ch = body[j]
            if (escaped) {
                escaped = false
                j++
                continue
            }
            when (ch) {
                '\\' -> {
                    escaped = true
                    j++
                }
                '/' -> return j + 1
                else -> j++
            }
        }
        return body.length
    }

    private fun problemSuffix(set: YaraRuleSet): String =
        if (set.problems.isEmpty()) "" else " | examples: ${set.problems.joinToString(" / ")}"

    companion object {
        const val DEFAULT_MAX_SOURCE_BYTES: Long = 8L * 1024L * 1024L
        private const val MAX_PROBLEMS = 20
    }
}
