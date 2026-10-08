package org.xsecurity.scanner.phishing

/**
 * Duz metinden baglanti cikarma (**saf**, test edilir).
 *
 *  - `http(s)://...` bicimleri + `www.` ile baslayan ciplak alan adlari.
 *  - Sondaki noktalama (cümle sonu `.`, `,`, `!` …) kirpilir.
 *  - Tekrarlar elenir, [MAX_URLS] tavani vardir (yapistirilan devasa metinler
 *    arayuzu kilitlemesin).
 */
object UrlExtractor {

    const val MAX_URLS = 20

    private val SCHEME_PATTERN = Regex("""(?i)\bhttps?://[^\s<>"'()\[\]]+""")
    private val WWW_PATTERN = Regex("""(?i)\bwww\.[^\s<>"'()\[\]]+""")
    private val TRAILING_PUNCTUATION = setOf('.', ',', ';', ':', '!', '?')

    fun extract(text: String, max: Int = MAX_URLS): List<String> {
        if (text.isBlank()) return emptyList()
        val out = LinkedHashSet<String>()
        SCHEME_PATTERN.findAll(text).forEach { match ->
            if (out.size >= max) return out.toList()
            clean(match.value)?.let { out += it }
        }
        if (out.size < max) {
            WWW_PATTERN.findAll(text).forEach { match ->
                if (out.size >= max) return out.toList()
                clean(match.value)?.let { out += it }
            }
        }
        return out.toList()
    }

    private fun clean(raw: String): String? {
        val trimmed = raw.trim().trimEnd { it in TRAILING_PUNCTUATION }
        if (trimmed.isEmpty()) return null
        // `www.` tek basina eslesemez; noktasiz kirpintilar elenir.
        val hostPart = trimmed.substringAfter("://", trimmed).substringBefore('/')
        if (!hostPart.contains('.')) return null
        return trimmed
    }
}
