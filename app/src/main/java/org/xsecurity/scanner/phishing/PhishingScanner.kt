package org.xsecurity.scanner.phishing

/**
 * Metin -> bulgu listesi (**saf** orkestrasyon, test edilir): baglanti cikar,
 * her birini blok listesi + sezgisellerle degerlendir.
 */
object PhishingScanner {

    fun scanText(text: String, blocklist: Set<String>): List<PhishingHeuristics.Finding> =
        UrlExtractor.extract(text).map { url ->
            val host = PhishingHeuristics.hostOf(url)
            PhishingHeuristics.evaluate(url, PhishingBlocklist.matches(host, blocklist))
        }
}
