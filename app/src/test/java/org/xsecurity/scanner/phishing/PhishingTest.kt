package org.xsecurity.scanner.phishing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.phishing.PhishingHeuristics.Reason
import org.xsecurity.scanner.phishing.PhishingHeuristics.Verdict

/**
 * URL/oltalama taramasinin saf mantigi: cikarma, sezgiseller, blok listesi.
 */
class PhishingTest {

    @Test
    fun extractsSchemeAndWwwLinks() {
        val text = "Merhaba https://ornek.com/kredi?x=1 bak, sonra www.test.org/yol ve bitis."
        assertEquals(
            listOf("https://ornek.com/kredi?x=1", "www.test.org/yol"),
            UrlExtractor.extract(text)
        )
    }

    @Test
    fun trimsTrailingPunctuationAndDedupes() {
        val text = "Tikla: https://a.com/x., sonra yine https://a.com/x ve (https://b.com/y)!"
        assertEquals(listOf("https://a.com/x", "https://b.com/y"), UrlExtractor.extract(text))
    }

    @Test
    fun extractCapsAndIgnoresNonLinks() {
        assertTrue(UrlExtractor.extract("baglanti yok, sadece metin").isEmpty())
        assertTrue(UrlExtractor.extract("").isEmpty())
        val many = (1..30).joinToString(" ") { "https://s$it.com/" }
        assertEquals(UrlExtractor.MAX_URLS, UrlExtractor.extract(many).size)
        assertEquals(2, UrlExtractor.extract(many, max = 2).size)
    }

    @Test
    fun hostParsingLowercasesAndHandlesBareDomains() {
        assertEquals("ornek.com", PhishingHeuristics.hostOf("https://Ornek.COM/yol"))
        assertEquals("www.test.org", PhishingHeuristics.hostOf("www.test.org/yol"))
        assertEquals("evil.com", PhishingHeuristics.hostOf("https://kullanici@evil.com/"))
        assertNull(PhishingHeuristics.hostOf(""))
        assertNull(PhishingHeuristics.hostOf("http://[bozuk"))
    }

    @Test
    fun detectsIpHosts() {
        assertTrue(PhishingHeuristics.isIpHost("192.168.1.1"))
        assertTrue(PhishingHeuristics.isIpHost("10.0.0.255"))
        assertTrue(PhishingHeuristics.isIpHost("[2001:db8::1]"))
        assertFalse(PhishingHeuristics.isIpHost("ornek.com"))
        assertFalse(PhishingHeuristics.isIpHost("999.1.1.1"))
        assertFalse(PhishingHeuristics.isIpHost("1.2.3"))
    }

    @Test
    fun detectsAtSignOnlyInAuthority() {
        assertTrue(PhishingHeuristics.hasAtSign("https://banka.com@kotu.example/giris"))
        assertTrue(PhishingHeuristics.hasAtSign("https://kullanici@kotu.example/"))
        assertFalse(PhishingHeuristics.hasAtSign("https://ornek.com/@kullanici/gonderi"))
        assertFalse(PhishingHeuristics.hasAtSign("https://ornek.com/yol?a=b"))
    }

    @Test
    fun detectsPunycodeAndShorteners() {
        assertTrue(PhishingHeuristics.isPunycode("xn--bcher-kva.example"))
        assertFalse(PhishingHeuristics.isPunycode("ornek.com"))
        assertTrue(PhishingHeuristics.isShortener("bit.ly"))
        assertTrue(PhishingHeuristics.isShortener("x.bit.ly"))
        assertTrue(PhishingHeuristics.isShortener("T.CO"))
        assertFalse(PhishingHeuristics.isShortener("bit.ly.evil.com"))
        assertFalse(PhishingHeuristics.isShortener("ornek.com"))
    }

    @Test
    fun verdictPriorityIsBlocklistThenHeuristics() {
        val blocklisted = PhishingHeuristics.evaluate("https://kotu.example/g", blocklisted = true)
        assertEquals(Verdict.MALICIOUS, blocklisted.verdict)
        assertTrue(blocklisted.reasons.contains(Reason.BLOCKLISTED))

        val ip = PhishingHeuristics.evaluate("http://192.168.1.1/giris", blocklisted = false)
        assertEquals(Verdict.SUSPICIOUS, ip.verdict)
        assertTrue(ip.reasons.contains(Reason.IP_HOST))

        val multi = PhishingHeuristics.evaluate("http://a@10.0.0.1/x", blocklisted = false)
        assertTrue(multi.reasons.containsAll(listOf(Reason.IP_HOST, Reason.AT_SIGN)))

        val safe = PhishingHeuristics.evaluate("https://ornek.com/hesap", blocklisted = false)
        assertEquals(Verdict.SAFE, safe.verdict)
        assertTrue(safe.reasons.isEmpty())
    }

    @Test
    fun blocklistParsesAndMatchesSubdomains() {
        val raw = """
            # yorum
            Kotu.Example
            olta-test.example   # satir sonu yorum
            gecersiz girdi
            tekil
        """.trimIndent()
        val entries = PhishingBlocklist.parse(raw)
        assertEquals(setOf("kotu.example", "olta-test.example"), entries)

        assertTrue(PhishingBlocklist.matches("kotu.example", entries))
        assertTrue(PhishingBlocklist.matches("a.b.kotu.example", entries))
        assertTrue(PhishingBlocklist.matches("KOTU.EXAMPLE.", entries))
        assertFalse(PhishingBlocklist.matches("kotuexample.com", entries))
        assertFalse(PhishingBlocklist.matches("ornek.com", entries))
        assertFalse(PhishingBlocklist.matches(null, entries))
        assertFalse(PhishingBlocklist.matches("kotu.example", emptySet()))
    }

    @Test
    fun scanTextEndToEnd() {
        val blocklist = setOf("kotu.example")
        val findings = PhishingScanner.scanText(
            "Guvenli: https://ornek.com/a. Oltu: http://kotu.example/x ve http://10.0.0.1/y.",
            blocklist
        )
        assertEquals(3, findings.size)
        assertEquals(Verdict.SAFE, findings[0].verdict)
        assertEquals(Verdict.MALICIOUS, findings[1].verdict)
        assertEquals(Verdict.SUSPICIOUS, findings[2].verdict)
    }
}
