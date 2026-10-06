package org.xsecurity.scanner.phishing

import java.net.IDN
import java.net.URI

/**
 * URL/oltalama sezgiselleri (**saf** JVM mantigi, test edilir).
 *
 * Kurallar (sartname):
 *  - IP host (IPv4 dortlusu ya da IPv6): alan adi yerine sayisal adres,
 *  - `@` isareti (yetki bolumunde): gercek hedefi gizleyen `kullanici@host`,
 *  - punycode (`xn--`): benzer gorunumlu karakter oyunu,
 *  - kisaltici: hedefi gizleyen bilinen link-kisaltma alan adlari.
 *
 * Hüküm: blok listesindeyse [Verdict.MALICIOUS]; sezgisel tuttuysa
 * [Verdict.SUSPICIOUS]; aksi halde [Verdict.SAFE]. Ag YOK — karar tamamen
 * cihaz icidir (blok listesi ayrica guncellenebilir, bkz. [PhishingStore]).
 */
object PhishingHeuristics {

    enum class Verdict { SAFE, SUSPICIOUS, MALICIOUS }

    enum class Reason { BLOCKLISTED, IP_HOST, AT_SIGN, PUNYCODE, SHORTENER }

    data class Finding(
        val url: String,
        val host: String?,
        val verdict: Verdict,
        val reasons: List<Reason>
    )

    /**
     * Bilinen link kisalticilar (hedefi gizledikleri icin tek baslarina
     * "supheli" sayilir; alt alan adlari da tutar: `x.bit.ly`).
     */
    val SHORTENERS: Set<String> = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
        "rebrand.ly", "t.ly", "s.id", "qr.ae", "v.gd", "clck.ru",
        "picsee.link", "short.io", "soo.gd"
    )

    fun evaluate(url: String, blocklisted: Boolean): Finding {
        val host = hostOf(url)
        if (host == null) {
            // Ayristirilamayan girdi cozulemedi: fail-closed, supheli sayilir.
            return Finding(url, null, Verdict.SUSPICIOUS, emptyList())
        }
        val reasons = ArrayList<Reason>(3)
        if (blocklisted) reasons += Reason.BLOCKLISTED
        if (isIpHost(host)) reasons += Reason.IP_HOST
        if (hasAtSign(url)) reasons += Reason.AT_SIGN
        if (isPunycode(host)) reasons += Reason.PUNYCODE
        if (isShortener(host)) reasons += Reason.SHORTENER
        val verdict = when {
            blocklisted -> Verdict.MALICIOUS
            reasons.isNotEmpty() -> Verdict.SUSPICIOUS
            else -> Verdict.SAFE
        }
        return Finding(url, host, verdict, reasons)
    }

    /** Saf: URL'den kucuk-harfe cevrilmis host (sema yoksa https varsayilir). */
    fun hostOf(url: String): String? {
        val trimmed = url.trim()
        if (trimmed.isEmpty()) return null
        // `URI.host` kullanici-bilgisi (`kullanici@`) icermez; ham metindeki
        // `@` ayrica [hasAtSign] ile denetlenir.
        val withScheme = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        val host = try {
            URI(withScheme).host
        } catch (_: Exception) {
            return null
        } ?: return null
        return host.lowercase().trimEnd('.').ifEmpty { null }
    }

    /** Saf: IPv4 dortlusu (0-255) ya da IPv6 (`:` iceren) mi? */
    fun isIpHost(host: String): Boolean {
        if (host.contains(':')) return true
        val parts = host.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            if (part.isEmpty() || part.length > 3 || !part.all { it.isDigit() }) return@all false
            val number = part.toIntOrNull() ?: return@all false
            number in 0..255
        }
    }

    /** Saf: yetki bolumunde (`://` ile ilk `/` arasi) `@` var mi? */
    fun hasAtSign(url: String): Boolean {
        val afterScheme = url.substringAfter("://", url)
        val authority = afterScheme.substringBefore('/')
        return '@' in authority
    }

    /** Saf: IDN ASCII biciminde `xn--` etiketi var mi? */
    fun isPunycode(host: String): Boolean {
        val ascii = try {
            IDN.toASCII(host)
        } catch (_: Exception) {
            return host.contains("xn--")
        }
        return ascii.contains("xn--")
    }

    /** Saf: host kisaltici (ya da onun alt alan adi) mi? */
    fun isShortener(host: String): Boolean {
        val clean = host.lowercase().trimEnd('.')
        return SHORTENERS.any { short -> clean == short || clean.endsWith(".$short") }
    }
}
