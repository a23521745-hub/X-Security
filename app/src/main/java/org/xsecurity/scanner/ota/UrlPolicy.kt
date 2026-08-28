package org.xsecurity.scanner.ota

import java.net.URI

/**
 * Ag uclari icin katı izin listesi (allowlist).
 *
 * Uygulamanin ag erisimi yalnizca OTA icindir ve bu nesne disina cikmaz:
 *  - Yalnizca **https** (port 443 ya da standart-disinda acikca 443; cleartext yok).
 *  - Ana bilgisayar (host) [allowedHosts] icinde olmali — bagimsiz/ucu acik bir URL'e
 *    yonlendirme bile reddedilir (indirme `followRedirects=false` ile calisir, sonra
 *    her atlanan konum bu politikadan tekrar gecer).
 *  - Bos host, IP yerine isim tabanli host beklenir; kullanici/kimlik bilgisi iceren
 *    (`userinfo`) URL'ler reddedilir.
 *
 * Bu sayede manifeste sizmis bir `apkUrl` ile baska bir sunucudan APK cekilmesi onlenir.
 */
object UrlPolicy {

    /**
     * [url]'in [allowedHosts] uzerinden guvenli olup olmadigini doner.
     * Basarisiz yontem exception firlatmaz; `null` doner ve [reason] aciklamasi dolar.
     */
    fun check(url: String, allowedHosts: Set<String>): Result {
        val trimmed = url.trim()
        if (trimmed.isEmpty()) return Result(false, "URL bos")

        val uri = try {
            URI(trimmed)
        } catch (_: Throwable) {
            return Result(false, "URL ayrıştırılamadı")
        }

        val scheme = uri.scheme?.lowercase()
        if (scheme != "https") return Result(false, "yalnızca https desteklenir")
        if (uri.rawUserInfo != null) return Result(false, "URL kimlik bilgisi içeremez")

        val host = uri.host?.lowercase()?.removeSuffix(".")
        if (host.isNullOrBlank()) return Result(false, "URL bir ana bilgisayar içermiyor")

        val port = uri.port
        if (port != -1 && port != 443) return Result(false, "yalnızca 443 portuna izin var")

        val normalizedHosts = allowedHosts
            .map { it.lowercase().removeSuffix(".") }
            .filter { it.isNotBlank() }
            .toSet()
        val hostOk = normalizedHosts.any { allowed -> host == allowed }
        if (!hostOk) return Result(false, "ana bilgisayar izin listesinde değil: $host")

        return Result(true, null)
    }

    data class Result(val allowed: Boolean, val reason: String?) {
        inline fun <T> ifAllowed(block: () -> T): T? = if (allowed) block() else null
    }
}
