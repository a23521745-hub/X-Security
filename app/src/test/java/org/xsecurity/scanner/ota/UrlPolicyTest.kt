package org.xsecurity.scanner.ota

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlPolicyTest {

    private val hosts = setOf("updates.example.com", "cdn.example.org")

    @Test
    fun allowsHttpsOnAllowlistedHost() {
        val result = UrlPolicy.check("https://updates.example.com/path/app.apk", hosts)
        assertTrue(result.reason, result.allowed)
    }

    @Test
    fun rejectsHttpCleartext() {
        val result = UrlPolicy.check("http://updates.example.com/app.apk", hosts)
        assertFalse(result.allowed)
        assertTrue(result.reason.orEmpty().contains("https"))
    }

    @Test
    fun rejectsNonAllowlistedHost() {
        val result = UrlPolicy.check("https://evil.example.net/app.apk", hosts)
        assertFalse(result.allowed)
        assertTrue(result.reason.orEmpty().contains("izin listesinde değil"))
    }

    @Test
    fun rejectsNonStandardPort() {
        val result = UrlPolicy.check("https://updates.example.com:8443/app.apk", hosts)
        assertFalse(result.allowed)
    }

    @Test
    fun rejectsUrlWithUserInfo() {
        val result = UrlPolicy.check("https://user:pass@updates.example.com/app.apk", hosts)
        assertFalse(result.allowed)
    }

    @Test
    fun rejectsEmptyOrBlankHostList() {
        assertFalse(UrlPolicy.check("https://updates.example.com/app.apk", emptySet()).allowed)
    }

    @Test
    fun treatsSubdomainAsDifferentHost() {
        // attacks.example.com ile updates.example.com farkli host'lardir; joker karakter yok.
        val result = UrlPolicy.check("https://attacks.example.com/app.apk", setOf("example.com"))
        assertFalse(result.allowed)
    }

    @Test
    fun hostComparisonIsCaseAndTrailingDotInsensitive() {
        assertTrue(UrlPolicy.check("https://UPDATES.example.com/x", hosts).allowed)
        assertEquals(true, UrlPolicy.check("https://updates.example.com./x", hosts).allowed)
    }
}
