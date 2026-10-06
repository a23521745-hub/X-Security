package org.xsecurity.scanner.community

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ETag/SHA-256 tazelik mantigi:
 *  - [CommunityDownloader.normalizeEtag]: baslik temizligi,
 *  - [Fetcher.fetchConditional] varsayilani: sahte/ozel fetcher'lar agsiz calisir,
 *  - [CommunityUpdater.isUpToDate]: SHA esitse VE dosya yerindeyse kurma,
 *  - [CommunityStore.shortHash]: UI'da gosterilen kisa ozet.
 */
class ConditionalFetchTest {

    @Test
    fun normalizeEtagTrimsAndNullsBlank() {
        assertEquals("\"abc123\"", CommunityDownloader.normalizeEtag("  \"abc123\"  "))
        assertEquals("W/\"v2\"", CommunityDownloader.normalizeEtag("W/\"v2\""))
        assertNull(CommunityDownloader.normalizeEtag(null))
        assertNull(CommunityDownloader.normalizeEtag(""))
        assertNull(CommunityDownloader.normalizeEtag("   "))
    }

    @Test
    fun defaultFetchConditionalHashesPlainFetch() {
        val fetcher = object : Fetcher {
            override fun fetch(url: String): ByteArray = "abc".toByteArray()
        }
        val result = fetcher.fetchConditional("https://example.invalid/x", "\"etag\"")
        assertTrue(result is ConditionalFetch.Fresh)
        val fresh = result as ConditionalFetch.Fresh
        // sha256("abc") — bilinen vektor; varsayilan ozeti dogru hesaplamali.
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", fresh.sha256)
        assertNull(fresh.etag)
    }

    @Test
    fun upToDateOnlyWhenShaMatchesAndFileExists() {
        val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assertTrue(CommunityUpdater.isUpToDate(sha, sha, fileExists = true))
        // Dosya eksikse ozet esslese bile kurulum gerekir (fail-closed).
        assertFalse(CommunityUpdater.isUpToDate(sha, sha, fileExists = false))
        assertFalse(CommunityUpdater.isUpToDate(null, sha, fileExists = true))
        assertFalse(CommunityUpdater.isUpToDate("00", sha, fileExists = true))
    }

    @Test
    fun shortHashTakesTwelveHexChars() {
        val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assertEquals("ba7816bf8f01", CommunityStore.shortHash(sha))
        assertEquals("ba7816bf8f01", CommunityStore.shortHash("  $sha  "))
        assertNull(CommunityStore.shortHash(null))
        assertNull(CommunityStore.shortHash("kisa"))
    }
}
