package org.xsecurity.scanner.matcher

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * [BytePatternMatcher] streaming + carry davranisi icin regresyon testleri.
 *
 * Eski surum her chunk'u bagimsiz okuyor, kisa kalip uzunlugu kadar tasima
 * yapmiyordu ve `input.read(buffer)` tek cagrisina guveniyordu; bu yuzden
 * (1) chunk sinirini asan kalplar bulunamiyor, (2) OS kisa okuma yaparsa dosyanin
 * geri kalani hic taranmiyordu.
 */
class BytePatternMatcherTest {

    private fun pattern(text: String, id: Int = 0, ignoreCase: Boolean = false, mask: ByteArray? = null) =
        BytePattern(id, text.encodeToByteArray(), mask, ignoreCase)

    private fun tempFile(bytes: ByteArray): File {
        val file = File.createTempFile("xsec-", ".bin")
        file.deleteOnExit()
        file.writeBytes(bytes)
        return file
    }

    @Test
    fun findsPatternThatSpansAChunkBoundary() {
        val data = ByteArray(60) { '.'.code.toByte() } + "TAILMARK".encodeToByteArray() + ByteArray(60) { '-'.code.toByte() }
        val matcher = BytePatternMatcher(listOf(pattern("TAILMARK")), chunkSize = 16)
        val result = matcher.scan(tempFile(data))

        assertTrue("chunk sinirini asan kalip bulunmali", result.matchedIds.contains(0))
        assertEquals(data.size.toLong(), result.bytesScanned)
    }

    @Test
    fun findsPatternAtTheVeryEndOfFile() {
        val data = ByteArray(500) { '.'.code.toByte() } + "TAIL".encodeToByteArray()
        val matcher = BytePatternMatcher(listOf(pattern("TAIL")), chunkSize = 64)
        assertTrue(matcher.scan(tempFile(data)).matchedIds.contains(0))
    }

    @Test
    fun patternLongerThanChunkSizeIsStillMatched() {
        val long = ByteArray(300) { 'L'.code.toByte() }
        val data = ByteArray(50) { 'z'.code.toByte() } + long + ByteArray(50) { 'w'.code.toByte() }
        val result = BytePatternMatcher(listOf(BytePattern(7, long)), chunkSize = 8).scan(tempFile(data))

        assertTrue(result.matchedIds.contains(7))
    }

    @Test
    fun shortReadsDoNotTruncateTheScan() {
        // 4 KiB'lik bir dosya, koca bir tamponla tek `read` cagrisinda okunamaz hale
        // gelse bile tum baytlar taranmali: toplam taranan bayt = dosya boyutu.
        val data = ByteArray(4096) { (it % 251).code.toByte() } + "NEEDLE".encodeToByteArray()
        val matcher = BytePatternMatcher(listOf(pattern("NEEDLE")), chunkSize = 4096)
        val result = matcher.scan(tempFile(data))

        assertEquals(4096L + 6L, result.bytesScanned)
        assertTrue(result.matchedIds.contains(0))
    }

    @Test
    fun ignoreCaseMatchesOnlyAsciiLetters() {
        val folded = pattern("hello", ignoreCase = true)
        val exact = pattern("hello", id = 1)
        val matcher = BytePatternMatcher(listOf(folded, exact), chunkSize = 4)
        val result = matcher.scan(tempFile("say HELLO now".encodeToByteArray()))

        assertTrue(result.matchedIds.contains(0))
        assertFalse("nocase olmayan kalip buyuk harfle eslesmemeli", result.matchedIds.contains(1))
    }

    @Test
    fun widePatternMatchesUtf16LeEncoding() {
        val pattern = BytePattern(0, BytePattern.widen("hello".encodeToByteArray()), null, ignoreCase = true)
        val data = "junk h\u0000e\u0000l\u0000l\u0000o\u0000 tail".toByteArray(Charsets.ISO_8859_1)
        val result = BytePatternMatcher(listOf(pattern), chunkSize = 5).scan(tempFile(data))
        assertTrue("wide + nocase UTF-16LE kalicinda bulunmali", result.matchedIds.contains(0))
    }

    @Test
    fun maskBytesAreFreePositions() {
        val mask = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0, 0, 0xFF.toByte(), 0xFF.toByte())
        val matcher = BytePatternMatcher(listOf(pattern("ABZZCD", mask = mask)), chunkSize = 8)

        val hit = matcher.scan(tempFile("xxAB12CDyy".encodeToByteArray()))
        assertTrue(hit.matchedIds.contains(0))

        val mismatch = matcher.scan(tempFile("xxAB12CEyy".encodeToByteArray()))
        assertFalse(mismatch.matchedIds.contains(0))
    }

    @Test
    fun allWildcardPatternIsRejectedAsUnusable() {
        val matcher = BytePatternMatcher(listOf(BytePattern(0, byteArrayOf(0, 0), byteArrayOf(0, 0))))
        assertTrue(matcher.isEmpty)
        assertEquals(1, matcher.unusablePatternCount)
    }

    @Test
    fun positionFilterDecidesWhichHitsCount() {
        val matcher = BytePatternMatcher(listOf(pattern("ABCDE")), chunkSize = 16)
        val atZero = ByteArray(200) { '.'.code.toByte() }
        val data = "ABCDE".encodeToByteArray() + ByteArray(123) { '-'.code.toByte() } + "ABCDE".encodeToByteArray() + ByteArray(120) { '+'.code.toByte() }

        val exact = matcher.scan(tempFile(data), positionFilter = { _, position -> position == 128L })
        assertTrue("128 haric, filtre buraya dusmuyor", exact.matchedIds.isEmpty())

        val anchored = matcher.scan(tempFile(data), positionFilter = { _, position -> position == 0L })
        assertEquals(setOf(0), anchored.matchedIds)
        assertEquals(listOf(0L), anchored.positions.getValue(0))

        val ranged = matcher.scan(
            tempFile(data),
            positionFilter = { _, position -> position in 16L..47L },
            maxPositionsPerId = 8
        )
        assertTrue("ofset 0 ve 128, 16..47 araligi disinda", ranged.matchedIds.isEmpty())
        assertFalse("bos veri taramasi da ayni mantikla calismali", matcher.scan(tempFile(atZero)).truncated)
    }
}
