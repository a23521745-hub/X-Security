package org.xsecurity.scanner.clamav

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ClamAvDatabaseParserTest {

    private val parser = ClamAvDatabaseParser()

    @Test
    fun parsesStandardFourFieldRecord() {
        val db = parser.parseLines(listOf("Eva.Malware:0:0:41424344"))
        assertEquals(1, db.size)
        val signature = db.signatures.single()
        assertEquals("Eva.Malware", signature.name)
        assertEquals(0, signature.targetType)
        assertEquals("ABCD", String(signature.bytes, Charsets.ISO_8859_1))
        assertNull(signature.mask)
        assertFalse(signature.isAnchored)
    }

    @Test
    fun numericOffsetsBecomeRealConstraints() {
        val exact = parser.parseLines(listOf("A:0:64:4142")).signatures.single()
        assertTrue(exact.offset is ClamAvSignature.OffsetConstraint.Exact)
        assertEquals(64L, (exact.offset as ClamAvSignature.OffsetConstraint.Exact).position)

        val ranged = parser.parseLines(listOf("B:0:16,32:4142")).signatures.single()
        assertTrue(ranged.offset is ClamAvSignature.OffsetConstraint.Range)
        val range = ranged.offset as ClamAvSignature.OffsetConstraint.Range
        assertEquals(16L, range.from)
        assertEquals(48L, range.to)

        assertTrue(
            "offset=0 'her yer' demek",
            parser.parseLines(listOf("C:0:0:4142")).signatures.single().offset
                is ClamAvSignature.OffsetConstraint.Any
        )
    }

    @Test
    fun symbolicOffsetsAreKeptButReported() {
        val db = parser.parseLines(listOf("D:1:e:4142", "E:1:x:4142", "F:0:\".text\"#4:4142"))
        assertEquals(3, db.size)
        db.signatures.forEach { assertTrue(it.offset is ClamAvSignature.OffsetConstraint.Any) }
        assertEquals(3, db.stats.symbolicOffsetsIgnored)
        assertEquals(2, db.stats.targetTypesIgnored)
        assertTrue(db.stats.isPartial)
    }

    @Test
    fun nibbleWildcardsAreCompiledIntoMask() {
        val signature = parser.parseLines(listOf("G:0:0:64 65 78 0a ?? ?? ?? ??")).signatures.single()
        assertEquals("dex\n", String(signature.bytes.copyOfRange(0, 4), Charsets.ISO_8859_1))
        assertNotNull(signature.mask)
        assertEquals(4, signature.mask!!.count { it == 0.toByte() })
    }

    @Test
    fun variableLengthWildcardIsSkippedAndCounted() {
        val db = parser.parseLines(listOf("H:0:0:41*42", "I:0:0:4142"))
        assertEquals(1, db.size)
        assertEquals(1, db.stats.unsupportedPattern)
        assertEquals(1, db.stats.skipped)
    }

    @Test
    fun malformedAndCommentLinesAreCounted() {
        val db = parser.parseLines(
            listOf(
                "# comment",
                "",
                "no-colons-here",
                "J:0:41",
                "K:0:0:ZZZZ",
                "L:0:0:4142"
            )
        )
        assertEquals(1, db.size)
        assertEquals(3, db.stats.malformed)
    }

    @Test
    fun fileSizeBoundsFieldIsAccepted() {
        val db = parser.parseLines(listOf("M:0:0:4142:68-"))
        assertEquals(1, db.size)
    }
}
