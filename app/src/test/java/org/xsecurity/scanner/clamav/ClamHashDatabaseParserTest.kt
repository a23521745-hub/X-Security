package org.xsecurity.scanner.clamav

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ClamHashDatabaseParserTest {

    private val parser = ClamHashDatabaseParser()

    @Test
    fun hashLengthDeterminesTheAlgorithm() {
        val md5 = "0123456789abcdef0123456789abcdef"
        val sha1 = "0123456789abcdef0123456789abcdef01234567"
        val sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val db = parser.parseLines(
            listOf(
                "$md5:10:A.Md5",
                "$sha1:20:A.Sha1",
                "$sha256:30:A.Sha256"
            )
        )
        assertEquals(3, db.size)
        assertEquals(ClamHashDatabaseParser.Algorithm.MD5, db.signatures[md5]!!.algorithm)
        assertEquals(ClamHashDatabaseParser.Algorithm.SHA_1, db.signatures[sha1]!!.algorithm)
        assertEquals(ClamHashDatabaseParser.Algorithm.SHA_256, db.signatures[sha256]!!.algorithm)
        assertEquals(1, db.stats.md5)
        assertEquals(1, db.stats.sha1)
        assertEquals(1, db.stats.sha256)
    }

    @Test
    fun unknownSizeMarkersAreCountedNotRejected() {
        val sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val db = parser.parseLines(
            listOf(
                "$sha256:*:A.Star",
                "$sha256:-1:A.MinusOne",
                "$sha256::A.Empty"
            )
        )
        // Ayni hash uc kez verildi: ilki yuklenir, diger ikisi dup sayilir.
        assertEquals(1, db.size)
        assertEquals(-1L, db.signatures[sha256]!!.sizeBytes)
        assertEquals(1, db.stats.unknownSize)
        assertEquals(2, db.stats.duplicates)
        assertEquals(0, db.stats.malformed)
    }

    @Test
    fun explicitSizeIsKeptAsAConstraint() {
        val sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val db = parser.parseLines(listOf("$sha256:68:Eicar.Test-File"))
        assertEquals(68L, db.signatures[sha256]!!.sizeBytes)
        assertEquals(0, db.stats.unknownSize)
    }

    @Test
    fun colonsInsideTheNameArePreserved() {
        // split(':', limit = 3) — isim alanindaki ':' ler bozulmadan kalmali.
        val sha1 = "0123456789abcdef0123456789abcdef01234567"
        val db = parser.parseLines(listOf("$sha1:5:Some:Name:With:Colons"))
        assertEquals("Some:Name:With:Colons", db.signatures[sha1]!!.name)
    }

    @Test
    fun commentsAndBlankLinesAreSkipped() {
        val md5 = "0123456789abcdef0123456789abcdef"
        val db = parser.parseLines(
            listOf(
                "# baslik yorumu",
                "",
                "   ",
                "$md5:1:A.Real",
                "# kapanis yorumu"
            )
        )
        assertEquals(1, db.size)
        assertEquals(1, db.stats.totalLines)
        assertEquals(0, db.stats.malformed)
    }

    @Test
    fun malformedLinesAreCountedWithExamples() {
        val db = parser.parseLines(
            listOf(
                "kisa-hash:1:A",                                    // hash uzunlugu gecersiz
                "0123456789abcdef0123456789abcdef:xyz:A",            // boyut sayi degil
                "0123456789abcdef0123456789abcdef:-5:A",             // negatif boyut
                "0123456789abcdef0123456789abcdef:1:",               // bos isim
                "0123456789abcdef0123456789abcdef:1",                // alan eksik
                "z123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:1:A" // hex degil
            )
        )
        assertEquals(0, db.size)
        assertEquals(6, db.stats.malformed)
        assertEquals(6, db.stats.problems.size)
    }

    @Test
    fun uppercaseHashIsNormalisedToLowerCase() {
        val upper = "0123456789ABCDEF0123456789ABCDEF"
        val db = parser.parseLines(listOf("$upper:1:A.Upper"))
        assertEquals(1, db.size)
        assertEquals("0123456789abcdef0123456789abcdef", db.signatures.keys.single())
        // lookup buyuk harfle de bulmali (motor normalize eder).
        assertEquals("A.Upper", db.lookup(upper)!!.name)
    }

    @Test
    fun entryLimitIsEnforced() {
        val md5 = "0123456789abcdef0123456789abcdef"
        val lines = (1..3).map { index ->
            val hash = md5.take(28) + index.toString().padStart(4, '0')
            "$hash:1:A$index"
        }
        try {
            ClamHashDatabaseParser(maxEntries = 2).parseLines(lines)
            throw AssertionError("giris limiti asildiginda exception beklenir")
        } catch (expected: Exception) {
            assertTrue(expected.message!!.contains("entry limit"))
        }
    }

    @Test
    fun fileWithOnlyGarbageLinesIsRejected() {
        val garbage = File.createTempFile("xsec-hsb-garbage-", ".hsb")
        garbage.deleteOnExit()
        garbage.writeText("bozuk satir\nbir baska bozuk\n")
        try {
            parser.parse(garbage)
            throw AssertionError("hicbir imza yuklenemeyen dosya reddedilmeli")
        } catch (expected: Exception) {
            assertTrue(expected.message!!.contains("No scannable hash signatures"))
        }
    }

    @Test
    fun missingFileIsRejected() {
        val missing = File.createTempFile("xsec-hsb-missing-", ".hsb")
        missing.delete()
        try {
            parser.parse(missing)
            throw AssertionError("olmayan dosya reddedilmeli")
        } catch (expected: Exception) {
            assertTrue(expected.message!!.contains("not found"))
        }
    }

    @Test
    fun lookupMissReturnsNull() {
        val md5 = "0123456789abcdef0123456789abcdef"
        val db = parser.parseLines(listOf("$md5:1:A"))
        assertNull(db.lookup("ffffffffffffffffffffffffffffffff"))
    }
}
