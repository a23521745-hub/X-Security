package org.xsecurity.scanner.community

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EchapCsvToHsbTest {

    private val shaA = "2f3bc9ebe8c249f0416f5b0367f34b4b8f6aaa7d351dc5b4912fe2558491b6b7"
    private val shaB = "5bbbaff31596d3634439f7a0f29d82d120e482aa0ddc5563835c2a38a22f243d"
    private val shaC = "6e81de3f104586f1ca13cb54b88187bff655fb502a27f91a2019514bcb7d1f0d"

    @Test
    fun convertsValidRowsWithUnknownSize() {
        val csv = """
            SHA256,Package Name,Certificate,Version,App
            $shaA,com.topspy,7F5C,9,1TopSpy
            $shaB,,,,GuestSpy
            $shaC,,,,HelloSpy
        """.trimIndent()

        val conversion = EchapCsvToHsb.convert(csv, "Android.Stalkerware.", 10_000)

        assertEquals(3, conversion.lines.size)
        assertEquals(
            listOf(
                "$shaA:-1:Android.Stalkerware.1TopSpy",
                "$shaB:-1:Android.Stalkerware.GuestSpy",
                "$shaC:-1:Android.Stalkerware.HelloSpy"
            ),
            conversion.lines
        )
        // Baslik satiri "gecersiz hash" sayilir (SHA256 bir hex-64 degil).
        assertEquals(1, conversion.skippedBadHash)
    }

    @Test
    fun duplicateRowsAreDropped() {
        val csv = "SHA256,Package,Cert,Version,App\n$shaA,pkg,cert,1,Fam\n$shaA,pkg,cert,1,Fam"
        val conversion = EchapCsvToHsb.convert(csv, "X.", 100)
        assertEquals(1, conversion.lines.size)
        assertEquals(1, conversion.duplicates)
    }

    @Test
    fun rowsWithoutAppNameAreSkipped() {
        val csv = "SHA256,Package,Cert,Version,App\n$shaA,,,,"
        val conversion = EchapCsvToHsb.convert(csv, "X.", 100)
        assertTrue(conversion.lines.isEmpty())
        assertEquals(1, conversion.skippedNoName)
    }

    @Test
    fun quotedFieldsWithCommasSurvive() {
        val csv = "SHA256,Package,Cert,Version,App\n$shaA,\"pkg,inc\",cert,1,\"App, With Comma\""
        val conversion = EchapCsvToHsb.convert(csv, "X.", 100)
        assertEquals(listOf("$shaA:-1:X.App, With Comma"), conversion.lines)
    }

    @Test
    fun nameSanitiserStripsFormatBreakingCharacters() {
        val csv = "SHA256,Package,Cert,Version,App\n$shaA,p,c,1,We:ird\tName"
        val conversion = EchapCsvToHsb.convert(csv, "X.", 100)
        assertEquals(listOf("$shaA:-1:X.WeirdName"), conversion.lines)
    }

    @Test
    fun maxEntriesTruncatesTheOutput() {
        val csv = "SHA256,Package,Cert,Version,App\n$shaA,p,c,1,F\n$shaB,p,c,1,F\n$shaC,p,c,1,F"
        val conversion = EchapCsvToHsb.convert(csv, "X.", 2)
        assertEquals(2, conversion.lines.size)
    }

    @Test
    fun producedLinesAreValidHsb() {
        // Donusum ciktisi bizzat motor parser'iyla ayristirilabilmeli
        // (CommunityValidator'in dayandigi sozlesme).
        val csv = "SHA256,Package,Cert,Version,App\n$shaA,p,c,1,Family"
        val conversion = EchapCsvToHsb.convert(csv, "Android.Stalkerware.", 100)
        val database = org.xsecurity.scanner.clamav.ClamHashDatabaseParser()
            .parseLines(conversion.lines)
        assertEquals(1, database.size)
        assertEquals("Android.Stalkerware.Family", database.signatures.values.single().name)
        assertEquals(-1L, database.signatures.values.single().sizeBytes)
    }

    @Test
    fun unclosedQuoteMarksLineAsBroken() {
        val line = "$shaA,\"unclosed,pkg,c,1,App"
        assertEquals(emptyList<String>(), EchapCsvToHsb.splitCsvLine(line))
    }

    @Test
    fun csvFieldSplittingHandlesEdgeCases() {
        assertEquals(listOf("a", "b", "c"), EchapCsvToHsb.splitCsvLine("a,b,c"))
        assertEquals(listOf("a", "", "c"), EchapCsvToHsb.splitCsvLine("a,,c"))
        assertEquals(listOf("a,b", "c"), EchapCsvToHsb.splitCsvLine("\"a,b\",c"))
        assertEquals(listOf("quote\"inside", "c"), EchapCsvToHsb.splitCsvLine("\"quote\"\"inside\",c"))
    }
}
