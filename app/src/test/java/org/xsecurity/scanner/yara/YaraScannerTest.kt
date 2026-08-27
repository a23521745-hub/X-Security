package org.xsecurity.scanner.yara

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class YaraScannerTest {

    private val parser = YaraRuleParser()
    private val scanner = YaraScanner(chunkSize = 16)

    private fun tempFile(bytes: ByteArray): File {
        val file = File.createTempFile("xsec-", ".apk")
        file.deleteOnExit()
        file.writeBytes(bytes)
        return file
    }

    private fun scan(source: String, content: ByteArray): List<String> {
        val rules = parser.parseSource(source).rules
        return scanner.match(tempFile(content), rules).matches.map { it.ruleName }
    }

    @Test
    fun anyOfThemMatchesWhenASingleStringHits() {
        val matched = scan(
            """
            rule AndroRat {
                strings:
                    ${'$'}a = "malware-marker"
                    ${'$'}b = "c2-endpoint"
                condition:
                    any of them
            }
            """.trimIndent(),
            "prefix malware-marker suffix".encodeToByteArray()
        )
        assertEquals(listOf("AndroRat"), matched)
    }

    @Test
    fun allOfThemStillRequiresEveryString() {
        val source = "rule Strict { strings: " +
            "${'$'}a = \"one\" ${'$'}b = \"two\" condition: all of them }"

        assertEquals(emptyList<String>(), scan(source, "only one here".encodeToByteArray()))
        assertEquals(listOf("Strict"), scan(source, "one and two".encodeToByteArray()))
    }

    @Test
    fun countOfThemNeedsThatManyStrings() {
        val source = "rule TwoOf { strings: " +
            "${'$'}a = \"1111\" ${'$'}b = \"2222\" ${'$'}c = \"3333\" condition: 2 of them }"

        assertEquals(listOf("TwoOf"), scan(source, "1111 3333".encodeToByteArray()))
        assertEquals(emptyList<String>(), scan(source, "1111 only".encodeToByteArray()))
    }

    @Test
    fun noneOfThemInverts() {
        val source = "rule Absent { strings: ${'$'}a = \"absent-marker\" condition: none of them }"
        assertEquals(listOf("Absent"), scan(source, "nothing to see".encodeToByteArray()))
        assertEquals(emptyList<String>(), scan(source, "absent-marker here".encodeToByteArray()))
    }

    @Test
    fun andOrBooleanChainsWork() {
        val and = "rule Anded { strings: ${'$'}a = \"AA\" ${'$'}b = \"BB\" condition: ${'$'}a and ${'$'}b }"
        assertEquals(listOf("Anded"), scan(and, "xx AA xx BB".encodeToByteArray()))
        assertEquals(emptyList<String>(), scan(and, "only AA".encodeToByteArray()))

        val or = "rule Ored { strings: ${'$'}a = \"CC\" ${'$'}b = \"DD\" condition: ${'$'}a or ${'$'}b }"
        assertEquals(listOf("Ored"), scan(or, "only DD".encodeToByteArray()))

        val not = "rule Noted { strings: ${'$'}a = \"AA\" ${'$'}b = \"SAFE\" condition: ${'$'}a and not ${'$'}b }"
        assertEquals(listOf("Noted"), scan(not, "AA here".encodeToByteArray()))
        assertEquals(emptyList<String>(), scan(not, "AA and SAFE".encodeToByteArray()))
    }

    @Test
    fun hexPatternWithWildcardIsScanned() {
        val matched = scan(
            "rule Hexy { strings: ${'$'}d = { 64 65 78 0a ?? ?? ?? ?? } condition: any of them }",
            "dex\n035junk".encodeToByteArray()
        )
        assertEquals(listOf("Hexy"), matched)
    }

    @Test
    fun nocaseAndWideVariantsMatch() {
        val matched = scan(
            "rule Cased { strings: ${'$'}s = \"PoISON\" wide nocase condition: any of them }",
            "junk P\u0000o\u0000I\u0000S\u0000o\u0000N\u0000 tail".toByteArray(Charsets.ISO_8859_1)
        )
        assertEquals(listOf("Cased"), matched)
    }

    @Test
    fun patternBeyondTheFirstChunkIsFound() {
        val source = "rule Late { strings: ${'$'}a = \"END-MARKER\" condition: any of them }"
        val content = ByteArray(5000) { '.'.code.toByte() } + "END-MARKER".encodeToByteArray()
        assertEquals(listOf("Late"), scan(source, content))
    }

    @Test
    fun truncationIsReportedInsteadOfSilentlyIgnored() {
        val rules = parser.parseSource("rule Late { strings: ${'$'}a = \"TAIL\" condition: any of them }").rules
        val content = ByteArray(200) { 'x'.code.toByte() } + "TAIL".encodeToByteArray()
        val outcome = YaraScanner(chunkSize = 16, maxBytesToScan = 64).match(tempFile(content), rules)

        assertTrue("limit asilmali", outcome.truncated)
        assertTrue(outcome.matches.isEmpty())
        assertEquals(64L, outcome.scannedBytes)
    }

    @Test
    fun approximateRulesAreFlaggedOnMatch() {
        val rules = parser.parseSource(
            "rule Loose { strings: ${'$'}a = \"needle\" condition: ${'$'}a and filesize > 10 }"
        ).rules
        val outcome = scanner.match(tempFile("needle here".encodeToByteArray()), rules)
        assertEquals(1, outcome.matches.size)
        assertTrue("kural yaklasik olarak isaretlenmeli", outcome.matches.single().approximate)
    }
}
