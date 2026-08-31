package org.xsecurity.scanner.community

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.clamav.ClamHashDatabaseParser
import org.xsecurity.scanner.core.SignatureDatabaseException

class CommunityValidatorTest {

    private val shaA = "2f3bc9ebe8c249f0416f5b0367f34b4b8f6aaa7d351dc5b4912fe2558491b6b7"
    private val shaB = "5bbbaff31596d3634439f7a0f29d82d120e482aa0ddc5563835c2a38a22f243d"

    private fun hashSource(maxEntries: Int = 10_000) = CommunitySource(
        id = "t-hashes",
        kind = CommunitySource.Kind.HSB_FROM_CSV,
        label = "Test Hashes",
        detail = "",
        url = "https://raw.githubusercontent.com/a/b/samples.csv",
        namePrefix = "Android.Stalkerware.",
        maxEntries = maxEntries,
        enabledByDefault = true,
        license = "CC BY 4.0",
        attribution = "test"
    )

    private fun yaraSource(maxEntries: Int = 100) = CommunitySource(
        id = "t-yara",
        kind = CommunitySource.Kind.YARA,
        label = "Test YARA",
        detail = "",
        url = "https://raw.githubusercontent.com/a/b/rules.yar",
        namePrefix = "",
        maxEntries = maxEntries,
        enabledByDefault = true,
        license = "CC BY 4.0",
        attribution = "test"
    )

    @Test
    fun csvPayloadBecomesParseableHsb() {
        val csv = "SHA256,Package,Cert,Version,App\n$shaA,p,c,1,1TopSpy\n$shaB,p,c,1,GuestSpy"
        val validated = CommunityValidator.validate(hashSource(), csv.toByteArray())

        assertEquals(2, validated.hashEntries)
        assertEquals(0, validated.yaraRules)
        // Uretilen icerik motor parser'iyla tekrar ayristirilabilmeli (yuvarlak trips).
        val reparsed = ClamHashDatabaseParser().parseLines(validated.content.lineSequence().toList())
        assertEquals(2, reparsed.size)
        assertTrue(validated.content.contains("Android.Stalkerware.1TopSpy"))
    }

    @Test
    fun csvWithoutValidRowsIsRejected() {
        try {
            CommunityValidator.validate(hashSource(), "SHA256,Package\nnot-a-hash,x".toByteArray())
            throw AssertionError("gecerli satiri olmayan CSV reddedilmeli")
        } catch (expected: SignatureDatabaseException) {
            assertTrue(expected.message!!.contains("gecerli hash satiri"))
        }
    }

    @Test
    fun yaraPayloadIsCountedAndPassedThrough() {
        val yar = """
            rule Community_One { strings: ${'$'}a = "needleOne" condition: any of them }
            rule Community_Two { strings: ${'$'}b = "needleTwo" condition: 1 of them }
        """.trimIndent()
        val validated = CommunityValidator.validate(yaraSource(), yar.toByteArray())

        assertEquals(2, validated.yaraRules)
        assertEquals(yar, validated.content)
    }

    @Test
    fun yaraPayloadWithoutParsableRulesIsRejected() {
        try {
            CommunityValidator.validate(yaraSource(), "bu bir yara dosyasi degil".toByteArray())
            throw AssertionError("kural cikmayan icerik reddedilmeli")
        } catch (expected: SignatureDatabaseException) {
            assertTrue(expected.message!!.contains("kural cikmadi"))
        }
    }

    @Test
    fun yaraRuleCountOverTheCapIsRejected() {
        val yar = """
            rule A { strings: ${'$'}a = "x1" condition: any of them }
            rule B { strings: ${'$'}a = "x2" condition: any of them }
            rule C { strings: ${'$'}a = "x3" condition: any of them }
        """.trimIndent()
        try {
            CommunityValidator.validate(yaraSource(maxEntries = 2), yar.toByteArray())
            throw AssertionError("tavani asan kural sayisi reddedilmeli")
        } catch (expected: SignatureDatabaseException) {
            assertTrue(expected.message!!.contains("tavani"))
        }
    }

    @Test
    fun echapStyleConditionParsesNOfThem() {
        // Yukari akis Echap kurallari "uint16(0) == 0x6564 and N of them" bicimindedir;
        // motor bunu N-of-them olarak cozmelidir (any-of-them'e dusmemeli).
        val yar = """
            rule echap_style {
                strings:
                    ${'$'}s1 = "mspyonline.com" ascii
                    ${'$'}s2 = "inputType=0x%08x" ascii
                condition:
                    uint16(0) == 0x6564 and 2 of them
            }
        """.trimIndent()
        val validated = CommunityValidator.validate(yaraSource(), yar.toByteArray())
        assertEquals(1, validated.yaraRules)
    }
}
