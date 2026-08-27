package org.xsecurity.scanner.yara

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Parser regresyon testleri. Her biri, onceki satir-bazli parserin sessizce kaybettigi
 * bir kural seklini dogrudan sariya baglar.
 */
class YaraRuleParserTest {

    private val parser = YaraRuleParser()

    @Test
    fun anyOfThemConditionIsParsedAndNotForcedToAll() {
        val set = parser.parseSource(
            """
            rule Demo {
                strings:
                    ${'$'}a = "malware"
                    ${'$'}b = "c2"
                condition:
                    any of them
            }
            """.trimIndent()
        )

        assertEquals(1, set.rules.size)
        val rule = set.rules.single()
        assertEquals("Demo", rule.name)
        assertEquals(listOf("a", "b"), rule.strings.map { it.identifier })
        assertSame(YaraCondition.AnyOfThem, rule.condition)
        assertFalse(rule.approximateCondition)
        assertEquals(0, set.unparsableRules)
    }

    @Test
    fun privateAndGlobalRulesAreRecognised() {
        val set = parser.parseSource(
            """
            private rule Helper {
                strings:
                    ${'$'}a = "internal"
                condition:
                    ${'$'}a
            }
            global rule Guard {
                strings:
                    ${'$'}x = "guard"
                condition:
                    all of them
            }
            """.trimIndent()
        )

        assertEquals(listOf("Helper", "Guard"), set.rules.map { it.name })
        assertTrue(set.rules[0].condition is YaraCondition.OrTerms)
        assertSame(YaraCondition.AllOfThem, set.rules[1].condition)
    }

    @Test
    fun singleLineRuleIsNotDropped() {
        val set = parser.parseSource(
            "rule Compact { strings: ${'$'}a = \"inline\" condition: any of them }"
        )
        assertEquals(1, set.rules.size)
        assertEquals("inline", String(set.rules.single().strings.single().bytes, Charsets.UTF_8))
    }

    @Test
    fun hexStringsAreCompiledWithWildcardMask() {
        val set = parser.parseSource(
            """
            rule Hexy {
                strings:
                    ${'$'}d = { 64 65 78 0a ?? ?? ?? ?? }
                condition:
                    any of them
            }
            """.trimIndent()
        )

        val declaration = set.rules.single().strings.single()
        assertFalse("hex string isText olmamali", declaration.isText)
        assertEquals("dex\n", String(declaration.bytes.copyOfRange(0, 4), Charsets.ISO_8859_1))
        assertTrue("6. bayt joker olmali", declaration.bytes[4] == 0.toByte())
        assertEquals(4, declaration.mask!!.count { it == 0.toByte() })
    }

    @Test
    fun escapeSequencesIncludingHexByteAreDecoded() {
        val set = parser.parseSource(
            "rule Nl { strings: ${'$'}a = \"A\\tb\\x90C\" condition: ${'$'}a }"
        )
        val bytes = set.rules.single().strings.single().bytes
        assertEquals(4, bytes.size)
        assertEquals('A'.code.toByte(), bytes[0])
        assertEquals('\t'.code.toByte(), bytes[1])
        assertEquals((-0x70).toByte(), bytes[2]) // 0x90 signed
        assertEquals('C'.code.toByte(), bytes[3])
    }

    @Test
    fun wideAndNocaseModifiersArePreserved() {
        val set = parser.parseSource(
            """
            rule Mods {
                strings:
                    ${'$'}a = "cmd.exe" wide nocase
                    ${'$'}b = "plain"
                    ${'$'}c = "both" ascii wide
                    ${'$'}d = "caseless" nocase
                condition:
                    any of them
            }
            """.trimIndent()
        )
        val byName = set.rules.single().strings.associateBy { it.identifier }

        // YARA semantigi: yalnizca `wide` verilirse ascii varyanti uretilmez.
        assertTrue(byName.getValue("a").wide)
        assertTrue(byName.getValue("a").nocase)
        assertFalse(byName.getValue("a").ascii)
        assertEquals(1, byName.getValue("a").variants().size)

        assertFalse(byName.getValue("b").wide)
        assertTrue(byName.getValue("b").ascii)
        assertEquals(1, byName.getValue("b").variants().size)

        assertTrue(byName.getValue("c").ascii)
        assertTrue(byName.getValue("c").wide)
        assertEquals(2, byName.getValue("c").variants().size)

        assertTrue(byName.getValue("d").nocase)
        assertTrue(byName.getValue("d").ascii)
        assertFalse(byName.getValue("d").wide)
    }

    @Test
    fun regexAndUnsupportedModifiersAreCountedNotSilentlyLost() {
        val set = parser.parseSource(
            """
            rule RegexOnly {
                strings:
                    ${'$'}r = /botnet\.(com|net)/
                condition:
                    ${'$'}r
            }
            rule Xored {
                strings:
                    ${'$'}x = "secret" xor(1-255)
                condition:
                    any of them
            }
            rule Good {
                strings:
                    ${'$'}g = "ok"
                condition:
                    any of them
            }
            """.trimIndent()
        )

        assertEquals("RegexOnly ve Xored taranabilir degil", listOf("Good"), set.rules.map { it.name })
        assertEquals(2, set.unsupportedStrings)
        assertEquals(2, set.unparsableRules)
        assertTrue(set.isPartial)
    }

    @Test
    fun unparsableConditionFallsBackToAnyOfThemAndIsReported() {
        val set = parser.parseSource(
            """
            rule Filesize {
                strings:
                    ${'$'}a = "needle"
                condition:
                    ${'$'}a and filesize > 100 and for all i in (1..2) : (${'$'}a at i)
            }
            """.trimIndent()
        )
        val rule = set.rules.single()
        assertSame(YaraCondition.AnyOfThem, rule.condition)
        assertTrue(rule.approximateCondition)
        assertEquals(1, set.approximateConditions)
    }

    @Test
    fun countOfThemAndSelectorListsAreUnderstood() {
        val two = parser.parseSource(
            "rule N { strings: ${'$'}a = \"1\" ${'$'}b = \"2\" ${'$'}c = \"3\" condition: 2 of them }"
        ).rules.single()
        assertTrue(two.condition is YaraCondition.CountOfThem)
        assertEquals(2, (two.condition as YaraCondition.CountOfThem).count)

        val prefixed = parser.parseSource(
            "rule P { strings: ${'$'}aa = \"1\" ${'$'}ab = \"2\" ${'$'}z = \"3\" " +
                "condition: any of (${'$'}a*) }"
        ).rules.single()
        val ofThem = prefixed.condition as YaraCondition.OfThem
        assertEquals(listOf("a*"), ofThem.selectors)
        assertTrue(ofThem.evaluate(setOf("aa"), setOf("aa", "ab", "z")))
        assertFalse(ofThem.evaluate(setOf("z"), setOf("aa", "ab", "z")))
    }

    @Test
    fun commentsAndNestedBracesDoNotBreakRuleSplitting() {
        val set = parser.parseSource(
            """
            // leading comment
            import "pe"
            /* block
               comment with "quote" and } brace */
            rule AfterComments {
                strings:
                    ${'$'}a = "found"   // trailing comment
                condition:
                    any of them
            }
            """.trimIndent()
        )
        assertEquals(listOf("AfterComments"), set.rules.map { it.name })
        assertEquals(0, set.unparsableRules)
    }

    @Test
    fun metaDescriptionIsCaptured() {
        val set = parser.parseSource(
            """
            rule WithMeta {
                meta:
                    description = "aciklama burada \"kasnakli\""
                    author = "x"
                strings:
                    ${'$'}a = "m"
                condition:
                    any of them
            }
            """.trimIndent()
        )
        assertEquals("aciklama burada \"kasnakli\"", set.rules.single().description)
    }

    @Test
    fun tagsAfterRuleNameAreSkipped() {
        val set = parser.parseSource(
            "rule Tagged : rat android 1 {\n strings:\n  ${'$'}a = \"x\"\n condition:\n  any of them\n}"
        )
        assertEquals("Tagged", set.rules.single().name)
    }
}
