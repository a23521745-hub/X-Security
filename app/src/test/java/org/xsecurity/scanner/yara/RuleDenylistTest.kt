package org.xsecurity.scanner.yara

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.engine.ApkContentScanner
import org.xsecurity.scanner.engine.ApkScannerEngine
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * P0 false-positive brake regression lock (v19 live incident: system apps flagged by the
 * accessibility/overlay permission-combo heuristic).
 *
 * `Android_Suspicious_Accessibility_Overlay_*` is denylisted at LOAD time: it never reaches the
 * scanner, from any rule file, and the skip is reported (never silent).
 */
class RuleDenylistTest {

    private val parser = YaraRuleParser()

    @Test
    fun accessibilityOverlayFamilyIsDenied() {
        assertTrue(RuleDenylist.isDenied("Android_Suspicious_Accessibility_Overlay_Combo"))
        assertTrue(RuleDenylist.isDenied("Android_Suspicious_Accessibility_Overlay_V2"))
        assertFalse("the family pattern must not match the bare stem", RuleDenylist.isDenied("Android_Suspicious_Accessibility_Overlay"))
        assertFalse(RuleDenylist.isDenied("Android_Metasploit_Stage_Payload"))
        assertFalse(RuleDenylist.isDenied("Eicar_Test_File"))
        assertFalse(RuleDenylist.isDenied(null))
        assertFalse(RuleDenylist.isDenied(""))
    }

    @Test
    fun parserSkipsDeniedRulesAndReportsThem() {
        val set = parser.parseSource(
            """
            rule Android_Suspicious_Accessibility_Overlay_Combo
            {
                strings:
                    ${'$'}a = "unique-denylist-fixture-aaa" ascii
                condition:
                    any of them
            }
            rule Android_Test_Kept_Rule
            {
                strings:
                    ${'$'}a = "unique-denylist-fixture-bbb" ascii
                condition:
                    any of them
            }
            """.trimIndent()
        )
        assertEquals(listOf("Android_Test_Kept_Rule"), set.rules.map { it.name })
        assertEquals(listOf("Android_Suspicious_Accessibility_Overlay_Combo"), set.deniedRuleNames)
        assertTrue(set.skippedRuleNames.contains("Android_Suspicious_Accessibility_Overlay_Combo"))
        assertTrue(set.problems.single().startsWith(RuleDenylist.PROBLEM_PREFIX))
        assertTrue(set.problems.single().contains("Android_Suspicious_Accessibility_Overlay_Combo"))
        // The skip is not a parse loss: it must not be reported as unparsable/approximated.
        assertEquals(0, set.unparsableRules)
        assertEquals(0, set.approximateConditions)
    }

    @Test
    fun shippedCuratedFileLoadsWithoutTheIncidentRule() {
        val set = parser.parse(repoFile("definitions/rules.yar"))
        assertFalse(set.rules.any { it.name == "Android_Suspicious_Accessibility_Overlay_Combo" })
        assertTrue(set.deniedRuleNames.contains("Android_Suspicious_Accessibility_Overlay_Combo"))
        // Everything else still loads.
        assertTrue(set.ruleCount >= 5)
        assertEquals(0, set.unparsableRules)
        assertEquals(0, set.unsupportedStrings)
        assertEquals(0, set.approximateConditions)
    }

    /**
     * The live-incident fixture: an APK manifest that would satisfy the denied heuristic.
     * With the shipped rule set the scan must come back clean of that rule; a renamed copy of
     * the same rule (not denylisted) DOES match the same fixture, proving the fixture triggers
     * the heuristic and that only the denylist stops it.
     */
    @Test
    fun accessibilityOverlayFixtureNoLongerMatchesTheShippedRuleSet() {
        val fixture = File.createTempFile("xsec-overlay-", ".apk")
        fixture.deleteOnExit()
        FileOutputStream(fixture).use { output ->
            ZipOutputStream(output).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml").apply { method = ZipEntry.DEFLATED })
                // 3 of the 4 wide-encoded permissions are enough for `3 of them`.
                zip.write("android.permission.BIND_ACCESSIBILITY_SERVICE".toByteArray(Charsets.UTF_16LE))
                zip.write("android.permission.SYSTEM_ALERT_WINDOW".toByteArray(Charsets.UTF_16LE))
                zip.write("android.permission.RECEIVE_SMS".toByteArray(Charsets.UTF_16LE))
                zip.closeEntry()
            }
        }

        val engine = ApkScannerEngine.load(
            repoFile("definitions/rules.yar"),
            repoFile("definitions/signatures.ndb")
        ).getOrThrow()
        val result = engine.scan(fixture)
        assertTrue("incident rule must never fire: ${result.threats.map { it.name }}",
            result.threats.none { it.name == "Android_Suspicious_Accessibility_Overlay_Combo" })

        // Control: the same rule under a non-denylisted ID still matches the same fixture
        // (scanned the same way the engine does: raw bytes + decompressed ZIP entries).
        val controlText = repoFile("definitions/rules.yar").readText()
            .replace("Android_Suspicious_Accessibility_Overlay_Combo", "XTest_Accessibility_Overlay_Combo")
        val control = parser.parseSource(controlText)
        assertTrue(control.deniedRuleNames.isEmpty())
        val scanner = YaraScanner()
        val compiled = scanner.compile(control.rules)
        val matched = ApkContentScanner.withEntries(fixture) { entrySources, _ ->
            scanner.matchBundle(compiled, fixture, entrySources, ApkContentScanner.MAX_TOTAL_ENTRY_BYTES)
                .matches.any { it.ruleName == "XTest_Accessibility_Overlay_Combo" }
        }
        assertTrue("control rule must match the fixture", matched)
    }

    private fun repoFile(path: String): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".")
        while (dir != null) {
            val candidate = File(dir, path)
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        throw AssertionError("repository file not found: $path (user.dir=${System.getProperty("user.dir")})")
    }
}
