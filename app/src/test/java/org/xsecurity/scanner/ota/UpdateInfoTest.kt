package org.xsecurity.scanner.ota

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class UpdateInfoTest {

    private val sha = "a".repeat(64)

    /**
     * Degerleri JSON kurallarina gore escape eder: string icinde ham kontrol
     * karakteri (orn. satir sonu) gecerli degildir ve gercek org.json bunu
     * "Unterminated string" JSONException ile reddeder.
     */
    private fun jsonString(value: String): String = buildString {
        append('"')
        for (ch in value) when (ch) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            '\b' -> append("\\b")
            '\u000C' -> append("\\f")
            else -> if (ch.code < 0x20) append("\\u%04x".format(ch.code)) else append(ch)
        }
        append('"')
    }

    private fun manifest(
        versionCode: String = "5",
        versionName: String = "0.92.1",
        apkUrl: String = "https://updates.example.com/x-security/app-release.apk",
        apkSha256: String = sha,
        apkSize: String = "1234567",
        forceUpdate: Boolean? = null,
        changelog: String? = null
    ): String = """
        {
          "versionCode": $versionCode,
          "versionName": "$versionName",
          "apkUrl": "$apkUrl",
          "apkSha256": "$apkSha256",
          "apkSizeBytes": $apkSize,
          "releaseNotes": "Duzeltmeler.",
          "minSdk": 26${if (forceUpdate != null) ",\n          \"forceUpdate\": $forceUpdate" else ""}${if (changelog != null) ",\n          \"changelog\": ${jsonString(changelog)}" else ""}
        }
    """.trimIndent()

    @Test
    fun parsesValidManifest() {
        val info = UpdateInfo.parse(manifest().toByteArray())
        assertEquals(5L, info.versionCode)
        assertEquals("0.92.1", info.versionName)
        assertEquals(1234567L, info.apkSizeBytes)
        assertEquals(26, info.minSdk)
        assertEquals(sha, info.apkSha256)
    }

    @Test
    fun roundTripsThroughJson() {
        val info = UpdateInfo.parse(manifest().toByteArray())
        val again = UpdateInfo.fromJson(info.toJson())
        assertEquals(info, again)
    }

    @Test
    fun parsesForceUpdateAndChangelog() {
        val info = UpdateInfo.parse(
            manifest(forceUpdate = true, changelog = "- resume destegi\n- Ed25519").toByteArray()
        )
        assertEquals(true, info.forceUpdate)
        assertEquals("- resume destegi\n- Ed25519", info.changelog)
        assertEquals("- resume destegi\n- Ed25519", info.displayNotes)
    }

    @Test
    fun forceUpdateAndChangelogDefaultWhenAbsent() {
        val info = UpdateInfo.parse(manifest().toByteArray())
        assertEquals(false, info.forceUpdate)
        assertEquals("", info.changelog)
        // Not alani yoksa displayNotes kisa not'a duser.
        assertEquals("Duzeltmeler.", info.displayNotes)
    }

    @Test
    fun extendedManifestRoundTripsThroughJson() {
        val info = UpdateInfo.parse(
            manifest(forceUpdate = true, changelog = "- a\n- b").toByteArray()
        )
        assertEquals(info, UpdateInfo.fromJson(info.toJson()))
    }

    @Test
    fun rejectsRawNewlineInsideStringValue() {
        // RFC 8259: string icindeki kontrol karakterleri escape edilmek zorunda.
        // Gercek org.json ham '\n' gordugunde "Unterminated string" JSONException
        // firlatir; uygulama da bozuk manifesti kabul etmemelidir (fail-closed).
        val invalid = manifest(changelog = "- ham\nsatir sonu")
            .replace("- ham\\nsatir sonu", "- ham\nsatir sonu")
        assertThrows(org.json.JSONException::class.java) {
            UpdateInfo.parse(invalid.toByteArray())
        }
    }

    @Test
    fun rejectsNonPositiveVersionCode() {
        assertThrows(IllegalArgumentException::class.java) {
            UpdateInfo.parse(manifest(versionCode = "0").toByteArray())
        }
    }

    @Test
    fun rejectsMissingVersionCode() {
        assertThrows(IllegalArgumentException::class.java) {
            UpdateInfo.parse(manifest(versionCode = "-99").toByteArray())
        }
    }

    @Test
    fun rejectsBadSha256() {
        assertThrows(IllegalArgumentException::class.java) {
            UpdateInfo.parse(manifest(apkSha256 = "xyz").toByteArray())
        }
    }

    @Test
    fun rejectsUppercaseShortSha256() {
        assertThrows(IllegalArgumentException::class.java) {
            UpdateInfo.parse(manifest(apkSha256 = "ABCDEF").toByteArray())
        }
    }

    @Test
    fun rejectsNonPositiveSize() {
        assertThrows(IllegalArgumentException::class.java) {
            UpdateInfo.parse(manifest(apkSize = "-1").toByteArray())
        }
    }

    @Test
    fun rejectsBlankApkUrl() {
        assertThrows(IllegalArgumentException::class.java) {
            UpdateInfo.parse(manifest(apkUrl = "   ").toByteArray())
        }
    }

    @Test
    fun rejectsBlankVersionName() {
        assertThrows(IllegalArgumentException::class.java) {
            UpdateInfo.parse(manifest(versionName = "  ").toByteArray())
        }
    }
}
