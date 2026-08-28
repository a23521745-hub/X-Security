package org.xsecurity.scanner.ota

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class UpdateInfoTest {

    private val sha = "a".repeat(64)

    private fun manifest(
        versionCode: String = "5",
        versionName: String = "0.92.1",
        apkUrl: String = "https://updates.example.com/x-security/app-release.apk",
        apkSha256: String = sha,
        apkSize: String = "1234567",
        forceUpdate: String? = null,
        changelog: String? = null
    ): String = """
        {
          "versionCode": $versionCode,
          "versionName": "$versionName",
          "apkUrl": "$apkUrl",
          "apkSha256": "$apkSha256",
          "apkSizeBytes": $apkSize,
          "releaseNotes": "Duzeltmeler.",
          "minSdk": 26${if (forceUpdate != null) ",\n          \"forceUpdate\": $forceUpdate" else ""}${if (changelog != null) ",\n          \"changelog\": $changelog" else ""}
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
            manifest(forceUpdate = "true", changelog = "\"- resume destegi\n- Ed25519\"").toByteArray()
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
            manifest(forceUpdate = "true", changelog = "\"- a\n- b\"").toByteArray()
        )
        assertEquals(info, UpdateInfo.fromJson(info.toJson()))
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
