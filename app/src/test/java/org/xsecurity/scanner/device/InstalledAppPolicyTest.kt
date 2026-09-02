package org.xsecurity.scanner.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstalledAppPolicyTest {

    private val options = InstalledAppPolicy.Options(includeSystemApps = false, selfPackage = "org.xsecurity.scanner")

    private fun app(
        pkg: String,
        source: String = "/data/app/$pkg-1/base.apk",
        flags: Int = 0,
        updated: Long = 0L,
        label: String = pkg
    ) = InstalledApp(packageName = pkg, label = label, sourceDir = source, flags = flags, lastUpdateTime = updated)

    @Test
    fun skipsOwnPackage() {
        assertFalse(InstalledAppPolicy.shouldScan(app("org.xsecurity.scanner"), options))
    }

    @Test
    fun scansUserAppsByDefault() {
        assertTrue(InstalledAppPolicy.shouldScan(app("com.example.user"), options))
    }

    @Test
    fun skipsPureSystemAppsUnlessRequested() {
        val system = app("com.android.settings", source = "/system/priv-app/Settings/Settings.apk", flags = InstalledApp.FLAG_SYSTEM)
        assertFalse(InstalledAppPolicy.shouldScan(system, options))
        assertTrue(InstalledAppPolicy.shouldScan(system, options.copy(includeSystemApps = true)))
    }

    @Test
    fun updatedSystemAppsAreAlwaysScanned() {
        val updated = app(
            "com.vendor.updated",
            flags = InstalledApp.FLAG_SYSTEM or InstalledApp.FLAG_UPDATED_SYSTEM_APP
        )
        assertTrue(InstalledAppPolicy.shouldScan(updated, options))
    }

    @Test
    fun rejectsBlankOrRelativeSourceDir() {
        assertFalse(InstalledAppPolicy.hasScannablePath(app("a", source = "")))
        assertFalse(InstalledAppPolicy.hasScannablePath(app("a", source = "base.apk")))
        assertTrue(InstalledAppPolicy.hasScannablePath(app("a", source = "/data/app/~~x/a-1/base.apk")))
        assertTrue(InstalledAppPolicy.hasScannablePath(app("a", source = "/system/app/Foo/Foo.apk")))
    }

    @Test
    fun ordersUserAppsFirstThenMostRecentlyUpdated() {
        val list = listOf(
            app("com.old", updated = 10L),
            app("com.android.sys", source = "/system/app/S/S.apk", flags = InstalledApp.FLAG_SYSTEM, updated = 999L),
            app("com.new", updated = 50L),
            app("org.xsecurity.scanner", updated = 5000L),
            app("com.new", updated = 50L)
        )
        val targets = InstalledAppPolicy.selectTargets(list, options.copy(includeSystemApps = true))
        assertEquals(listOf("com.new", "com.old", "com.android.sys"), targets.map { it.packageName })
    }

    @Test
    fun apkPathsIncludeSplitsWithoutDuplicates() {
        val app = InstalledApp(
            packageName = "a",
            label = "",
            sourceDir = "/data/app/a/base.apk",
            splitSourceDirs = listOf("/data/app/a/split_config.arm64.apk", "/data/app/a/base.apk", "")
        )
        assertEquals(listOf("/data/app/a/base.apk", "/data/app/a/split_config.arm64.apk"), app.apkPaths)
        assertEquals("a", app.displayName)
    }
}
