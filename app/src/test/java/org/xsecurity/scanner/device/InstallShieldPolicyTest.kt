package org.xsecurity.scanner.device

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.xsecurity.scanner.engine.ScanStatus
import org.xsecurity.scanner.engine.ThreatMatch

class InstallShieldPolicyTest {

    private val self = "org.xsecurity.scanner"

    @Test
    fun scansFreshInstall() {
        assertEquals(
            InstallShieldPolicy.Verdict.SCAN,
            InstallShieldPolicy.decide(InstallShieldPolicy.ACTION_PACKAGE_ADDED, "com.new", replacing = false, selfPackage = self)
        )
    }

    @Test
    fun scansReplacedButNotTheAddedHalfOfAnUpdate() {
        assertEquals(
            InstallShieldPolicy.Verdict.SKIP_REPLACING_DUPLICATE,
            InstallShieldPolicy.decide(InstallShieldPolicy.ACTION_PACKAGE_ADDED, "com.upd", replacing = true, selfPackage = self)
        )
        assertEquals(
            InstallShieldPolicy.Verdict.SCAN,
            InstallShieldPolicy.decide(InstallShieldPolicy.ACTION_PACKAGE_REPLACED, "com.upd", replacing = true, selfPackage = self)
        )
    }

    @Test
    fun skipsSelfUnknownActionAndMissingPackage() {
        assertEquals(
            InstallShieldPolicy.Verdict.SKIP_SELF,
            InstallShieldPolicy.decide(InstallShieldPolicy.ACTION_PACKAGE_REPLACED, self, replacing = true, selfPackage = self)
        )
        assertEquals(
            InstallShieldPolicy.Verdict.SKIP_UNKNOWN_ACTION,
            InstallShieldPolicy.decide("android.intent.action.PACKAGE_REMOVED", "com.x", replacing = false, selfPackage = self)
        )
        assertEquals(
            InstallShieldPolicy.Verdict.SKIP_UNKNOWN_ACTION,
            InstallShieldPolicy.decide(null, "com.x", replacing = false, selfPackage = self)
        )
        assertEquals(
            InstallShieldPolicy.Verdict.SKIP_NO_PACKAGE,
            InstallShieldPolicy.decide(InstallShieldPolicy.ACTION_PACKAGE_ADDED, "", replacing = false, selfPackage = self)
        )
    }

    @Test
    fun extractsPackageNameFromIntentData() {
        assertEquals("com.example.app", InstallShieldPolicy.packageNameFromData("package:com.example.app"))
        assertEquals("com.example.app", InstallShieldPolicy.packageNameFromData("com.example.app"))
        assertNull(InstallShieldPolicy.packageNameFromData("package:"))
        assertNull(InstallShieldPolicy.packageNameFromData(null))
    }

    @Test
    fun alertDecisionFollowsResultAndQuietPreference() {
        val infected = AppScanEntry("a", "A", ScanStatus.THREATS_FOUND, threats = listOf(ThreatMatch("YARA", "X")))
        val clean = AppScanEntry("b", "B", ScanStatus.CLEAN)
        val failed = AppScanEntry("c", "C", ScanStatus.FAILED, errorMessage = "io")
        assertEquals(InstallShieldPolicy.Alert.THREAT, InstallShieldPolicy.alertFor(infected, quietWhenClean = true))
        assertEquals(InstallShieldPolicy.Alert.THREAT, InstallShieldPolicy.alertFor(infected, quietWhenClean = false))
        assertEquals(InstallShieldPolicy.Alert.NONE, InstallShieldPolicy.alertFor(clean, quietWhenClean = true))
        assertEquals(InstallShieldPolicy.Alert.CLEAN_INFO, InstallShieldPolicy.alertFor(clean, quietWhenClean = false))
        assertEquals(InstallShieldPolicy.Alert.FAILED_INFO, InstallShieldPolicy.alertFor(failed, quietWhenClean = true))
    }

    @Test
    fun protectionModeParsingAndShieldGate() {
        assertEquals(ProtectionMode.INSTALL_ONLY, ProtectionSettings.parseMode(null))
        assertEquals(ProtectionMode.INSTALL_ONLY, ProtectionSettings.parseMode("garbage"))
        assertEquals(ProtectionMode.ALWAYS, ProtectionSettings.parseMode("ALWAYS"))
        assertEquals(ProtectionMode.OFF, ProtectionSettings.parseMode("OFF"))
        assertTrue(ProtectionSettings.installShieldEnabled(ProtectionMode.ALWAYS))
        assertTrue(ProtectionSettings.installShieldEnabled(ProtectionMode.INSTALL_ONLY))
        assertFalse(ProtectionSettings.installShieldEnabled(ProtectionMode.OFF))
    }
}
