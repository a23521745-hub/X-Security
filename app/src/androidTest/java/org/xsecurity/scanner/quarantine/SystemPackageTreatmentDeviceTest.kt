package org.xsecurity.scanner.quarantine

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.xsecurity.scanner.autopilot.SystemPackageSafelist
import org.xsecurity.scanner.autopilot.SystemPackageTreatment

/**
 * P0 emergency brake on a device: a system / updated-system package never reaches the system
 * uninstall confirmation from our UI, and the scan-result treatment says "no action taken".
 */
@RunWith(AndroidJUnit4::class)
class SystemPackageTreatmentDeviceTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun platformPackageIsClassifiedAsSystem() {
        // "android" is a FLAG_SYSTEM package on every Android build.
        org.junit.Assert.assertTrue(SystemPackageSafelist.isSystemPackage(context, "android"))
        org.junit.Assert.assertTrue(SystemPackageTreatment.isSafelisted(true))
        org.junit.Assert.assertFalse(SystemPackageTreatment.allowsRemovalActions(true))
    }

    @Test fun systemPackageNeverGetsAnUninstallIntent() {
        assertNull(QuarantineUserActions.uninstallIntent(context, "android", null))
        // A non-system, not-installed package is not safelisted; the intent is still only a
        // request for the system confirmation screen.
        assertNotNull(QuarantineUserActions.uninstallIntent(context, "com.example.not.installed", null))
    }
}
