package org.xsecurity.scanner.ota

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * H-1 regresyon kilidi: uretim anahtari verilmemis derlemelerde OTA kanali
 * "yapilandirilmamis" olmalidir; ornek-anahtar geri donusu YOKTUR.
 */
class OtaConfigTest {

    private val pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"

    @Test
    fun blankKeyDisablesOtaChannel() {
        // Manifest adresi olsa bile anahtar bossa kanal kapalidir (H-1).
        val config = OtaConfig(
            manifestUrl = "https://example.com/update.json",
            publicKeyPem = "   ",
            allowedHosts = setOf("example.com")
        )
        assertFalse(config.isConfigured)
    }

    @Test
    fun blankManifestDisablesOtaChannel() {
        val config = OtaConfig(
            manifestUrl = "   ",
            publicKeyPem = pem,
            allowedHosts = emptySet()
        )
        assertFalse(config.isConfigured)
    }

    @Test
    fun fullConfigEnablesOtaChannel() {
        val config = OtaConfig(
            manifestUrl = "https://example.com/update.json",
            publicKeyPem = pem,
            allowedHosts = setOf("example.com")
        )
        assertTrue(config.isConfigured)
    }
}
