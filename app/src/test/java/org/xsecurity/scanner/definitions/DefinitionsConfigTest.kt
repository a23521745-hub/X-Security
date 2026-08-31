package org.xsecurity.scanner.definitions

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DefinitionsConfigTest {

    private val pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"

    @Test
    fun manifestUrlIsDerivedFromOtaManifestUrl() {
        val config = DefinitionsConfig.derive(
            otaManifestUrl = "https://github.com/a/b/releases/latest/download/update.json",
            otaPublicKeyPem = pem,
            otaAllowedHostsCsv = "github.com,objects.githubusercontent.com"
        )

        assertEquals(
            "https://github.com/a/b/releases/latest/download/definitions.json",
            config.manifestUrl
        )
        assertTrue(config.isConfigured)
        // Izinli hostlar korunur ve manifest host'u eklenir.
        assertTrue("github.com" in config.allowedHosts)
        assertTrue("objects.githubusercontent.com" in config.allowedHosts)
    }

    @Test
    fun blankOtaUrlDisablesDefinitionsChannel() {
        val config = DefinitionsConfig.derive(
            otaManifestUrl = "   ",
            otaPublicKeyPem = pem,
            otaAllowedHostsCsv = "github.com"
        )

        assertFalse(config.isConfigured)
        assertEquals("", config.manifestUrl)
    }

    @Test
    fun deriveManifestUrlRejectsMalformedUrls() {
        assertEquals("", DefinitionsConfig.deriveManifestUrl(""))
        assertEquals("", DefinitionsConfig.deriveManifestUrl("not-a-url"))
        assertEquals("", DefinitionsConfig.deriveManifestUrl("https://host"))
        // sonu egik cizgili adres: dizin olarak yorumlanir
        assertEquals(
            "https://host/definitions.json",
            DefinitionsConfig.deriveManifestUrl("https://host/")
        )
    }
}
