package org.xsecurity.scanner.definitions

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature

class DefinitionsCheckerTest {

    private val hosts = setOf("updates.example.com")
    private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun manifest(
        defVersion: Int = 2,
        minApp: Long = 1,
        url: String = "https://updates.example.com/rules.yar",
        size: Long = 100
    ): ByteArray = """
        {
          "schemaVersion": 1,
          "defVersion": $defVersion,
          "minAppVersionCode": $minApp,
          "generatedAt": "2026-08-29T12:00:00Z",
          "files": [{
            "kind": "YARA",
            "name": "rules.yar",
            "url": "$url",
            "sha256": "${"a".repeat(64)}",
            "sizeBytes": $size
          }]
        }
    """.trimIndent().toByteArray()

    private fun sign(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(pair.private)
            update(data)
            sign()
        }

    private fun evaluate(
        manifestBytes: ByteArray,
        signatureBytes: ByteArray,
        currentDefVersion: Int = 1,
        currentAppVersionCode: Long = 10
    ): DefinitionsChecker.Outcome = DefinitionsChecker.evaluate(
        manifestBytes = manifestBytes,
        signatureBytes = signatureBytes,
        publicKey = pair.public,
        currentDefVersion = currentDefVersion,
        currentAppVersionCode = currentAppVersionCode,
        hosts = hosts
    )

    @Test
    fun signedNewerManifestYieldsUpdateAvailable() {
        val bytes = manifest(defVersion = 2)
        val outcome = evaluate(bytes, sign(bytes), currentDefVersion = 1)

        assertTrue(outcome is DefinitionsChecker.Outcome.UpdateAvailable)
        assertEquals(2, (outcome as DefinitionsChecker.Outcome.UpdateAvailable).manifest.defVersion)
    }

    @Test
    fun sameDefVersionYieldsUpToDate() {
        val bytes = manifest(defVersion = 2)
        val outcome = evaluate(bytes, sign(bytes), currentDefVersion = 2)

        assertEquals(DefinitionsChecker.Outcome.UpToDate, outcome)
    }

    @Test
    fun tamperedManifestIsRejected() {
        val bytes = manifest(defVersion = 2)
        val tampered = manifest(defVersion = 3)
        val outcome = evaluate(tampered, sign(bytes), currentDefVersion = 1)

        assertTrue(outcome is DefinitionsChecker.Outcome.Error)
        assertTrue(
            (outcome as DefinitionsChecker.Outcome.Error).message.contains("dogrulanamadi")
        )
    }

    @Test
    fun foreignHostInFileUrlIsRejected() {
        val bytes = manifest(url = "https://evil.example.net/rules.yar")
        val outcome = evaluate(bytes, sign(bytes))

        assertTrue(outcome is DefinitionsChecker.Outcome.Error)
    }

    @Test
    fun minAppVersionTooHighIsRejected() {
        val bytes = manifest(minApp = 99)
        val outcome = evaluate(bytes, sign(bytes), currentAppVersionCode = 10)

        assertTrue(outcome is DefinitionsChecker.Outcome.Error)
    }

    @Test
    fun oversizeFileIsRejected() {
        val bytes = manifest(size = DefinitionsConfig.MAX_FILE_BYTES + 1)
        val outcome = evaluate(bytes, sign(bytes))

        assertTrue(outcome is DefinitionsChecker.Outcome.Error)
    }
}
