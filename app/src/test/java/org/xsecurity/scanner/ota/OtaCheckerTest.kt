package org.xsecurity.scanner.ota

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class OtaCheckerTest {

    private val hosts = setOf("updates.example.com")
    private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun manifest(
        versionCode: Long = 5,
        apkUrl: String = "https://updates.example.com/app.apk",
        size: Long = 100
    ): ByteArray = """
        {
          "versionCode": $versionCode,
          "versionName": "0.92.1",
          "apkUrl": "$apkUrl",
          "apkSha256": "${"a".repeat(64)}",
          "apkSizeBytes": $size,
          "releaseNotes": "test",
          "minSdk": 26
        }
    """.trimIndent().toByteArray()

    private fun sign(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(pair.private)
            update(data)
            sign()
        }

    @Test
    fun signedNewerManifestYieldsUpdateAvailable() {
        val manifestBytes = manifest(versionCode = 5)
        val outcome = OtaChecker.evaluate(
            manifestBytes = manifestBytes,
            signatureBytes = sign(manifestBytes),
            publicKey = pair.public,
            currentVersionCode = 4,
            hosts = hosts
        )
        assertTrue(outcome is OtaChecker.Outcome.UpdateAvailable)
        assertEquals(5L, (outcome as OtaChecker.Outcome.UpdateAvailable).info.versionCode)
    }

    @Test
    fun unsignedManifestIsRejectedBeforeParsing() {
        // Imza, baska/bos bir veriye ait olsa bile manifest ayrıştırılMAdan reddedilmeli.
        val outcome = OtaChecker.evaluate(
            manifestBytes = manifest(),
            signatureBytes = sign("baska veri".toByteArray()),
            publicKey = pair.public,
            currentVersionCode = 1,
            hosts = hosts
        )
        assertTrue(outcome is OtaChecker.Outcome.Error)
        assertTrue((outcome as OtaChecker.Outcome.Error).message.contains("imza", ignoreCase = true))
    }

    @Test
    fun signedButMalformedManifestIsRejected() {
        // Dogru imzali ama icerigi bozuk JSON: imza gecer, ayristirma reddeder.
        val bogus = "{ bu bir json degil ".toByteArray()
        val outcome = OtaChecker.evaluate(
            manifestBytes = bogus,
            signatureBytes = sign(bogus),
            publicKey = pair.public,
            currentVersionCode = 1,
            hosts = hosts
        )
        assertTrue(outcome is OtaChecker.Outcome.Error)
        assertTrue((outcome as OtaChecker.Outcome.Error).message.contains("ayrıştırılamadı"))
    }

    @Test
    fun signedManifestPointingAtDisallowedHostIsRejected() {
        val manifestBytes = manifest(apkUrl = "https://cdn.evil.net/app.apk")
        val outcome = OtaChecker.evaluate(
            manifestBytes = manifestBytes,
            signatureBytes = sign(manifestBytes),
            publicKey = pair.public,
            currentVersionCode = 1,
            hosts = hosts
        )
        assertTrue(outcome is OtaChecker.Outcome.Error)
    }

    @Test
    fun olderOrEqualVersionIsUpToDate() {
        val manifestBytes = manifest(versionCode = 3)
        val outcome = OtaChecker.evaluate(
            manifestBytes = manifestBytes,
            signatureBytes = sign(manifestBytes),
            publicKey = pair.public,
            currentVersionCode = 4,
            hosts = hosts
        )
        assertTrue(outcome is OtaChecker.Outcome.UpToDate)
    }

    @Test
    fun emptySignatureIsErrorNotUpdate() {
        val outcome = OtaChecker.evaluate(
            manifestBytes = manifest(),
            signatureBytes = ByteArray(0),
            publicKey = pair.public,
            currentVersionCode = 1,
            hosts = hosts
        )
        assertTrue(outcome is OtaChecker.Outcome.Error)
    }

    @Test
    fun embeddedSamplePublicKeyLoadsAndIsRsa() {
        // Gomulu ornek anahtar yuklenebilmeli (yapilandirma bozulursa erken fark edilsin).
        val key = RsaVerifier.loadPublicKey(OtaConfig.SAMPLE_PUBLIC_KEY_PEM)
        assertEquals("RSA", key.algorithm)
        // Bilinen anahtarin base64 govdesi 392 karakterdir (2048 bit SPKI).
        val body = OtaConfig.SAMPLE_PUBLIC_KEY_PEM
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("""\s""".toRegex(), "")
        assertTrue(Base64.getDecoder().decode(body).size > 250)
    }
}
