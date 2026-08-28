package org.xsecurity.scanner.ota

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class RsaVerifierTest {

    private fun newKeyPair() = KeyPairGenerator.getInstance("RSA").apply {
        initialize(2048)
    }.generateKeyPair()

    private fun pem(publicKey: java.security.PublicKey): String {
        val base64 = Base64.getEncoder().encodeToString(publicKey.encoded)
        return "-----BEGIN PUBLIC KEY-----\n$base64\n-----END PUBLIC KEY-----\n"
    }

    private fun signSha256(privateKey: java.security.PrivateKey, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withRSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    @Test
    fun verifiesAuthenticSignature() {
        val pair = newKeyPair()
        val data = "imzali manifest govdesi".toByteArray()
        val signature = signSha256(pair.private, data)

        val key = RsaVerifier.loadPublicKey(pem(pair.public))
        assertTrue(RsaVerifier.verify(key, data, signature))
    }

    @Test
    fun acceptsBase64SignatureString() {
        val pair = newKeyPair()
        val data = "{\"versionCode\":5}".toByteArray()
        val signatureB64 = Base64.getEncoder().encodeToString(signSha256(pair.private, data))

        val key = RsaVerifier.loadPublicKey(pem(pair.public))
        assertTrue(RsaVerifier.verify(key, data, signatureB64))
    }

    @Test
    fun rejectsTamperedManifest() {
        val pair = newKeyPair()
        val data = "orijinal".toByteArray()
        val signature = signSha256(pair.private, data)

        val key = RsaVerifier.loadPublicKey(pem(pair.public))
        assertFalse(RsaVerifier.verify(key, "degistirilmis".toByteArray(), signature))
    }

    @Test
    fun rejectsSignatureFromDifferentKey() {
        val signer = newKeyPair()
        val verifierPair = newKeyPair()
        val data = "manifest".toByteArray()
        val signature = signSha256(signer.private, data)

        val verifierKey = RsaVerifier.loadPublicKey(pem(verifierPair.public))
        assertFalse(RsaVerifier.verify(verifierKey, data, signature))
    }

    @Test
    fun verifyFailsClosedOnGarbageInput() {
        val pair = newKeyPair()
        val key = RsaVerifier.loadPublicKey(pem(pair.public))
        assertFalse(RsaVerifier.verify(key, "x".toByteArray(), "!!!gecersiz base64!!!"))
    }

    @Test
    fun rejectsMalformedPublicKey() {
        var threw = false
        try {
            RsaVerifier.loadPublicKey("bu bir anahtar degil")
        } catch (_: Throwable) {
            threw = true
        }
        assertTrue(threw)
    }
}
