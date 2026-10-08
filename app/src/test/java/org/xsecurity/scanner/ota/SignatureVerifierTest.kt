package org.xsecurity.scanner.ota

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class SignatureVerifierTest {

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

        val key = SignatureVerifier.loadPublicKey(pem(pair.public))
        assertTrue(SignatureVerifier.verify(key, data, signature))
    }

    @Test
    fun acceptsBase64SignatureString() {
        val pair = newKeyPair()
        val data = "{\"versionCode\":5}".toByteArray()
        val signatureB64 = Base64.getEncoder().encodeToString(signSha256(pair.private, data))

        val key = SignatureVerifier.loadPublicKey(pem(pair.public))
        assertTrue(SignatureVerifier.verify(key, data, signatureB64))
    }

    @Test
    fun rejectsTamperedManifest() {
        val pair = newKeyPair()
        val data = "orijinal".toByteArray()
        val signature = signSha256(pair.private, data)

        val key = SignatureVerifier.loadPublicKey(pem(pair.public))
        assertFalse(SignatureVerifier.verify(key, "degistirilmis".toByteArray(), signature))
    }

    @Test
    fun rejectsSignatureFromDifferentKey() {
        val signer = newKeyPair()
        val verifierPair = newKeyPair()
        val data = "manifest".toByteArray()
        val signature = signSha256(signer.private, data)

        val verifierKey = SignatureVerifier.loadPublicKey(pem(verifierPair.public))
        assertFalse(SignatureVerifier.verify(verifierKey, data, signature))
    }

    @Test
    fun verifyFailsClosedOnGarbageInput() {
        val pair = newKeyPair()
        val key = SignatureVerifier.loadPublicKey(pem(pair.public))
        assertFalse(SignatureVerifier.verify(key, "x".toByteArray(), "!!!gecersiz base64!!!"))
    }

    @Test
    fun rejectsMalformedPublicKey() {
        var threw = false
        try {
            SignatureVerifier.loadPublicKey("bu bir anahtar degil")
        } catch (_: Throwable) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun ed25519SignaturesVerifyWhenSupported() {
        // JVM 15+/Android 13+ saglayicilari Ed25519 destekler; desteklenmeyen
        // ortamda bu test "destek yok" olarak bilincli olarak atlanir.
        val available = runCatching {
            java.security.KeyPairGenerator.getInstance("Ed25519")
        }.isSuccess
        if (!available) return

        val pair = java.security.KeyPairGenerator.getInstance("Ed25519").apply {
            // initialize not required for Ed25519
        }.generateKeyPair()
        val data = "ed25519-manifest".toByteArray()
        val signature = java.security.Signature.getInstance("Ed25519").run {
            initSign(pair.private)
            update(data)
            sign()
        }

        val key = SignatureVerifier.loadPublicKey(pem(pair.public))
        org.junit.Assert.assertEquals("Ed25519", SignatureVerifier.algorithmFor(key))
        assertTrue(SignatureVerifier.verify(key, data, signature))
        assertFalse(SignatureVerifier.verify(key, "degistirilmis".toByteArray(), signature))
    }
}
