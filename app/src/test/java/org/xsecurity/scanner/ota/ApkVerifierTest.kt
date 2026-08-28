package org.xsecurity.scanner.ota

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest

class ApkVerifierTest {

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun newTarget(): File =
        File.createTempFile("xsec-ota-", ".apk").apply { deleteOnExit(); delete() }

    @Test
    fun acceptsStreamMatchingHashAndSize() {
        val payload = "fake-apk-content".toByteArray()
        val target = newTarget()

        val result = ApkVerifier.verifyToFile(
            input = ByteArrayInputStream(payload),
            expectedSha256 = sha256Hex(payload),
            expectedSize = payload.size.toLong(),
            maxBytes = 1024,
            target = target
        )

        assertTrue((result as? ApkVerifier.Result.Failure)?.message ?: "success", result is ApkVerifier.Result.Success)
        val success = result as ApkVerifier.Result.Success
        assertEquals(payload.size.toLong(), success.bytes)
        assertEquals(sha256Hex(payload), success.sha256)
        assertTrue(target.isFile)
    }

    @Test
    fun rejectsHashMismatchAndDeletesFile() {
        val payload = "payload".toByteArray()
        val target = newTarget()

        val result = ApkVerifier.verifyToFile(
            input = ByteArrayInputStream(payload),
            expectedSha256 = "b".repeat(64),
            expectedSize = payload.size.toLong(),
            maxBytes = 1024,
            target = target
        )

        assertTrue(result is ApkVerifier.Result.Failure)
        assertTrue((result as ApkVerifier.Result.Failure).message.contains("SHA-256"))
        assertTrue("uyumsuz dosya silinmeli", !target.exists())
    }

    @Test
    fun rejectsSizeMismatch() {
        val payload = "payload".toByteArray()
        val target = newTarget()

        val result = ApkVerifier.verifyToFile(
            input = ByteArrayInputStream(payload),
            expectedSha256 = sha256Hex(payload),
            expectedSize = payload.size.toLong() + 10,
            maxBytes = 1024,
            target = target
        )

        assertTrue(result is ApkVerifier.Result.Failure)
        assertTrue(!target.exists())
    }

    @Test
    fun rejectsStreamExceedingMaxBytes() {
        val payload = ByteArray(5000) { 0x41 }
        val target = newTarget()

        val result = ApkVerifier.verifyToFile(
            input = ByteArrayInputStream(payload),
            expectedSha256 = sha256Hex(payload),
            expectedSize = payload.size.toLong(),
            maxBytes = 1024,
            target = target
        )

        assertTrue(result is ApkVerifier.Result.Failure)
        assertTrue((result as ApkVerifier.Result.Failure).message.contains("boyut"))
        assertTrue(!target.exists())
    }

    @Test
    fun rejectsEmptyStream() {
        val target = newTarget()
        val result = ApkVerifier.verifyToFile(
            input = ByteArrayInputStream(ByteArray(0)),
            expectedSha256 = sha256Hex(ByteArray(0)),
            expectedSize = 0,
            maxBytes = 1024,
            target = target
        )
        assertTrue(result is ApkVerifier.Result.Failure)
    }
}
