package org.xsecurity.scanner.ota

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Indirme yoneticisinin **saf karar** fonksiyonlari ve dosya dogrulayicisi
 * icin birim testleri. Gercek HTTP baglantisi gerektiren kisimlar entegrasyon
 * ortaminda; burada yalnizca deterministik mantik sartinir:
 *  - hangi yanit kodunda devam/bastan baslama/dogrulama karari verilmeli,
 *  - `verifyFile` dogru dosyayi kabul, bozuk/hash uyusmayan dosyayi reddetmeli.
 */
class ApkDownloaderTest {

    @Test
    fun partialContentResponseMeansAppend() {
        assertEquals(
            ApkDownloader.ResumeMode.APPEND,
            ApkDownloader.resumeMode(existingBytes = 500, expectedSize = 1000, responseCode = 206)
        )
    }

    @Test
    fun fullContentResponseMeansRestart() {
        assertEquals(
            ApkDownloader.ResumeMode.RESTART,
            ApkDownloader.resumeMode(existingBytes = 500, expectedSize = 1000, responseCode = 200)
        )
    }

    @Test
    fun noExistingBytesMeansRestart() {
        assertEquals(
            ApkDownloader.ResumeMode.RESTART,
            ApkDownloader.resumeMode(existingBytes = 0, expectedSize = 1000, responseCode = 206)
        )
    }

    @Test
    fun rangeNotSatisfiableOnCompletePartMeansFinalize() {
        assertEquals(
            ApkDownloader.ResumeMode.FINALIZE_EXISTING,
            ApkDownloader.resumeMode(existingBytes = 1000, expectedSize = 1000, responseCode = 416)
        )
    }

    @Test
    fun rangeNotSatisfiableOnIncompletePartMeansRestart() {
        assertEquals(
            ApkDownloader.ResumeMode.RESTART,
            ApkDownloader.resumeMode(existingBytes = 400, expectedSize = 1000, responseCode = 416)
        )
    }

    @Test
    fun verifyFileAcceptsIntactFile() {
        val payload = "fake-apk-bytes".toByteArray()
        val file = tempFile(payload)

        val result = ApkVerifier.verifyFile(
            file = file,
            expectedSha256 = sha256Hex(payload),
            expectedSize = payload.size.toLong(),
            maxBytes = 1024
        )
        assertTrue((result as? ApkVerifier.Result.Failure)?.message ?: "success", result is ApkVerifier.Result.Success)
        assertEquals(payload.size.toLong(), (result as ApkVerifier.Result.Success).bytes)
        file.delete()
    }

    @Test
    fun verifyFileRejectsTamperedFile() {
        val file = tempFile("tampered-content".toByteArray())
        val result = ApkVerifier.verifyFile(
            file = file,
            expectedSha256 = "b".repeat(64),
            expectedSize = "tampered-content".toByteArray().size.toLong(),
            maxBytes = 1024
        )
        assertTrue(result is ApkVerifier.Result.Failure)
        assertTrue((result as ApkVerifier.Result.Failure).message.contains("SHA-256"))
        file.delete()
    }

    @Test
    fun verifyFileRejectsSizeMismatch() {
        val file = tempFile("12345".toByteArray())
        val result = ApkVerifier.verifyFile(
            file = file,
            expectedSha256 = sha256Hex("12345".toByteArray()),
            expectedSize = 99L,
            maxBytes = 1024
        )
        assertTrue(result is ApkVerifier.Result.Failure)
        assertTrue((result as ApkVerifier.Result.Failure).message.contains("boyut"))
        file.delete()
    }

    @Test
    fun verifyFileRejectsMissingFile() {
        val result = ApkVerifier.verifyFile(
            file = File("böyle-bir-dosya-yok-${System.nanoTime()}.apk"),
            expectedSha256 = "a".repeat(64),
            expectedSize = 1L,
            maxBytes = 1024
        )
        assertTrue(result is ApkVerifier.Result.Failure)
    }

    private fun tempFile(bytes: ByteArray): File {
        val file = File.createTempFile("xsec-resume-", ".apk")
        file.deleteOnExit()
        file.writeBytes(bytes)
        return file
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
