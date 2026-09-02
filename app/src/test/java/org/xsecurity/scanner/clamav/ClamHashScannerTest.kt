package org.xsecurity.scanner.clamav

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ClamHashScannerTest {

    private val scanner = ClamHashScanner()
    private val eicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"

    private fun tempFile(content: ByteArray, suffix: String = ".bin"): File {
        val file = File.createTempFile("xsec-hashscan-", suffix)
        file.deleteOnExit()
        file.writeBytes(content)
        return file
    }

    @Test
    fun eicarIsDetectedByAllThreeAlgorithms() {
        val md5 = "44d88612fea8a8f36de82e1278abb02f"
        val sha1 = "3395856ce81f2b7382dee72602f798b642f14140"
        val sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        val db = ClamHashDatabaseParser().parseLines(
            listOf(
                "$md5:68:Eicar.Test-File",
                "$sha1:68:Eicar.Test-File",
                "$sha256:68:Eicar.Test-File"
            )
        )

        val outcome = scanner.scan(tempFile(eicar.toByteArray(), ".eicar"), db)

        assertEquals(3, outcome.hits.size)
        assertEquals(68L, outcome.scannedBytes)
        val algorithms = outcome.hits.map { it.algorithm }.toSet()
        assertEquals(
            setOf(
                ClamHashDatabaseParser.Algorithm.MD5,
                ClamHashDatabaseParser.Algorithm.SHA_1,
                ClamHashDatabaseParser.Algorithm.SHA_256
            ),
            algorithms
        )
        assertTrue(outcome.hits.all { it.name == "Eicar.Test-File" })
        assertTrue(outcome.hits.all { it.fileSize == 68L })
    }

    @Test
    fun matchingHashWithWrongFileSizeIsRejected() {
        val digest = sha256Of(eicar.toByteArray())
        val db = ClamHashDatabaseParser().parseLines(
            listOf("$digest:1:Eicar.Test-File") // yanlis boyut: 1 bayt bekleniyor
        )
        val outcome = scanner.scan(tempFile(eicar.toByteArray(), ".eicar"), db)
        assertTrue("boyut uyusmazliginda eslesme olmamali", outcome.hits.isEmpty())
    }

    @Test
    fun unknownSizeMatchesByHashAlone() {
        val digest = sha256Of(eicar.toByteArray())
        val db = ClamHashDatabaseParser().parseLines(
            listOf("$digest:-1:Eicar.Test-File")
        )
        val outcome = scanner.scan(tempFile(eicar.toByteArray(), ".eicar"), db)
        assertEquals(1, outcome.hits.size)
        assertEquals("Eicar.Test-File", outcome.hits.single().name)
        assertEquals(ClamHashDatabaseParser.Algorithm.SHA_256, outcome.hits.single().algorithm)
    }

    @Test
    fun cleanFileProducesNoHits() {
        val digest = sha256Of(eicar.toByteArray())
        val db = ClamHashDatabaseParser().parseLines(
            listOf("$digest:-1:Eicar.Test-File")
        )
        val outcome = scanner.scan(tempFile("temiz icerik".toByteArray()), db)
        assertTrue(outcome.hits.isEmpty())
        assertEquals(12L, outcome.scannedBytes)
    }

    @Test
    fun emptyDatabaseShortCircuits() {
        val db = ClamHashDatabaseParser().parseLines(emptyList())
        val outcome = scanner.scan(tempFile(eicar.toByteArray(), ".eicar"), db)
        assertTrue(outcome.hits.isEmpty())
        assertEquals(0L, outcome.scannedBytes)
    }

    @Test
    fun progressCallbackTracksBytes() {
        val digest = sha256Of(eicar.toByteArray())
        val db = ClamHashDatabaseParser().parseLines(listOf("$digest:-1:Eicar.Test-File"))
        val seen = ArrayList<Long>()
        scanner.scan(tempFile(eicar.toByteArray(), ".eicar"), db) { bytes -> seen += bytes }
        assertTrue("ilerleme bildirilmeli", seen.isNotEmpty())
        // Son bildirim dosya boyutuna esit olmali (tek okuma gecisi).
        assertEquals(68L, seen.last())
    }

    private fun sha256Of(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
