package org.xsecurity.scanner.clamav

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ClamAvScannerTest {

    private fun tempFile(bytes: ByteArray): File {
        val file = File.createTempFile("xsec-", ".apk")
        file.deleteOnExit()
        file.writeBytes(bytes)
        return file
    }

    private val abcde = "ABCDE".encodeToByteArray()

    @Test
    fun detectsSignatureAnywhereWhenUnanchored() {
        val data = ByteArray(70) { '.'.code.toByte() } + abcde + ByteArray(500) { '-'.code.toByte() }
        val db = ClamAvDatabaseParser().parseLines(listOf("Any.Pos:0:0:4142434445"))
        val outcome = ClamAvScanner(chunkSize = 16).scan(tempFile(data), db)

        assertEquals(listOf("Any.Pos"), outcome.names)
        assertEquals(70L, outcome.hits.single().firstPosition)
    }

    @Test
    fun exactOffsetIsEnforced() {
        val data = abcde + ByteArray(400) { '.'.code.toByte() }
        val db = ClamAvDatabaseParser().parseLines(
            listOf(
                "Wrong.Pos:0:100:4142434445",
                "Right.Pos:0:0:4142434445"
            )
        )
        val outcome = ClamAvScanner(chunkSize = 16).scan(tempFile(data), db)

        assertEquals(listOf("Right.Pos"), outcome.names)
    }

    @Test
    fun rangeOffsetAcceptsInsideAndRejectsOutside() {
        val inside = ByteArray(30) { '.'.code.toByte() } + abcde
        val outside = ByteArray(200) { '.'.code.toByte() } + abcde
        val db = ClamAvDatabaseParser().parseLines(listOf("Ranged:0:0,64:4142434445"))

        assertEquals(
            listOf("Ranged"),
            ClamAvScanner(chunkSize = 16).scan(tempFile(inside), db).names
        )
        assertTrue(
            "ofset 200 aralik 0..64 disinda",
            ClamAvScanner(chunkSize = 16).scan(tempFile(outside), db).names.isEmpty()
        )
    }

    @Test
    fun wildcardBytesMatchAnyContent() {
        val data = "dex\n035\u0000\u0000junk".encodeToByteArray()
        val db = ClamAvDatabaseParser().parseLines(listOf("Dex:0:0:64 65 78 0a ?? ?? ?? ??"))
        val outcome = ClamAvScanner(chunkSize = 4).scan(tempFile(data), db)
        assertEquals(listOf("Dex"), outcome.names)
    }

    @Test
    fun emptyDatabaseShortCircuits() {
        val outcome = ClamAvScanner().scan(tempFile("whatever".encodeToByteArray()), ClamAvDatabaseParser().parseLines(emptyList()))
        assertTrue(outcome.isEmpty)
        assertEquals(0, outcome.evaluatedPatterns)
    }
}
