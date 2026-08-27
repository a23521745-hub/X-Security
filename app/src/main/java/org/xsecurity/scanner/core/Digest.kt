package org.xsecurity.scanner.core

import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/** Dosya/akis SHA-256 ve boyut yardimcilari. */
object Digest {

    private const val BUFFER = 64 * 1024

    fun sha256Hex(stream: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER)
        while (true) {
            val read = stream.read(buffer)
            if (read < 0) break
            if (read > 0) digest.update(buffer, 0, read)
        }
        return digest.digest().toHexString()
    }

    fun sha256Hex(file: File): String = file.inputStream().use { sha256Hex(it) }

    fun ByteArray.toHexString(): String {
        val out = StringBuilder(size * 2)
        for (b in this) {
            val v = b.toInt() and 0xFF
            out.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
        }
        return out.toString()
    }

    /** Iki dosyanin icerik esitligini tam okumadan, boyut + ilk/son blok + hash ile kontrol eder. */
    fun isSameContent(a: File, b: File): Boolean {
        if (!a.isFile || !b.isFile) return false
        if (a.length() != b.length()) return false
        return sha256Hex(a) == sha256Hex(b)
    }

    fun shortHex(value: String, limit: Int = 12): String =
        if (value.length <= limit) value else value.substring(0, limit)

    private val HEX = "0123456789abcdef".toCharArray()
}
