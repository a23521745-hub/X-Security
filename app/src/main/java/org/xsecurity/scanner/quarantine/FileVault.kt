package org.xsecurity.scanner.quarantine

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** AES-GCM encrypted app-private vault. The AES key is generated and retained by Android Keystore. */
object FileVault {
    private const val DIRECTORY = "quarantine-vault"
    private const val KEY_ALIAS = "org.xsecurity.scanner.quarantine.filevault.v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private val magic = byteArrayOf('X'.code.toByte(), 'S'.code.toByte(), 'V'.code.toByte(), '1'.code.toByte())
    private val keyLock = Any()

    data class StoredFile(val fileName: String, val sha256: String)

    /** Encrypts a copy; never moves or deletes the source. */
    @Throws(IOException::class)
    fun store(context: Context, source: File, id: String): StoredFile {
        require(id.matches(Regex("[A-Za-z0-9-]{1,80}"))) { "invalid vault id" }
        require(source.isFile && source.canRead()) { "source file is unavailable" }
        val directory = vaultDirectory(context).apply { if (!isDirectory && !mkdirs()) throw IOException("vault directory unavailable") }
        val targetName = "$id.xsv"
        val target = File(directory, targetName)
        val temporary = File(directory, "$id.tmp")
        if (target.exists()) throw IOException("vault entry already exists")
        if (!temporary.createNewFile()) throw IOException("temporary vault entry already exists")
        val digest = MessageDigest.getInstance("SHA-256")
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey())
            FileOutputStream(temporary).use { raw ->
                BufferedOutputStream(raw).use { output ->
                    output.write(magic)
                    output.write(cipher.iv.size)
                    output.write(cipher.iv)
                    CipherOutputStream(output, cipher).use { encrypted ->
                        BufferedInputStream(FileInputStream(source)).use { input ->
                            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                digest.update(buffer, 0, count)
                                encrypted.write(buffer, 0, count)
                            }
                        }
                    }
                }
            }
            if (!temporary.renameTo(target)) throw IOException("encrypted vault entry could not be finalized")
            return StoredFile(targetName, digest.digest().toHex())
        } catch (error: Exception) {
            runCatching { temporary.delete() }
            if (error is IOException) throw error
            throw IOException("vault encryption failed", error)
        }
    }

    /** Decrypts only to a caller-owned app-private file; the vault entry is retained. */
    @Throws(IOException::class)
    fun restoreTo(context: Context, fileName: String, destination: File) {
        require(fileName.matches(Regex("[A-Za-z0-9-]{1,80}\\.xsv"))) { "invalid vault file name" }
        val source = File(vaultDirectory(context), fileName)
        if (!source.isFile) throw IOException("vault entry unavailable")
        destination.parentFile?.let { if (!it.isDirectory && !it.mkdirs()) throw IOException("restore directory unavailable") }
        try {
            BufferedInputStream(FileInputStream(source)).use { input ->
                val header = ByteArray(magic.size)
                readFully(input, header)
                if (!header.contentEquals(magic)) throw IOException("invalid vault header")
                val ivLength = input.read()
                if (ivLength !in 12..16) throw IOException("invalid vault nonce")
                val iv = ByteArray(ivLength)
                readFully(input, iv)
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, secretKey(), javax.crypto.spec.GCMParameterSpec(128, iv))
                CipherInputStream(input, cipher).use { decrypted ->
                    FileOutputStream(destination).use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        while (true) {
                            val count = decrypted.read(buffer)
                            if (count < 0) break
                            output.write(buffer, 0, count)
                        }
                        output.fd.sync()
                    }
                }
            }
        } catch (error: Exception) {
            runCatching { destination.delete() }
            if (error is IOException) throw error
            throw IOException("vault decryption failed", error)
        }
    }

    private fun secretKey(): SecretKey = synchronized(keyLock) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return@synchronized it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        generator.generateKey()
    }

    private fun vaultDirectory(context: Context): File = File(context.applicationContext.filesDir, DIRECTORY)

    private fun readFully(input: java.io.InputStream, destination: ByteArray) {
        var offset = 0
        while (offset < destination.size) {
            val count = input.read(destination, offset, destination.size - offset)
            if (count < 0) throw IOException("truncated vault entry")
            offset += count
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}
