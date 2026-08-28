package org.xsecurity.scanner.ota

import org.xsecurity.scanner.core.Digest.toHexString
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/**
 * Inen akisin dogrulamasini yapan saf (JVM'de test edilebilir, Android icermez) katman.
 *
 * Indirme ile dogrulama **ayni akista** yapilir: dosya diske yazilirken es zamanli
 * SHA-256 hesaplanir ve boyut sayilir. Manifestte bildirilen boyut/asim siniri
 * asilirsa ya da hash uyusmazsa akis yariya kesilir, hedef dosya silinir ve hata
 * doner. Boylece "once indir, sonra dogrula" penceresinde buyuk/bozuk bir dosya
 * diskte kalici hale gelmez.
 */
object ApkVerifier {

    private const val BUFFER = 64 * 1024

    sealed class Result {
        data class Success(val file: File, val bytes: Long, val sha256: String) : Result()
        data class Failure(val message: String) : Result()
    }

    /**
     * [input] akisini [target] dosyasina yazar; bu sirada:
     *  - [maxBytes] ve bildirilen [expectedSize] asimina karsi sert sinir,
     *  - [expectedSha256] ile tam eslesme,
     * kontrol edilir. [onProgress] 0..1 arasi ilerleme (expectedSize biliniyorsa) verir.
     *
     * Her turlu hata yolunda [target] silinir.
     */
    fun verifyToFile(
        input: InputStream,
        expectedSha256: String,
        expectedSize: Long,
        maxBytes: Long,
        target: File,
        onProgress: (Float) -> Unit = {}
    ): Result {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER)
        var total = 0L
        target.parentFile?.mkdirs()

        try {
            target.outputStream().use { output ->
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (read == 0) continue
                    total += read
                    if (total > maxBytes) {
                        return fail(target, "APK, izin verilen boyut sinirini aştı (${maxBytes} bayt)")
                    }
                    if (expectedSize in 1..<total) {
                        return fail(target, "APK, manifestte bildirilen boyuttan büyük (${expectedSize} bayt)")
                    }
                    digest.update(buffer, 0, read)
                    output.write(buffer, 0, read)
                    if (expectedSize > 0) {
                        onProgress((total.toFloat() / expectedSize.toFloat()).coerceIn(0f, 1f))
                    }
                }
            }

            if (total <= 0L) return fail(target, "İndirilen APK boş")
            if (expectedSize > 0L && total != expectedSize) {
                return fail(target, "APK boyutu eşleşmedi: bildirilen $expectedSize, gelen $total")
            }

            val actualSha = digest.digest().toHexString()
            if (!actualSha.equals(expectedSha256, ignoreCase = true)) {
                return fail(target, "APK SHA-256 eşleşmedi — indirme reddedildi")
            }

            onProgress(1f)
            return Result.Success(target, total, actualSha)
        } catch (error: Throwable) {
            return fail(target, error.message ?: "APK doğrulanamadı")
        }
    }

    private fun fail(file: File, message: String): Result {
        runCatching { if (file.exists()) file.delete() }
        return Result.Failure(message)
    }
}
