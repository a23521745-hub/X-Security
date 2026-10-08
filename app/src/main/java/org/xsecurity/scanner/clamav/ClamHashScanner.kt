package org.xsecurity.scanner.clamav

import org.xsecurity.scanner.core.Digest
import java.io.File
import java.security.MessageDigest

/**
 * Hash imza katmaninin tarayicisi: dosyayi TEK okuma gecisinde MD5 + SHA-1 + SHA-256
 * ile ozetler ve uc ozeti de [ClamHashDatabaseParser.Database] icinde arar.
 *
 * (Hypatia'nin yakinasi: "Files have their MD5/SHA-1/SHA-256 hashes calculated in
 * one pass" — ayni optimizasyon burada da uygulanir; diskten uc kez okuma yok.)
 *
 * Boyut kosulu: imzada boyut belirtilmisse dosya boyutu da eslesmek zorundadir;
 * boyut bilinmiyorsa (-1) hash eslesmesi tek basina yeterlidir.
 *
 * Bu katman YALNIZCA ham dosyanin ozetine bakar (hash imzasi dosya-butunudur);
 * ZIP girdilerine inilmez — apk icerigi zaten desen katmanlarinca taranir.
 */
class ClamHashScanner {

    class Hit(
        val name: String,
        val algorithm: ClamHashDatabaseParser.Algorithm,
        val hashHex: String,
        val fileSize: Long
    )

    class Outcome(
        val hits: List<Hit>,
        val scannedBytes: Long
    ) {
        val isEmpty: Boolean get() = hits.isEmpty()
    }

    fun scan(file: File, database: ClamHashDatabaseParser.Database, onBytes: (Long) -> Unit = {}): Outcome {
        if (!file.isFile || database.size == 0) {
            return Outcome(emptyList(), 0L)
        }

        val md5 = MessageDigest.getInstance("MD5")
        val sha1 = MessageDigest.getInstance("SHA-1")
        val sha256 = MessageDigest.getInstance("SHA-256")
        var total = 0L

        file.inputStream().buffered().use { stream ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = stream.read(buffer)
                if (read < 0) break
                if (read > 0) {
                    md5.update(buffer, 0, read)
                    sha1.update(buffer, 0, read)
                    sha256.update(buffer, 0, read)
                }
                total += read
                onBytes(total)
            }
        }

        val hits = ArrayList<Hit>(1)
        fun check(digest: MessageDigest, algorithm: ClamHashDatabaseParser.Algorithm) {
            val hex = Digest.hex(digest.digest())
            val signature = database.lookup(hex) ?: return
            if (signature.sizeBytes >= 0L && signature.sizeBytes != total) return
            hits += Hit(
                name = signature.name,
                algorithm = algorithm,
                hashHex = hex,
                fileSize = total
            )
        }
        check(md5, ClamHashDatabaseParser.Algorithm.MD5)
        check(sha1, ClamHashDatabaseParser.Algorithm.SHA_1)
        check(sha256, ClamHashDatabaseParser.Algorithm.SHA_256)

        return Outcome(hits, total)
    }
}
