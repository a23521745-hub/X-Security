package org.xsecurity.scanner.data

import android.content.Context
import android.net.Uri
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.engine.ScanEngines
import java.io.File
import java.io.IOException

/**
 * Uygulama-depolu imza veritabanlari.
 *
 * Repoda hicbir `.yar`/`.ndb` yoktu ve indirme akisi da bulunmadigi icin motor kutudan
 * cikis halinde bos donuyordu. Cozum: (1) `assets/signatures/` altindaki ornek
 * veritabanlari ilk calismada `filesDir/signatures/` kopyalanir, (2) kullanicini
 * SAF ile kendi kural/veritabanini secip atomik olarak kurabilir.
 */
object SignatureStore {

    enum class Kind(val fileName: String, val assetName: String, val requiredSuffix: String) {
        YARA("rules.yar", "signatures/sample-rules.yar", ".yar"),
        CLAM_AV("signatures.ndb", "signatures/sample-signatures.ndb", ".ndb")
    }

    data class Info(
        val kind: Kind,
        val path: String,
        val exists: Boolean,
        val size: Long,
        val modifiedAt: Long,
        val sha256Short: String?,
        val source: String
    ) {
        val isUsable: Boolean get() = exists && size > 0L
    }

    private const val PREFS = "xsec_signatures"
    private const val KEY_SOURCE = "source_"
    private const val KEY_SHA = "sha_"

    fun directory(context: Context): File =
        File(context.filesDir, "signatures").apply { if (!isDirectory) mkdirs() }

    fun file(context: Context, kind: Kind): File = File(directory(context), kind.fileName)

    /** Katman yalnizca dosya gercekten varsa aktif; yoksa motor "devre disi" raporlar. */
    fun fileOrNull(context: Context, kind: Kind): File? = file(context, kind).takeIf { it.isFile }

    fun ensureBundledDefaults(context: Context) {
        for (kind in Kind.values()) {
            val target = file(context, kind)
            if (target.isFile) continue
            runCatching { copyFromAssets(context, kind, target) }
        }
    }

    private fun copyFromAssets(context: Context, kind: Kind, target: File) {
        context.assets.open(kind.assetName).use { input ->
            val temp = File(target.parentFile, target.name + ".tmp")
            temp.outputStream().use { output -> input.copyTo(output) }
            val sha = Digest.sha256Hex(temp)
            if (!temp.renameTo(target)) {
                temp.delete()
                throw IOException("Bundled sample signature file could not be installed: ${target.absolutePath}")
            }
            markInstalled(context, kind, "bundled", sha)
        }
    }

    /**
     * Secilen dosyayi `filesDir/signatures/` altina atomik olarak kurar.
     * Ikinci eleman: kullaniciya gosterilecek uyari (yoksa `null`).
     */
    fun install(context: Context, kind: Kind, source: Uri, displayName: String?): Pair<Info, String?> {
        val target = file(context, kind)
        val temp = File(target.parentFile, target.name + ".tmp")
        val stream = context.contentResolver.openInputStream(source)
            ?: throw IOException("The file could not be opened: $source")
        try {
            stream.use { input -> temp.outputStream().use { output -> input.copyTo(output) } }
            if (temp.length() <= 0L) {
                throw IOException("The selected file is empty and cannot be used as a signature database.")
            }
            val sha = Digest.sha256Hex(temp)
            if (!temp.renameTo(target)) {
                throw IOException("The temporary file could not be moved into place: ${target.absolutePath}")
            }
            markInstalled(context, kind, "user", sha)
            ScanEngines.invalidate()
            val warning = if (displayName != null && !displayName.lowercase().endsWith(kind.requiredSuffix)) {
                "Selected file does not end with '${kind.requiredSuffix}' ($displayName); it was installed anyway and will be parsed."
            } else {
                null
            }
            return info(context, kind) to warning
        } catch (error: Exception) {
            temp.delete()
            throw error
        }
    }

    fun clear(context: Context, kind: Kind) {
        file(context, kind).delete()
        prefs(context).edit()
            .remove(KEY_SOURCE + kind.name)
            .remove(KEY_SHA + kind.name)
            .apply()
        ScanEngines.invalidate()
    }

    fun info(context: Context, kind: Kind): Info {
        val file = file(context, kind)
        val prefs = prefs(context)
        return Info(
            kind = kind,
            path = file.absolutePath,
            exists = file.isFile,
            size = if (file.isFile) file.length() else 0L,
            modifiedAt = if (file.isFile) file.lastModified() else 0L,
            sha256Short = prefs.getString(KEY_SHA + kind.name, null),
            source = prefs.getString(KEY_SOURCE + kind.name, null) ?: if (file.isFile) "unknown" else "none"
        )
    }

    private fun markInstalled(context: Context, kind: Kind, source: String, sha: String) {
        prefs(context).edit()
            .putString(KEY_SOURCE + kind.name, source)
            .putString(KEY_SHA + kind.name, Digest.shortHex(sha))
            .apply()
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
