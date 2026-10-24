package org.xsecurity.scanner.data

import android.content.Context
import android.net.Uri
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.engine.ApkScannerEngine
import org.xsecurity.scanner.engine.ScanEngines
import java.io.File
import java.io.IOException

/**
 * Uygulama-depolu imza veritabanlari.
 *
 * Repoda hicbir `.yar`/`.ndb` yoktu ve indirme akisi da bulunmadigi icin motor kutudan
 * cikis halinde bos donuyordu. Cozum katmanlari:
 *  (1) `assets/signatures/` altindaki **kuratorluk secilmis** veritabanlari ilk
 *      calismada `filesDir/signatures/` kopyalanir (kaynak `definitions/`),
 *  (2) kullanicini SAF ile kendi kural/veritabanini secip atomik olarak kurabilir,
 *  (3) imzali tanim kanali (`org.xsecurity.scanner.definitions`) guncel paketi
 *      indirip [installSetFromDownload] ile ayni hedefe atomik kurar.
 */
object SignatureStore {

    enum class Kind(val fileName: String, val assetName: String, val requiredSuffix: String) {
        YARA("rules.yar", "signatures/rules.yar", ".yar"),
        CLAM_AV("signatures.ndb", "signatures/signatures.ndb", ".ndb"),
        CLAM_HASHES("hashes.hsb", "signatures/hashes.hsb", ".hsb")
    }

    /** Paketle gelen tanim surumu (`assets/signatures/db-version.txt`); yoksa 0. */
    fun bundledDefVersion(context: Context): Int = try {
        context.assets.open("signatures/db-version.txt").use { stream ->
            stream.readBytes().decodeToString().trim().toIntOrNull() ?: 0
        }
    } catch (_: Throwable) {
        0
    }

    /** Paketle gelen imza dosyasinin kisa SHA-256 ozeti (ilk kurulum karsilastirmasi icin). */
    fun bundledSha256Short(context: Context, kind: Kind): String? = try {
        context.assets.open(kind.assetName).use { stream ->
            Digest.shortHex(Digest.sha256Hex(stream))
        }
    } catch (_: Throwable) {
        null
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

    /**
     * ALI-18 #2: dogrulanmis tanim setini atomik kurar (ya hep ya hic).
     *
     * Prefs yalan soylemez: kaynak/SHA isaretlemesi yalnizca takas BASARILI
     * olursa yazilir; hata durumunda eski dosyalar + eski prefs aynen korunur.
     *
     * @return basarida `null`, hatada kullaniciya gosterilebilir neden.
     */
    fun installSetFromDownload(context: Context, staged: Map<Kind, File>, source: String): String? {
        if (staged.isEmpty()) return null
        val shas = LinkedHashMap<Kind, String>()
        for ((kind, temp) in staged) {
            shas[kind] = runCatching { Digest.sha256Hex(temp) }.getOrNull()
                ?: return "Could not hash staged file: ${temp.absolutePath}"
        }
        return when (val outcome = AtomicFileSet.installSet(directory(context), staged.mapKeys { it.key.fileName })) {
            is AtomicFileSet.Outcome.Committed -> {
                for ((kind, sha) in shas) markInstalled(context, kind, source, sha)
                ScanEngines.invalidate()
                null
            }
            is AtomicFileSet.Outcome.RolledBack ->
                "Definitions update was rolled back and the previous set was kept (${outcome.reason})."
        }
    }

    /**
     * Onceki kurulumda process coktuysa yarim seti toparlar (ALI-18 review):
     * hedefi kayip yedekler geri yuklenir; hedef+yedek birlikte varsa oracle
     * (mevcut set yuklenebiliyor mu?) karar verir — yukleniyorsa yedek bayattir,
     * yuklenemiyorsa eski sete donulur.
     *
     * @return toparlanan/belirsiz bir durum bulunduysa `true`.
     */
    fun recoverInterruptedInstall(context: Context): Boolean {
        val directory = directory(context)
        val names = Kind.values().map { it.fileName }
        val outcome = AtomicFileSet.recover(directory, names)
        if (outcome.ambiguous.isEmpty()) return outcome.recovered.isNotEmpty()

        val currentLoads = runCatching {
            ApkScannerEngine.load(
                fileOrNull(context, Kind.YARA),
                fileOrNull(context, Kind.CLAM_AV),
                fileOrNull(context, Kind.CLAM_HASHES)
            ).isSuccess
        }.getOrDefault(false)
        if (currentLoads) {
            // Yeni set saglam; yedekler onceki committen kalma bayat artiklar.
            outcome.ambiguous.forEach { name ->
                runCatching { File(directory, name + AtomicFileSet.BACKUP_SUFFIX).delete() }
            }
        } else {
            // Mevcut set olu; yedeklerdeki eski sete don (bulunabilen kadariyla).
            outcome.ambiguous.forEach { name ->
                runCatching {
                    val target = File(directory, name)
                    val backup = File(directory, name + AtomicFileSet.BACKUP_SUFFIX)
                    if (target.isFile) target.delete()
                    if (backup.isFile) backup.renameTo(target)
                }
            }
            ScanEngines.invalidate()
        }
        return true
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
