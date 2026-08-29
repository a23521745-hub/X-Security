package org.xsecurity.scanner.community

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.engine.ScanEngines
import java.io.File
import java.io.IOException

/**
 * Topluluk kaynaklarini tazeleyen orkestrator: indir -> dogrula
 * ([CommunityValidator]) -> atomik kur -> motor onbelligini dusur.
 *
 * "Guncellemeleri kontrol et" dugmesi imzali kanali da kapsar; bu sinif yalnizca
 * topluluk kismini yurutur ve imzali kanalin sonucunu asla bozmaz (hatalar
 * kaynak bazinda yakalanir, akisi durdurmaz; onceki kurulum yerinde kalir).
 */
object CommunityUpdater {

    sealed class SourceResult {
        /** Icerik indirildi, dogrulandi ve kuruldu. */
        data class Installed(val hashEntries: Int, val yaraRules: Int) : SourceResult()

        /** Kaynak zaten bu icerikle kurulu; yenisi indirilmedi. */
        object UpToDate : SourceResult()

        /** Kaynak tercihi kapali. */
        object Disabled : SourceResult()

        /** Indirme/dogrulama hatasi; onceki kurulum (varsa) oldugu gibi kalir. */
        data class Failed(val message: String) : SourceResult()
    }

    /**
     * Tum kaynaklari sirayla tazeler. Test edilebilirlik icin fetcher enjekte
     * edilebilir; varsayilan gercek istemci ([CommunityDownloader]).
     */
    suspend fun refreshAll(
        context: Context,
        fetcher: Fetcher = CommunityDownloader()
    ): Map<String, SourceResult> = withContext(Dispatchers.IO) {
        val appContext = context.applicationContext
        val results = LinkedHashMap<String, SourceResult>()
        for (source in CommunityStore.registry(appContext)) {
            results[source.id] = refreshOne(appContext, source, fetcher)
        }
        CommunityStore.publish(appContext)
        results
    }

    internal fun refreshOne(
        context: Context,
        source: CommunitySource,
        fetcher: Fetcher
    ): SourceResult {
        if (!CommunityStore.isEnabled(context, source)) {
            return SourceResult.Disabled
        }
        CommunityStore.setUpdating(context, source.id, true)
        try {
            val payload = try {
                fetcher.fetch(source.url)
            } catch (error: IOException) {
                return failed(context, source, error.message ?: "indirme hatasi")
            }

            val sha = Digest.sha256Hex(payload)
            if (sha == CommunityStore.lastSha(context, source) &&
                CommunityStore.fileFor(context, source).isFile
            ) {
                CommunityStore.setError(context, source, null)
                return SourceResult.UpToDate
            }

            val validated = CommunityValidator.validate(source, payload)
            val target = CommunityStore.fileFor(context, source)
            writeAtomic(target, validated.content)
            CommunityStore.setInstalled(
                context,
                source,
                sha,
                validated.hashEntries,
                validated.yaraRules
            )
            ScanEngines.invalidate()
            CommunityStore.setError(context, source, null)
            return SourceResult.Installed(validated.hashEntries, validated.yaraRules)
        } catch (error: Exception) {
            return failed(context, source, error.message ?: "kaynak islenemedi")
        } finally {
            CommunityStore.setUpdating(context, source.id, false)
        }
    }

    private fun writeAtomic(target: File, content: String) {
        val temp = File(target.parentFile, target.name + ".tmp")
        temp.writeText(content)
        if (target.isFile) target.delete()
        if (!temp.renameTo(target)) {
            temp.delete()
            throw IOException("topluluk kaynagi kurulamadi: ${target.absolutePath}")
        }
    }

    private fun failed(context: Context, source: CommunitySource, message: String): SourceResult {
        CommunityStore.setError(context, source, message)
        return SourceResult.Failed(message)
    }
}
