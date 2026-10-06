package org.xsecurity.scanner.phishing

import android.content.Context
import androidx.core.content.edit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.community.CommunityDownloader
import org.xsecurity.scanner.community.ConditionalFetch
import java.io.File
import java.io.IOException

data class PhishingBlocklistState(
    val entries: Int = 0,
    val updatedAt: Long = 0L,
    val updating: Boolean = false,
    val error: String? = null
)

/**
 * Oltalama blok listesi: gomulu liste + topluluk guncellemesi.
 *
 *  - Etkin liste = APK'ya gomulu `assets/phishing-blocklist.txt` BIRLESIK
 *    indirilen kopya (`filesDir/phishing-blocklist.txt`). Gomulu liste her
 *    zaman vardir; indirme basarisiz olursa onceki liste korunur.
 *  - Guncelleme yalnizca KULLANICI dugmeye bastiginda yapilir (arka plan
 *    trafigi yok); kosullu GET (`If-None-Match` + `304`) ile veri tasarrufu
 *    saglanir. Indirme topluluk kanaliyla ayni host izin listesinden gecer.
 *  - Desen diger store'larla ayni: StateFlow + kalicilama, sessiz hata.
 */
object PhishingStore {

    /**
     * Topluluk blok listesi adresi. Depo kokundeki `phishing-blocklist.txt`
     * dosyasinin ham bicimidir; bakimcilar listeyi buradan buyutur.
     */
    const val BLOCKLIST_URL =
        "https://raw.githubusercontent.com/a23521745-hub/X-Security/main/phishing-blocklist.txt"

    private const val PREFS = "xsec_phishing"
    private const val KEY_ETAG = "etag"
    private const val KEY_UPDATED_AT = "updated_at"
    private const val FILE_NAME = "phishing-blocklist.txt"

    private val _state = MutableStateFlow(PhishingBlocklistState())
    val state: StateFlow<PhishingBlocklistState> = _state.asStateFlow()

    @Volatile
    private var cached: Set<String>? = null

    /** Etkin liste (gomulu + indirilen); bellege alinir, ana-dizide cagrilabilir. */
    fun blocklist(context: Context): Set<String> {
        cached?.let { return it }
        val merged = loadEmbedded(context) + loadOverlay(context)
        cached = merged
        publishCount(merged.size)
        return merged
    }

    fun restore(context: Context) {
        val appContext = context.applicationContext
        val merged = loadEmbedded(appContext) + loadOverlay(appContext)
        cached = merged
        _state.value = PhishingBlocklistState(
            entries = merged.size,
            updatedAt = prefs(appContext).getLong(KEY_UPDATED_AT, 0L)
        )
    }

    /**
     * Listeyi topluluk adresinden tazeler. Basarisiz olursa onceki liste ve
     * hata mesaji korunur (false doner); `304` degisiklik yok demektir.
     */
    suspend fun refresh(context: Context): Boolean = withContext(Dispatchers.IO) {
        val appContext = context.applicationContext
        _state.value = _state.value.copy(updating = true, error = null)
        try {
            val result = try {
                CommunityDownloader().fetchConditional(
                    BLOCKLIST_URL,
                    prefs(appContext).getString(KEY_ETAG, null)
                )
            } catch (error: IOException) {
                _state.value = _state.value.copy(
                    updating = false,
                    error = error.message ?: "indirme hatasi"
                )
                return@withContext false
            }
            if (result is ConditionalFetch.NotModified) {
                _state.value = _state.value.copy(updating = false, error = null)
                return@withContext true
            }
            val fresh = result as ConditionalFetch.Fresh
            val raw = String(fresh.bytes, Charsets.UTF_8)
            val overlay = PhishingBlocklist.parse(raw)
            if (overlay.isEmpty() && raw.isNotBlank()) {
                // Bicim taninmadi: onceki listeyi koru, hata goster.
                _state.value = _state.value.copy(updating = false, error = "liste bicimi taninmadi")
                return@withContext false
            }
            writeOverlay(appContext, raw)
            prefs(appContext).edit {
                putString(KEY_ETAG, fresh.etag)
                putLong(KEY_UPDATED_AT, System.currentTimeMillis())
            }
            val merged = loadEmbedded(appContext) + overlay
            cached = merged
            _state.value = PhishingBlocklistState(
                entries = merged.size,
                updatedAt = prefs(appContext).getLong(KEY_UPDATED_AT, 0L)
            )
            true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            _state.value = _state.value.copy(
                updating = false,
                error = error.message ?: "liste guncellenemedi"
            )
            false
        }
    }

    private fun loadEmbedded(context: Context): Set<String> = try {
        context.assets.open(PhishingBlocklist.ASSET_PATH).use { input ->
            PhishingBlocklist.parse(String(input.readBytes(), Charsets.UTF_8))
        }
    } catch (_: Throwable) {
        emptySet()
    }

    private fun loadOverlay(context: Context): Set<String> {
        val file = File(context.filesDir, FILE_NAME)
        if (!file.isFile) return emptySet()
        return try {
            PhishingBlocklist.parse(file.readText())
        } catch (_: Throwable) {
            emptySet()
        }
    }

    private fun writeOverlay(context: Context, raw: String) {
        val file = File(context.filesDir, FILE_NAME)
        val tmp = File(context.filesDir, "$FILE_NAME.tmp")
        tmp.writeText(raw)
        if (file.isFile) file.delete()
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw IOException("blok listesi yazilamadi")
        }
    }

    private fun publishCount(entries: Int) {
        // restore() sonrasi sayi degismisse akisi tazele (dosya disaridan silinmis olabilir).
        if (_state.value.entries != entries) {
            _state.value = _state.value.copy(entries = entries)
        }
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
