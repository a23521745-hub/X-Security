package org.xsecurity.scanner.community

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.xsecurity.scanner.engine.ScanEngines
import java.io.File

/**
 * Topluluk kaynaklarinin durumu: tercih (acik/kapali), kurulu imza sayisi,
 * son guncelleme zamani ve son hata. Durum hem kalici (SharedPreferences) hem
 * UI'i besleyen akis ([state]) olarak tutulur.
 *
 * Kurulu dosyalar `filesDir/signatures/community/` altinda, kaynak kimligi
 * adina yasar (`echap-hashes.hsb`, `echap-yara.yar`). Imzali kanal dosyalarina
 * (rules.yar / signatures.ndb / hashes.hsb) **dokunulmaz**; boylece OTA ile
 * topluluk icerigi birbirinin uzerine yazmaz.
 */
object CommunityStore {

    data class SourceState(
        val source: CommunitySource,
        val enabled: Boolean,
        val installedEntries: Int,
        val installedRules: Int,
        val updatedAt: Long,
        val updating: Boolean,
        val error: String?
    )

    private const val PREFS = "xsec_community"
    private const val KEY_ENABLED = "enabled_"
    private const val KEY_SHA = "sha_"
    private const val KEY_ENTRIES = "entries_"
    private const val KEY_RULES = "rules_"
    private const val KEY_UPDATED = "updated_"
    private const val KEY_ERROR = "error_"

    private val mutableState = MutableStateFlow<List<SourceState>>(emptyList())
    val state: StateFlow<List<SourceState>> = mutableState.asStateFlow()

    fun directory(context: Context): File =
        File(org.xsecurity.scanner.data.SignatureStore.directory(context), "community")
            .apply { if (!isDirectory) mkdirs() }

    fun fileFor(context: Context, source: CommunitySource): File =
        File(directory(context), source.id + when (source.kind) {
            CommunitySource.Kind.HSB_FROM_CSV -> ".hsb"
            CommunitySource.Kind.YARA -> ".yar"
        })

    fun isEnabled(context: Context, source: CommunitySource): Boolean =
        prefs(context).getBoolean(KEY_ENABLED + source.id, source.enabledByDefault)

    fun setEnabled(context: Context, source: CommunitySource, enabled: Boolean) {
        val preferences = prefs(context).edit().putBoolean(KEY_ENABLED + source.id, enabled)
        if (!enabled) {
            fileFor(context, source).delete()
            // Kapatilan kaynagin eski sayaclari UI'da asili kalmasin.
            preferences.remove(KEY_ENTRIES + source.id)
            preferences.remove(KEY_RULES + source.id)
            preferences.remove(KEY_UPDATED + source.id)
            preferences.remove(KEY_ERROR + source.id)
        }
        preferences.apply()
        ScanEngines.invalidate()
        publish(context)
    }

    fun lastSha(context: Context, source: CommunitySource): String? =
        prefs(context).getString(KEY_SHA + source.id, null)

    fun setInstalled(context: Context, source: CommunitySource, sha: String, entries: Int, rules: Int) {
        prefs(context).edit()
            .putString(KEY_SHA + source.id, sha)
            .putInt(KEY_ENTRIES + source.id, entries)
            .putInt(KEY_RULES + source.id, rules)
            .putLong(KEY_UPDATED + source.id, System.currentTimeMillis())
            .putString(KEY_ERROR + source.id, null)
            .apply()
        publish(context)
    }

    fun setError(context: Context, source: CommunitySource, message: String?) {
        prefs(context).edit().putString(KEY_ERROR + source.id, message).apply()
        publish(context)
    }

    fun setUpdating(context: Context, sourceId: String, updating: Boolean) {
        publish(context, sourceId to updating)
    }

    /**
     * Motorun yukleyecegi topluluk dosyalari: tercihi acik VE dosyasi yerinde
     * olan kaynaklar. Kapali kaynagin dosyasi [setEnabled]'de silinir; yine de
     * dosya yoksa (orn. henuz indirilmemis) liste o kaynagi icermez.
     */
    fun enabledYaraFiles(context: Context): List<File> =
        enabledFiles(context, CommunitySource.Kind.YARA)

    fun enabledHashFiles(context: Context): List<File> =
        enabledFiles(context, CommunitySource.Kind.HSB_FROM_CSV)

    private fun enabledFiles(context: Context, kind: CommunitySource.Kind): List<File> {
        val out = ArrayList<File>(2)
        for (source in registry(context)) {
            if (source.kind != kind) continue
            if (!isEnabled(context, source)) continue
            val file = fileFor(context, source)
            if (file.isFile && file.length() > 0L) out += file
        }
        return out
    }

    fun registry(context: Context): List<CommunitySource> = try {
        CommunitySource.load(context)
    } catch (error: Throwable) {
        // Kayit defteri APK icinde; bozulmasi derleme hatasi demektir. Yine de
        // uygulama cokmemeli: bos liste ile "kaynak yok" durumuna duseriz.
        emptyList()
    }

    fun publish(context: Context, updatingOverride: Pair<String, Boolean>? = null) {
        val sources = registry(context)
        val preferences = prefs(context)
        mutableState.value = sources.map { source ->
            SourceState(
                source = source,
                enabled = preferences.getBoolean(KEY_ENABLED + source.id, source.enabledByDefault),
                installedEntries = preferences.getInt(KEY_ENTRIES + source.id, 0),
                installedRules = preferences.getInt(KEY_RULES + source.id, 0),
                updatedAt = preferences.getLong(KEY_UPDATED + source.id, 0L),
                updating = if (updatingOverride != null && updatingOverride.first == source.id) {
                    updatingOverride.second
                } else false,
                error = preferences.getString(KEY_ERROR + source.id, null)
            )
        }
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
