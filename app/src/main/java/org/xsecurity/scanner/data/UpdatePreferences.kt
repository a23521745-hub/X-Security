package org.xsecurity.scanner.data

import android.content.Context
import android.net.ConnectivityManager
import androidx.core.content.edit
import androidx.work.WorkManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.xsecurity.scanner.definitions.DefinitionsController
import org.xsecurity.scanner.ota.OtaController

/**
 * Arka plan guncelleme kontrollerinin kullanici tercihleri.
 *
 *  - [UpdateSettings.autoCheckEnabled]: gunluk OTA + tanim kontrolleri calissin mi?
 *    Kapatilinca periyodik isler iptal edilir; elle "kontrol et" dugmeleri her
 *    zaman calisir (worker kapisi yalnizca arka plan islerine bakar).
 *  - [UpdateSettings.allowMetered]: kotali (mobil/olcumlu Wi-Fi) baglantida arka
 *    plan kontrolune izin var mi? Okuma [ConnectivityManager.isActiveNetworkMetered]
 *    ile yapilir, [android.Manifest.permission.ACCESS_NETWORK_STATE] normal izindir
 *    (kullanicidan istenmez).
 *
 * Desen diger store'larla ayni: SharedPreferences + StateFlow.
 */
data class UpdateSettings(
    val autoCheckEnabled: Boolean = true,
    val allowMetered: Boolean = true
)

object UpdatePreferences {

    private const val PREFS = "xsec_update_prefs"
    private const val KEY_AUTO_CHECK = "auto_check"
    private const val KEY_ALLOW_METERED = "allow_metered"

    private val _state = MutableStateFlow(UpdateSettings())
    val state: StateFlow<UpdateSettings> = _state.asStateFlow()

    fun restore(context: Context) {
        _state.value = UpdateSettings(
            autoCheckEnabled = isAutoCheckEnabled(context),
            allowMetered = isMeteredAllowed(context)
        )
    }

    fun isAutoCheckEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_AUTO_CHECK, true)

    fun isMeteredAllowed(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ALLOW_METERED, true)

    fun setAutoCheckEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit { putBoolean(KEY_AUTO_CHECK, enabled) }
        _state.value = _state.value.copy(autoCheckEnabled = enabled)
    }

    fun setMeteredAllowed(context: Context, allowed: Boolean) {
        prefs(context).edit { putBoolean(KEY_ALLOW_METERED, allowed) }
        _state.value = _state.value.copy(allowMetered = allowed)
    }

    /**
     * Ayar ekranindan cagrilir: tercihi yazar + periyodik isleri buna gore kurar
     * ya da iptal eder. KEEP kurali korunur (zaten kuruluysa dokunulmaz).
     */
    fun applyAutoCheck(context: Context, enabled: Boolean) {
        val appContext = context.applicationContext
        setAutoCheckEnabled(appContext, enabled)
        if (enabled) {
            OtaController.schedulePeriodicCheck(appContext)
            DefinitionsController.schedulePeriodicCheck(appContext)
        } else {
            runCatching {
                val work = WorkManager.getInstance(appContext)
                work.cancelUniqueWork(OtaController.CHECK_WORK_NAME)
                work.cancelUniqueWork(DefinitionsController.PERIODIC_WORK_NAME)
            }
        }
    }

    /**
     * Worker kapisi: bu arka plan kontrolu simdi calismali mi? Tercih kapaliysa ya
     * da kotali baglantida izin yoksa worker sessizce `success` doner (retry YOK:
     * kosul saglanmadan tekrar denemenin anlami yok).
     */
    fun shouldRunBackgroundCheck(context: Context): Boolean {
        val appContext = context.applicationContext
        return shouldRun(
            autoCheckEnabled = isAutoCheckEnabled(appContext),
            allowMetered = isMeteredAllowed(appContext),
            metered = isActiveNetworkMetered(appContext)
        )
    }

    /** Saf: kapinın karar mantigi (birim testte kilitlenir). */
    fun shouldRun(autoCheckEnabled: Boolean, allowMetered: Boolean, metered: Boolean): Boolean {
        if (!autoCheckEnabled) return false
        if (metered && !allowMetered) return false
        return true
    }

    /** Ince sarmalayici: aktif baglanti kotali mi? Okunamazsa kotasiz sayilir. */
    fun isActiveNetworkMetered(context: Context): Boolean = try {
        val manager = context.applicationContext.getSystemService(ConnectivityManager::class.java)
        manager?.isActiveNetworkMetered ?: false
    } catch (_: Throwable) {
        false
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
