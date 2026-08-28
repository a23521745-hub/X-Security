package org.xsecurity.scanner.ui

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.R
import org.xsecurity.scanner.data.EngineInfo
import org.xsecurity.scanner.data.ScanController
import org.xsecurity.scanner.data.ScanNotifications
import org.xsecurity.scanner.data.ScanStore
import org.xsecurity.scanner.data.SignatureStore
import org.xsecurity.scanner.engine.ScanEngines
import org.xsecurity.scanner.ota.OtaController
import org.xsecurity.scanner.ota.OtaNotifications
import org.xsecurity.scanner.ota.OtaStore
import org.xsecurity.scanner.ui.screens.DashboardScreen
import org.xsecurity.scanner.ui.theme.XSecurityTheme
import java.io.File

/**
 * Uygulamanin tek ekrani.
 *
 * Manifest bu sinifi launcher olarak ilan ediyordu ama dosya hic mevcut degildi
 * (acilista `ActivityNotFoundException`). Ayrica UI, `ApkScanWorker` sonuclarini
 * hic okumuyor, sabit "cihaziniz guvende" metinleri gosteriyordu. Simdi arayuz
 * `ScanStore.state` uzerinden gercek tarama durumunu izliyor.
 */
class MainActivity : ComponentActivity() {

    private val apkPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) queueScan(uri) else ScanStore.clearMessage()
    }

    private val yaraPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) installSignature(SignatureStore.Kind.YARA, uri) else ScanStore.clearMessage()
    }

    private val clamPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) installSignature(SignatureStore.Kind.CLAM_AV, uri) else ScanStore.clearMessage()
    }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* sonuç önemli degil */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // API 35 hedefinde kenar-dan-kenara zorunlu; SystemBarStyle varsayilanlari
        // ikon rengini arka plana gore seciyor (eski kod status bar'i koyu boyaya
        // koyu ikonla ciziyordu).
        enableEdgeToEdge()

        SignatureStore.ensureBundledDefaults(this)
        ScanNotifications.ensureChannel(this)
        OtaNotifications.ensureChannel(this)
        ScanStore.restore(this)
        OtaStore.restore(this)
        requestNotificationPermissionIfNeeded()
        // Gunluk imzali guncelleme kontrolu (yalnizca ag bagliyken; bildirim sessiz).
        OtaController.schedulePeriodicCheck(this)
        reloadEngine()

        setContent {
            XSecurityTheme {
                val state by ScanStore.state.collectAsState()
                val otaState by OtaStore.state.collectAsState()
                DashboardScreen(
                    state = state,
                    otaState = otaState,
                    installedVersionCode = OtaController.currentVersionCode(this),
                    onScanApk = { apkPicker.launch(APK_MIME_TYPES) },
                    onPickYaraRules = { yaraPicker.launch(ANY_MIME_TYPES) },
                    onPickClamDatabase = { clamPicker.launch(ANY_MIME_TYPES) },
                    onReloadEngine = { reloadEngine() },
                    onCancelScan = { ScanController.cancelAll(this) },
                    onCheckUpdate = { lifecycleScope.launch { OtaController.check(this@MainActivity) } },
                    onDownloadUpdate = { startDownload() },
                    onInstallUpdate = { installDownloadedUpdate() }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Worker baska bir surecten calissa bile sonucui yenile.
        ScanStore.restore(this)
        OtaStore.restore(this)
    }

    /** Indirme butonu: yalnizca dogrulanmis bir guncelleme varken Worker'i kuyruklar. */
    private fun startDownload() {
        val info = OtaStore.state.value.available ?: return
        OtaController.enqueueDownload(this, info)
    }

    /**
     * Kur butonu: indirilmis + dogrulanmis APK icin sistemin paket kurulum ekranini acar.
     * Uygulama hicbir zaman sessiz kurmaz; izin yoksa kullanici sistem ayarina yonlendirilir.
     */
    private fun installDownloadedUpdate() {
        val path = OtaStore.state.value.downloadedPath ?: return
        when (val result = OtaController.install(this, File(path))) {
            is OtaController.Result.NeedsPermission -> {
                runCatching { startActivity(result.settingsIntent) }
                OtaStore.error(getString(R.string.ota_install_permission))
            }
            is OtaController.Result.Error -> OtaStore.error(result.message)
            OtaController.Result.InstallPromptLaunched -> Unit // sistem kurulum ekrani acildi
        }
    }

    private fun queueScan(uri: Uri) {
        lifecycleScope.launch {
            ScanStore.markQueued(this@MainActivity, getString(R.string.stage_preparing))
            val displayName = withContext(Dispatchers.IO) { queryDisplayName(uri) }
            val outcome = ScanController.enqueueFromUri(this@MainActivity, uri, displayName)
            if (!outcome.enqueued) {
                ScanStore.markFailed(this@MainActivity, outcome.message ?: getString(R.string.stage_failed))
            } else {
                reloadEngine()
            }
        }
    }

    private fun installSignature(kind: SignatureStore.Kind, uri: Uri) {
        lifecycleScope.launch {
            val message = withContext(Dispatchers.IO) { installBlocking(kind, uri) }
            if (message != null) {
                ScanStore.markFailed(this@MainActivity, message)
            } else {
                reloadEngine()
            }
        }
    }

    /** Kopyalama + motor gecersiz kirma; uyari mesaji varsa doner (null = sorunsuz). */
    private fun installBlocking(kind: SignatureStore.Kind, uri: Uri): String? = try {
        val displayName = queryDisplayName(uri)
        val (_, warning) = SignatureStore.install(this, kind, uri, displayName)
        ScanEngines.invalidate()
        warning
    } catch (error: Exception) {
        error.message ?: getString(R.string.signature_install_failed)
    }

    /** Motoru diskteki imzalardan yeniden kurar ve UI'a sayim/uyari bilgisi basar. */
    private fun reloadEngine() {
        lifecycleScope.launch(Dispatchers.IO) {
            val yaraFile = SignatureStore.fileOrNull(this@MainActivity, SignatureStore.Kind.YARA)
            val clamFile = SignatureStore.fileOrNull(this@MainActivity, SignatureStore.Kind.CLAM_AV)
            val acquired = ScanEngines.acquire(yaraFile, clamFile, force = false)
            withContext(Dispatchers.Main) {
                val engine = acquired.getOrNull()
                if (engine == null) {
                    ScanStore.publishEngine(null)
                    ScanStore.markFailed(
                        this@MainActivity,
                        acquired.exceptionOrNull()?.message ?: getString(R.string.engine_unknown_error)
                    )
                } else {
                    ScanStore.publishEngine(
                        EngineInfo.from(
                            engine = engine,
                            yaraPath = yaraFile?.absolutePath,
                            clamPath = clamFile?.absolutePath
                        )
                    )
                    ScanStore.markEngineReady()
                }
            }
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun queryDisplayName(uri: Uri): String? {
        val projection = arrayOf(OpenableColumns.DISPLAY_NAME)
        contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) return cursor.getString(index)
        }
        return null
    }

    private companion object {
        // SAF'ta `.yar`/`.ndb` icin kayitli bir MIME turu yoktur; genis tur listesi
        // verip dogrulamayi parser'a birakiyoruz.
        val ANY_MIME_TYPES = arrayOf("*/*")
        val APK_MIME_TYPES = arrayOf(
            "application/vnd.android.package-archive",
            "application/java-archive",
            "application/zip",
            "*/*"
        )
    }
}
