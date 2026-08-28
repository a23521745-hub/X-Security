package org.xsecurity.scanner.ota

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.BuildConfig
import java.io.File
import java.net.URL

/**
 * UI'in OTA'ya tek temas noktasi: kontrol et, indir, kur.
 *
 * Tum ag/calistirma isleri [Dispatchers.IO] uzerinde; durum [OtaStore]'a yazilir.
 * Kurulum asla otomatik tetiklenmez — [install] yalnizca kullanici "Kur"a bastiginda
 * cagrilir ve sistemin paket kurulum ekrani acilir.
 */
object OtaController {

    const val DOWNLOAD_WORK_NAME = "xsec_ota_download"
    private const val OTA_DIR = "ota"

    /** Derleme zamaninda enjekte edilen degerlerden calisma yapilandirmasini kurar. */
    fun currentConfig(): OtaConfig {
        val manifestUrl = BuildConfig.OTA_MANIFEST_URL.orEmpty().trim()
        val pem = BuildConfig.OTA_PUBLIC_KEY_PEM.ifBlank { OtaConfig.SAMPLE_PUBLIC_KEY_PEM }
        val configured = manifestUrl.isNotBlank()
        val hosts = LinkedHashSet<String>()
        BuildConfig.OTA_ALLOWED_HOSTS.split(',').map { it.trim().lowercase() }
            .filter { it.isNotBlank() }
            .forEach(hosts::add)
        if (configured) {
            runCatching { URL(manifestUrl).host?.lowercase() }
                .getOrNull()
                ?.takeIf { it.isNotBlank() }
                ?.let(hosts::add)
        }
        return OtaConfig(manifestUrl = manifestUrl, publicKeyPem = pem, allowedHosts = hosts)
    }

    fun currentVersionCode(context: Context): Long = try {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(context.packageName, android.content.pm.PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, 0)
        }
        info.longVersionCode
    } catch (_: Throwable) {
        0L
    }

    suspend fun check(context: Context) = withContext(Dispatchers.IO) {
        OtaStore.checking()
        val config = currentConfig()
        if (!config.isConfigured) {
            OtaStore.notConfigured("OTA sunucu adresi yapılandırılmamış; güncelleme kontrolü devre dışı.")
            return@withContext
        }
        when (val outcome = OtaChecker(config).check(currentVersionCode(context))) {
            is OtaChecker.Outcome.UpdateAvailable -> OtaStore.updateAvailable(outcome.info)
            OtaChecker.Outcome.UpToDate -> OtaStore.upToDate()
            is OtaChecker.Outcome.NotConfigured -> OtaStore.notConfigured(outcome.message)
            is OtaChecker.Outcome.Error -> OtaStore.error(outcome.message)
        }
    }

    fun enqueueDownload(context: Context, info: UpdateInfo) {
        val request = OneTimeWorkRequestBuilder<OtaDownloadWorker>()
            .setInputData(
                Data.Builder()
                    .putString(OtaDownloadWorker.KEY_INFO_JSON, info.toJson())
                    .build()
            )
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            DOWNLOAD_WORK_NAME,
            ExistingWorkPolicy.KEEP,
            request
        )
    }

    fun cancelDownload(context: Context) {
        runCatching { WorkManager.getInstance(context).cancelUniqueWork(DOWNLOAD_WORK_NAME) }
    }

    /** Inen APK'yi kurmak icin sistem ekranini acar; donus sonucu UI'a mesaj olarak yansir. */
    fun install(context: Context, apk: File): Result {
        return when (val result = OtaInstaller.install(
            context = context,
            apk = apk,
            expectedPackage = context.packageName,
            expectedVersionCode = currentVersionCode(context)
        )) {
            OtaInstaller.Result.LaunchPrompt -> Result.InstallPromptLaunched
            is OtaInstaller.Result.NeedsPermission -> Result.NeedsPermission(result.settingsIntent)
            is OtaInstaller.Result.Failure -> Result.Error(result.message)
        }
    }

    /** APK'nin indirildigi uygulama-ozel dizin. */
    fun downloadDirectory(context: Context): File =
        File(context.cacheDir, OTA_DIR).apply { if (!isDirectory) mkdirs() }

    sealed class Result {
        object InstallPromptLaunched : Result()
        data class NeedsPermission(val settingsIntent: Intent) : Result()
        data class Error(val message: String) : Result()
    }
}
