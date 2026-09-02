package org.xsecurity.scanner.ota

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.BuildConfig
import org.xsecurity.scanner.worker.OtaCheckWorker
import org.xsecurity.scanner.worker.OtaDownloadWorker
import java.io.File
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * UI'in OTA'ya tek temas noktasi: kontrol et, indir, kur.
 *
 * Tum ag/calistirma isleri WorkManager uzerinde; durum [OtaStore]'a yazilir.
 * Kurulum asla otomatik tetiklenmez — [install] yalnizca kullanici "Kur"a bastiginda
 * cagrilir ve sistemin paket kurulum ekrani acilir.
 */
object OtaController {

    const val DOWNLOAD_WORK_NAME = "xsec_ota_download"
    const val CHECK_WORK_NAME = "xsec_ota_check"
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
        packageVersionCode(info)
    } catch (_: Throwable) {
        0L
    }

    /** API 28 oncesinde `longVersionCode` yoktur; eski `versionCode` alanindan okunur. */
    private fun packageVersionCode(info: android.content.pm.PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            info.versionCode.toLong()
        }

    suspend fun check(context: Context) = withContext(Dispatchers.IO) {
        OtaStore.checking()
        val config = currentConfig()
        if (!config.isConfigured) {
            OtaStore.notConfigured("OTA sunucu adresi yapılandırılmamış; güncelleme kontrolü devre dışı.")
            return@withContext
        }
        when (val outcome = OtaChecker(config).check(currentVersionCode(context), Build.VERSION.SDK_INT)) {
            is OtaChecker.Outcome.UpdateAvailable -> OtaStore.updateAvailable(outcome.info)
            OtaChecker.Outcome.UpToDate -> OtaStore.upToDate()
            is OtaChecker.Outcome.NotConfigured -> OtaStore.notConfigured(outcome.message)
            is OtaChecker.Outcome.Error -> OtaStore.error(outcome.message)
        }
    }

    /**
     * Periyodik (gunde bir) güncelleme kontrolunu WorkManager'a kurar; ag bagli
     * degilse kontrol ertelenir. Kullaniciyi yormayan, kaynak dostu bir arka plan
     * isidir: uygulama acik degilken de calisabilir.
     */
    fun schedulePeriodicCheck(context: Context) {
        if (!currentConfig().isConfigured) return
        val request = PeriodicWorkRequestBuilder<OtaCheckWorker>(24, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        runCatching {
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                CHECK_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }

    /**
     * Indirmeyi kuyruga koyar:
     *  - yalnizca ag bagliyken baslar,
     *  - tikanirsa (ag kopmasi vb.) ARTAN beklemeyle WorkManager tekrar dener;
     *    [ApkDownloader] kaldigi yerden devam ettigi icin deneme bastan baslamaz.
     */
    fun enqueueDownload(context: Context, info: UpdateInfo) {
        val request = OneTimeWorkRequestBuilder<OtaDownloadWorker>()
            .setInputData(
                Data.Builder()
                    .putString(OtaDownloadWorker.KEY_INFO_JSON, info.toJson())
                    .build()
            )
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
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

    /**
     * Kur butonu: indirilmis APK'yi kuruluma sunar. Kurulum oncesi dosyanin
     * SHA-256'i manifestle bir kez daha karsilastirilir (indirme sonrasi bozulma/
     * degistirilmeye karsi savunma derinligi); uyusmazlikta dosya silinir ve
     * durum yeniden indirilebilir sekilde isaretlenir.
     */
    fun install(context: Context, apk: File): Result {
        val info = OtaStore.state.value.available
        if (info != null && apk.isFile) {
            val verified = ApkVerifier.verifyFile(
                file = apk,
                expectedSha256 = info.apkSha256,
                expectedSize = info.apkSizeBytes,
                maxBytes = OtaConfig.MAX_APK_BYTES
            )
            if (verified is ApkVerifier.Result.Failure) {
                runCatching { apk.delete() }
                OtaStore.updateAvailable(info)
                return Result.Error(
                    "İndirilen dosya doğrulanamadı ve silindi; lütfen güncellemeyi yeniden indirin. " +
                        "(${verified.message})"
                )
            }
        }

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
