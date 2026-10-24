package org.xsecurity.scanner.definitions

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.BuildConfig
import org.xsecurity.scanner.R
import org.xsecurity.scanner.community.CommunityStore
import org.xsecurity.scanner.data.SignatureStore
import org.xsecurity.scanner.data.UpdatePreferences
import org.xsecurity.scanner.engine.ApkScannerEngine
import org.xsecurity.scanner.engine.ScanEngines
import org.xsecurity.scanner.ota.OtaConfig
import org.xsecurity.scanner.ota.OtaController
import org.xsecurity.scanner.worker.DefinitionsUpdateWorker
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * UI'in tanim kanalina tek temas noktasi: kontrol et, indir, kur.
 *
 * APK guncellemesinden farki: imzali tanim paketi **otomatik kurulur** (kullanici
 * onayı gerekmez — bu klasik freshclam davranisidir). Guvenlik zinciri:
 * manifest RSA imzasi -> dosya basina SHA-256 -> atomik kurulum -> motor
 * onbelleginin gecersiz kilinmasi.
 *
 * Istisna: kullanici SAF ile kendi `.yar`/`.ndb` dosyasini kurmussa (`source == "user"`)
 * otomatik kurulum **o dosyalarin uzerine yazmaz**; guncelleme sadece bildirilir.
 */
object DefinitionsController {

    const val PERIODIC_WORK_NAME = "xsec_definitions_check"
    const val MANUAL_WORK_NAME = "xsec_definitions_manual"

    /**
     * Tanim kanali yapilandirmasi OTA yapilandirmasindan turenilir: ayni imza
     * anahtari, ayni izinli hostlar, ayni dizinde `definitions.json`.
     */
    fun currentConfig(context: Context): DefinitionsConfig =
        DefinitionsConfig.derive(
            otaManifestUrl = BuildConfig.OTA_MANIFEST_URL.orEmpty(),
            otaPublicKeyPem = BuildConfig.OTA_PUBLIC_KEY_PEM.ifBlank { OtaConfig.SAMPLE_PUBLIC_KEY_PEM },
            otaAllowedHostsCsv = BuildConfig.OTA_ALLOWED_HOSTS
        )

    /** Kontrol et; guncelleme varsa indirip kur (worker ve manuel dugme buraya gelir). */
    suspend fun checkAndInstall(context: Context): Outcome = withContext(Dispatchers.IO) {
        val appContext = context.applicationContext

        // ALI-18 review: onceki kurulumda process coktuysa yarim seti toparla
        // (ag'a cikmadan, dosya-yerel ve ucuz).
        runCatching { SignatureStore.recoverInterruptedInstall(appContext) }

        DefinitionsStore.checking()
        val config = currentConfig(appContext)
        if (!config.isConfigured) {
            val message = appContext.getString(R.string.def_not_configured)
            DefinitionsStore.notConfigured(message)
            return@withContext Outcome.NotConfigured
        }

        val currentDefVersion = DefinitionsStore.installedDefVersion(appContext)
        val appVersionCode = OtaController.currentVersionCode(appContext)

        val outcome = DefinitionsChecker(config).check(currentDefVersion, appVersionCode)
        val manifest = when (outcome) {
            is DefinitionsChecker.Outcome.UpdateAvailable -> outcome.manifest
            DefinitionsChecker.Outcome.UpToDate -> {
                DefinitionsStore.upToDate()
                return@withContext Outcome.UpToDate
            }
            is DefinitionsChecker.Outcome.NotConfigured -> {
                DefinitionsStore.notConfigured(outcome.message)
                return@withContext Outcome.NotConfigured
            }
            is DefinitionsChecker.Outcome.Error -> {
                DefinitionsStore.error(outcome.message)
                return@withContext Outcome.Error(outcome.message)
            }
        }

        DefinitionsStore.updateAvailable(manifest)

        // Kullanicinin kendi veritabani varsa uzerine yazilmaz.
        val userOwned = SignatureStore.Kind.values().any { kind ->
            SignatureStore.info(appContext, kind).source == "user"
        }
        if (userOwned) {
            val message = appContext.getString(R.string.def_user_db_protected)
            DefinitionsStore.notice(message)
            return@withContext Outcome.AvailableNotInstalled(manifest.defVersion, message)
        }

        DefinitionsStore.downloading(manifest)
        val directory = SignatureStore.directory(appContext)
        val staged = LinkedHashMap<SignatureStore.Kind, File>()
        val downloader = DefinitionsDownloader(config)

        // Trial motorunun sayilari: bildirimde yedek deger olarak kullanilir.
        var trialYaraRules = 0
        var trialClamSignatures = 0
        var trialHashSignatures = 0

        try {
            var completed = 0
            for (file in manifest.files) {
                val target = File(directory, file.kind.fileName + ".download")
                if (target.isFile) target.delete()
                val result = downloader.download(
                    url = file.url,
                    expectedSha256 = file.sha256,
                    expectedSize = file.sizeBytes,
                    target = target,
                    onProgress = { fraction ->
                        DefinitionsStore.setDownloadProgress(
                            (completed + fraction) / manifest.files.size
                        )
                    }
                )
                when (result) {
                    is DefinitionsDownloader.Result.Success -> staged[file.kind] = result.file
                    is DefinitionsDownloader.Result.Failure -> {
                        staged.values.forEach { runCatching { it.delete() } }
                        DefinitionsStore.error(result.message)
                        return@withContext Outcome.Error(result.message)
                    }
                }
                completed++
            }

            // ALI-18 #2: (1) trial-load — efektif set (staged + degismeyen aktif
            // dosyalar) motor tarafindan yuklenebiliyor mu? Aktif sete dokunmadan
            // dogrulanir; yuklenemeyen set kurulmaz.
            val effYara = staged[SignatureStore.Kind.YARA]
                ?: SignatureStore.fileOrNull(appContext, SignatureStore.Kind.YARA)
            val effClam = staged[SignatureStore.Kind.CLAM_AV]
                ?: SignatureStore.fileOrNull(appContext, SignatureStore.Kind.CLAM_AV)
            val effHash = staged[SignatureStore.Kind.CLAM_HASHES]
                ?: SignatureStore.fileOrNull(appContext, SignatureStore.Kind.CLAM_HASHES)
            val trial = runCatching {
                ApkScannerEngine.load(
                    effYara,
                    effClam,
                    effHash,
                    CommunityStore.enabledYaraFiles(appContext),
                    CommunityStore.enabledHashFiles(appContext)
                )
            }.getOrElse { Result.failure(it) }
            if (trial.isFailure) {
                val reason = trial.exceptionOrNull()?.message
                    ?: appContext.getString(R.string.def_error_generic)
                val message = "Definitions update rejected: staged set cannot be loaded ($reason)."
                staged.values.forEach { runCatching { it.delete() } }
                DefinitionsStore.error(message)
                return@withContext Outcome.Error(message)
            }
            val trialEngine = trial.getOrThrow()
            // ALI-18 review: "motor acildi" yetmez — dosyasi olan her katman
            // KULLANILABILIR sayida kural/imza vermeli (sessizce olen katmanla
            // guncelleme kabul edilmez).
            checkEffectiveUsability(
                trialEngine,
                hasYaraFile = effYara != null,
                hasClamFile = effClam != null,
                hasHashFile = effHash != null
            )?.let { reason ->
                staged.values.forEach { runCatching { it.delete() } }
                DefinitionsStore.error(reason)
                return@withContext Outcome.Error(reason)
            }
            trialYaraRules = trialEngine.yaraStats.ruleCount
            trialClamSignatures = trialEngine.clamAvSignatureCount
            trialHashSignatures = trialEngine.hashSignatureCount

            // (2) Atomik kurulum: ya hep ya hic. Hatada eski set + prefs korunur.
            val installError = SignatureStore.installSetFromDownload(
                context = appContext,
                staged = staged,
                source = "ota-v${manifest.defVersion}"
            )
            staged.values.forEach { runCatching { it.delete() } }
            if (installError != null) {
                DefinitionsStore.error(installError)
                return@withContext Outcome.Error(installError)
            }
        } catch (error: Exception) {
            staged.values.forEach { runCatching { it.delete() } }
            val message = error.message ?: appContext.getString(R.string.def_error_generic)
            DefinitionsStore.error(message)
            return@withContext Outcome.Error(message)
        }

        DefinitionsStore.installed(manifest.defVersion)

        // Bildirim icin motoru yeni dosyalardan bir kez kur (kural/imza sayilari
        // + onbellek isitma). Yukleme patlarsa trial sayilari kullanilir.
        val yaraFile = SignatureStore.fileOrNull(appContext, SignatureStore.Kind.YARA)
        val clamFile = SignatureStore.fileOrNull(appContext, SignatureStore.Kind.CLAM_AV)
        val hashFile = SignatureStore.fileOrNull(appContext, SignatureStore.Kind.CLAM_HASHES)
        val engine = runCatching {
            ScanEngines.acquire(
                yaraFile,
                clamFile,
                hashFile,
                CommunityStore.enabledYaraFiles(appContext),
                CommunityStore.enabledHashFiles(appContext)
            ).getOrNull()
        }.getOrNull()
        runCatching {
            DefinitionsNotifications.showInstalled(
                context = appContext,
                defVersion = manifest.defVersion,
                yaraRules = engine?.yaraStats?.ruleCount ?: trialYaraRules,
                clamSignatures = engine?.clamAvSignatureCount ?: trialClamSignatures,
                hashSignatures = engine?.hashSignatureCount ?: trialHashSignatures
            )
        }

        Outcome.Installed(manifest.defVersion)
    }

    /**
     * Efektif sette dosyasi bulunan her katmanin trial motorunda KULLANILABILIR
     * sayida kural/imza urettigini dogrular (ALI-18 review).
     *
     * Saf fonksiyondur (Context yok) — birim testi `DefinitionsUsabilityTest`'tedir.
     *
     * @return sorun yoksa `null`, varsa kullaniciya gosterilebilir neden.
     */
    internal fun checkEffectiveUsability(
        engine: ApkScannerEngine,
        hasYaraFile: Boolean,
        hasClamFile: Boolean,
        hasHashFile: Boolean
    ): String? {
        if (hasYaraFile && engine.yaraRules.isEmpty()) {
            return "Definitions update rejected: YARA layer carries no usable rules."
        }
        if (hasClamFile && engine.clamAvSignatureCount <= 0) {
            return "Definitions update rejected: ClamAV layer carries no usable signatures."
        }
        if (hasHashFile && engine.hashSignatureCount <= 0) {
            return "Definitions update rejected: hash layer carries no usable signatures."
        }
        return null
    }

    /**
     * Periyodik (gunde bir) tanim kontrolunu kurar; uygulama guncellemesindeki gibi
     * yalnizca ag bagliyken calisir. Kurulum otomatik oldugu icin kullaniciyi
     * yalnizca gercekten kurulum yapildiginda bildirimle haberdar eder.
     */
    fun schedulePeriodicCheck(context: Context) {
        if (!UpdatePreferences.isAutoCheckEnabled(context)) {
            runCatching { WorkManager.getInstance(context).cancelUniqueWork(PERIODIC_WORK_NAME) }
            return
        }
        if (!currentConfig(context).isConfigured) return
        val request = PeriodicWorkRequestBuilder<DefinitionsUpdateWorker>(24, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        runCatching {
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                PERIODIC_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }

    /** "Kontrol et / Guncelle" dugmesi: tek seferlik is kuyruga yazilir. */
    fun enqueueManualCheck(context: Context) {
        val request = OneTimeWorkRequestBuilder<DefinitionsUpdateWorker>()
            .setInputData(
                androidx.work.Data.Builder()
                    .putBoolean(DefinitionsUpdateWorker.KEY_MANUAL, true)
                    .build()
            )
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        runCatching {
            WorkManager.getInstance(context).enqueueUniqueWork(
                MANUAL_WORK_NAME,
                ExistingWorkPolicy.KEEP,
                request
            )
        }
    }

    sealed class Outcome {
        object NotConfigured : Outcome()
        object UpToDate : Outcome()
        data class Installed(val defVersion: Int) : Outcome()
        data class AvailableNotInstalled(val defVersion: Int, val reason: String) : Outcome()
        data class Error(val message: String) : Outcome()
    }
}
