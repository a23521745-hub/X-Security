package org.xsecurity.scanner.data

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.worker.ApkScanWorker
import org.xsecurity.scanner.worker.DeviceScanWorker
import org.xsecurity.scanner.worker.PackageScanWorker
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.UUID

/**
 * Tarama isteklerini WorkManager'a kuyruklayan tek giris noktasi.
 *
 * Onceki surumde arka plan servisinden `context.startService(...)` cagriliyordu;
 * API 26+ cihazlarda bu `IllegalStateException` ile patlar, servis ayrica hicbir is
 * yapmadan hemen `stopSelf()` cagriyordu. Servis katmani kaldirildi: arayuz dogrudan
 * WorkManager'a kuyruk yazar; ilerleme ve sonuc bellek-ici state + bildirim ile doner.
 */
object ScanController {

    private const val WORK_PREFIX = "apk_scan_"
    private const val DEVICE_WORK = "device_scan"
    private const val PACKAGE_WORK_PREFIX = "pkg_scan_"
    const val SHIELD_TAG = "xsec-shield"
    private const val SCAN_DIR = "scans"
    private const val STALE_AGE_MILLIS = 6L * 60L * 60L * 1000L

    const val TAG = "xsec-scan"

    class EnqueueResult(
        val enqueued: Boolean,
        val sha256: String?,
        val message: String?
    )

    /**
     * Secilen dosyayi uygulama onbellegine kopyalar ve taramayi kuyruga koyar.
     *
     * SAF/scoped-storage nedeniyle rastgele bir yolu dogrudan okumaya calismak
     * `FileNotFoundException` ile sonuclaniyordu; artik yalnizca kendi kopyamiz
     * taraniyor. Kopyanin adi icerik hash'idir, boylece ayni dosya iki kez taranmaz.
     */
    suspend fun enqueueFromUri(context: Context, uri: Uri, displayName: String?): EnqueueResult =
        withContext(Dispatchers.IO) {
            val staged: Staged? = try {
                stageFile(context, uri)
            } catch (error: Exception) {
                null
            }

            if (staged == null) {
                EnqueueResult(false, null, "The selected file could not be copied into app storage.")
            } else {
                purgeStaleCopies(context)
                enqueue(context, staged, displayName)
            }
        }

    private fun enqueue(context: Context, staged: Staged, displayName: String?): EnqueueResult {
        val request = OneTimeWorkRequestBuilder<ApkScanWorker>()
            .setInputData(
                Data.Builder()
                    .putString(ApkScanWorker.KEY_APK_PATH, staged.file.absolutePath)
                    .putString(ApkScanWorker.KEY_DISPLAY_NAME, displayName ?: staged.file.name)
                    .putString(ApkScanWorker.KEY_SHA256, staged.sha256)
                    .build()
            )
            .addTag(TAG)
            .build()

        return try {
            // KEEP: devam eden ayni taramayi iptal etmek yerine onu kullanir.
            // (Eski REPLACE politikasi, ikinci tiklamada ilerleyen taramayi olduruyordu.)
            WorkManager.getInstance(context).enqueueUniqueWork(
                WORK_PREFIX + staged.sha256,
                ExistingWorkPolicy.KEEP,
                request
            )
            EnqueueResult(true, staged.sha256, null)
        } catch (error: Exception) {
            staged.file.delete()
            EnqueueResult(false, staged.sha256, error.message ?: "The scan could not be queued.")
        }
    }

    /**
     * Kurulu uygulama taramasini kuyruklar. KEEP: suren tarama varsa ikinci dokunus
     * onu oldurmez. Ayni [TAG] kullanilir; "Iptal" butonu her iki turu de durdurur.
     */
    fun enqueueDeviceScan(context: Context, includeSystemApps: Boolean = false): Boolean {
        val request = OneTimeWorkRequestBuilder<DeviceScanWorker>()
            .setInputData(
                Data.Builder()
                    .putBoolean(DeviceScanWorker.KEY_INCLUDE_SYSTEM, includeSystemApps)
                    .build()
            )
            .addTag(TAG)
            .build()
        return try {
            WorkManager.getInstance(context).enqueueUniqueWork(DEVICE_WORK, ExistingWorkPolicy.KEEP, request)
            true
        } catch (error: Exception) {
            false
        }
    }

    /**
     * Kurulum ani kalkani: tek paketi kuyruklar. REPLACE: ayni paket icin arka arkaya
     * gelen ADDED/REPLACED yayinlarinda en son surum taranir. Ayri etiket: kullanicinin
     * "Iptal" dugmesi kalkan taramasini durdurmaz.
     */
    fun enqueuePackageScan(context: Context, packageName: String): Boolean {
        val request = OneTimeWorkRequestBuilder<PackageScanWorker>()
            .setInputData(Data.Builder().putString(PackageScanWorker.KEY_PACKAGE, packageName).build())
            .addTag(SHIELD_TAG)
            .build()
        return try {
            WorkManager.getInstance(context).enqueueUniqueWork(
                PACKAGE_WORK_PREFIX + packageName,
                ExistingWorkPolicy.REPLACE,
                request
            )
            true
        } catch (error: Exception) {
            false
        }
    }

    /**
     * Sistemin paket kaldirma ekranini acan intent. Uygulama hicbir zaman sessiz
     * kaldirma yapmaz (DELETE_PACKAGES normal uygulamalara verilmez ve denenmez);
     * son karar her zaman sistem diyalogunda kullaniciya aittir.
     */
    fun uninstallIntent(packageName: String): Intent =
        Intent(Intent.ACTION_DELETE, Uri.parse("package:" + packageName)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

    fun cancelAll(context: Context) {
        runCatching { WorkManager.getInstance(context).cancelAllWorkByTag(TAG) }
    }

    fun hasPendingScans(context: Context): Boolean = try {
        WorkManager.getInstance(context)
            .getWorkInfosByTag(TAG)
            .get(2, TimeUnit.SECONDS)
            .orEmpty()
            .any { !it.state.isFinished }
    } catch (error: Exception) {
        false
    }

    /** Uygulamanin tarama kopyalarini tuttugu dizin (worker basarili taramada siler). */
    fun stagingDirectory(context: Context): File =
        File(context.cacheDir, SCAN_DIR).apply { if (!isDirectory) mkdirs() }

    private class Staged(val file: File, val sha256: String)

    @Throws(IOException::class)
    private fun stageFile(context: Context, uri: Uri): Staged {
        val directory = stagingDirectory(context)
        val temp = File(directory, "incoming-${System.currentTimeMillis()}-${UUID.randomUUID()}.tmp")
        val stream = context.contentResolver.openInputStream(uri)
            ?: throw IOException("The file could not be opened: $uri")
        try {
            stream.use { input -> temp.outputStream().use { output -> input.copyTo(output) } }
            if (temp.length() <= 0L) throw IOException("The selected file is empty and cannot be scanned.")
            val sha = Digest.sha256Hex(temp)
            val target = File(directory, "$sha.apk")
            if (target.isFile && target.length() == temp.length()) {
                temp.delete()
                return Staged(target, sha)
            }
            target.delete()
            if (!temp.renameTo(target)) throw IOException("The file could not be staged in the cache.")
            return Staged(target, sha)
        } catch (error: Exception) {
            temp.delete()
            throw error
        }
    }

    private fun purgeStaleCopies(context: Context) {
        val directory = stagingDirectory(context)
        val cutoff = System.currentTimeMillis() - STALE_AGE_MILLIS
        directory.listFiles()?.forEach { entry ->
            if (entry.lastModified() < cutoff) runCatching { entry.delete() }
        }
    }
}
