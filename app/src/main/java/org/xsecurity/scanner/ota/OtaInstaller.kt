package org.xsecurity.scanner.ota

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File

/**
 * Indirilen APK'yi **yalnizca kullanici onayiyla** kurar.
 *
 * Tasarim geregi sessiz/otomatik kurulum YOKTUR:
 *  - APK bir [FileProvider] content URI'si olarak paylasilir ve sistemin standart
 *    paket kurulum ekrani acilir. Kurulum kararini (ve imza uyumsuzlugunda sistemi
 *    reddini) tamamen kullanici/Android verir.
 *  - Android 8+ icin `REQUEST_INSTALL_PACKAGES` izni kontrol edilir; yoksa kullanici
 *    "bilinmeyen kaynaklar" ayarina yonlendirilir.
 *  - Kurulumdan once [verifyArchive] ile paketin kendi uygulama kimligimiz oldugu ve surum
 *    dusurmedigi dogrulanir (savunma derinligi; nihai imza kontrolunu zaten Android yapar).
 */
object OtaInstaller {

    sealed class Result {
        object LaunchPrompt : Result()
        data class NeedsPermission(val settingsIntent: Intent) : Result()
        data class Failure(val message: String) : Result()
    }

    fun install(context: Context, apk: File, expectedPackage: String, expectedVersionCode: Long): Result {
        if (!apk.isFile) return Result.Failure("Kurulacak APK bulunamadı; lütfen yeniden indirin.")

        verifyArchive(context, apk, expectedPackage, expectedVersionCode)?.let { return Result.Failure(it) }

        if (!canRequestInstall(context)) {
            val intent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
                .setData(Uri.parse("package:${context.packageName}"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            return Result.NeedsPermission(intent)
        }

        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.ota-fileprovider",
            apk
        )
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return try {
            context.startActivity(intent)
            Result.LaunchPrompt
        } catch (error: Throwable) {
            Result.Failure("Paket kurulum ekranı açılamadı: ${error.message ?: "bilinmeyen hata"}")
        }
    }

    private fun canRequestInstall(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.packageManager.canRequestPackageInstalls()
        } else {
            true
        }

    /**
     * APK'nin paket adinin [expectedPackage] oldugunu ve surum kodunun
     * [expectedVersionCode]'tan yuksek oldugunu dogrular. Hata mesaji ya da `null`.
     */
    fun verifyArchive(
        context: Context,
        apk: File,
        expectedPackage: String,
        expectedVersionCode: Long
    ): String? = try {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageArchiveInfo(apk.absolutePath, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageArchiveInfo(apk.absolutePath, 0)
        }
        when {
            info == null -> "İndirilen dosya geçerli bir Android paketi değil."
            info.packageName != expectedPackage ->
                "Paket adı uyuşmuyor: ${info.packageName} (beklenen $expectedPackage)."
            info.longVersionCode <= expectedVersionCode ->
                "Paket sürümü yüklü sürümden yeni değil (downgrade engellendi)."
            else -> null
        }
    } catch (error: Throwable) {
        "Paket doğrulanamadı: ${error.message ?: "bilinmeyen hata"}"
    }
}
