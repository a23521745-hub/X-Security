package org.xsecurity.scanner.device

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.core.content.ContextCompat

/**
 * Download/ klasorunu izlemek icin gereken depolama erisimi.
 *
 *  - API 30+: `MANAGE_EXTERNAL_STORAGE` ("Tum dosyalara erisim") — sistem ayar
 *    ekranindan verilir; runtime diyalogu yoktur. Bu yuzden once uygulama icinde
 *    neden-gerekli diyalogu gosterilir, sonra ayar ekrani acilir.
 *  - API 26-29: klasik `READ_EXTERNAL_STORAGE` runtime izni yeterlidir.
 */
object StorageAccess {

    fun hasAllFilesAccess(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED
        }

    /**
     * Can the app delete/write files outside its own directories through the plain File API?
     * API 30+: All Files Access (MANAGE_EXTERNAL_STORAGE). API 26-29: WRITE_EXTERNAL_STORAGE.
     * Without it, cut-and-paste quarantine routes the user's tap through the system delete dialog.
     */
    fun hasDirectDeleteAccess(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED
        }

    /** Runtime permissions to request on API 26-29 (none on 30+, where the settings screen is used). */
    val legacyRuntimePermissions: Array<String>
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) emptyArray()
        else arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE)

    /** API 30+ icin sistem "Tum dosyalara erisim" ekrani; once uygulamaya ozel, olmazsa genel liste. */
    fun settingsIntents(context: Context): List<Intent> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return emptyList()
        return listOf(
            Intent(
                Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                Uri.parse("package:" + context.packageName)
            ),
            Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
        )
    }

    val usesRuntimePermission: Boolean get() = Build.VERSION.SDK_INT < Build.VERSION_CODES.R
}
