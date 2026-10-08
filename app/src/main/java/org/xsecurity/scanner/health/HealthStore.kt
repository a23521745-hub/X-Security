package org.xsecurity.scanner.health

import android.content.Context
import android.os.Build
import android.provider.Settings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

/**
 * Cihaz sagligi durumu: Store+StateFlow. Okuma ucuzdur (bir dosya-kumesi
 * `stat` + iki sistem okumasi); kalicilik YOK — her acilista taze hesaplanir.
 */
object HealthStore {

    private val _snapshot = MutableStateFlow(DeviceHealth.Snapshot())
    val snapshot: StateFlow<DeviceHealth.Snapshot> = _snapshot.asStateFlow()

    fun refresh(context: Context) {
        val appContext = context.applicationContext
        val su = DeviceHealth.findSu { path ->
            try {
                File(path).exists()
            } catch (_: Throwable) {
                false
            }
        }
        val adb = try {
            Settings.Global.getInt(appContext.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (_: Throwable) {
            false
        }
        _snapshot.value = DeviceHealth.evaluate(su, DeviceHealth.hasTestKeys(Build.TAGS), adb)
    }
}
