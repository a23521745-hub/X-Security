package org.xsecurity.scanner.privacy

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

enum class PrivacyPhase { IDLE, SCANNING, DONE }

data class PrivacyItem(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val groups: Set<PrivacyRisk.Group>,
    val level: PrivacyRisk.Level
)

data class PrivacyState(
    val phase: PrivacyPhase = PrivacyPhase.IDLE,
    val items: List<PrivacyItem> = emptyList(),
    val scannedAt: Long = 0L
) {
    /** Hic denetim yapilmadi mi (kart "bilinmiyor" gosterir)? */
    val neverScanned: Boolean get() = phase == PrivacyPhase.IDLE && scannedAt == 0L
}

/**
 * Gizlilik Danismani durumu: Store+StateFlow. Kalicilik YOK — ekran her
 * acildiginda yeniden denetlenir (izinler Ayarlar'dan her an degisebilir;
 * eski liste yaniltici olur).
 */
object PrivacyStore {

    private val _state = MutableStateFlow(PrivacyState())
    val state: StateFlow<PrivacyState> = _state.asStateFlow()

    fun markScanning() {
        _state.value = _state.value.copy(phase = PrivacyPhase.SCANNING)
    }

    suspend fun scan(context: Context) = withContext(Dispatchers.IO) {
        markScanning()
        val appContext = context.applicationContext
        try {
            val apps = PrivacyScanner.scan(appContext).map { granted ->
                PrivacyRisk.App(
                    packageName = granted.packageName,
                    label = granted.label,
                    isSystem = granted.isSystem,
                    groups = PrivacyRisk.groupsFor(granted.grantedPermissions)
                )
            }
            val items = PrivacyRisk.sort(apps).map { app ->
                PrivacyItem(
                    packageName = app.packageName,
                    label = app.label,
                    isSystem = app.isSystem,
                    groups = app.groups,
                    level = app.level
                )
            }
            _state.value = PrivacyState(
                phase = PrivacyPhase.DONE,
                items = items,
                scannedAt = System.currentTimeMillis()
            )
        } catch (cancelled: CancellationException) {
            _state.value = _state.value.copy(phase = PrivacyPhase.DONE)
            throw cancelled
        } catch (_: Throwable) {
            // Denetim hatasi onceki listeyi silmez; yalnizca "taraniyor" biter.
            _state.value = _state.value.copy(phase = PrivacyPhase.DONE)
        }
    }
}
