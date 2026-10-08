package org.xsecurity.scanner.tile

import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import org.xsecurity.scanner.R
import org.xsecurity.scanner.data.ScanController

/**
 * Hizli ayar karosu: tek dokunusla kurulu-uygulama taramasi baslatir.
 *
 *  - Ekran kilitliyken de calisir (WorkManager kuyruklama kilit gerektirmez).
 *  - `hasPendingScans` en fazla ~2 sn bloklar; ana diziyi kilitlememek icin
 *    arka plan dizisinde cagrilir, karo + toast ana dizide guncellenir.
 *  - Yeni izin YOK; karo etiketi/simgesi manifesttedir.
 */
class ScanTileService : TileService() {

    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onStartListening() {
        super.onStartListening()
        paint(state = Tile.STATE_INACTIVE)
        Thread {
            val busy = runCatching { ScanController.hasPendingScans(this) }.getOrDefault(false)
            mainHandler.post { paint(state = if (busy) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE) }
        }.start()
    }

    override fun onClick() {
        super.onClick()
        // Kilitli ekranda da kuyruklama denenir; sonuc toast'la bildirilir.
        Thread {
            val busy = runCatching { ScanController.hasPendingScans(this) }.getOrDefault(false)
            if (!busy) {
                runCatching { ScanController.enqueueDeviceScan(this, includeSystemApps = false) }
            }
            mainHandler.post {
                runCatching {
                    Toast.makeText(
                        this,
                        getString(if (busy) R.string.tile_scan_running else R.string.tile_scan_started),
                        Toast.LENGTH_SHORT
                    ).show()
                }
                paint(state = Tile.STATE_ACTIVE)
            }
        }.start()
    }

    private fun paint(state: Int) {
        val tile = qsTile ?: return
        runCatching {
            tile.state = state
            tile.label = getString(R.string.tile_label)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = getString(R.string.tile_subtitle)
            }
            tile.updateTile()
        }
    }
}
