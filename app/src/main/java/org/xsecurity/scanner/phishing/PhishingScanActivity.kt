package org.xsecurity.scanner.phishing

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import org.xsecurity.scanner.autopilot.AutopilotRuntime
import org.xsecurity.scanner.autopilot.SecurityEvent
import org.xsecurity.scanner.autopilot.SignalRequest
import org.xsecurity.scanner.ui.screens.PhishingShareScreen
import org.xsecurity.scanner.ui.theme.XSecurityTheme

/**
 * Paylasim hedefi: baska uygulamalarin "Paylas" menusunde
 * "X-Security ile tara" olarak gorunur (manifestteki `ACTION_SEND`
 * filtresiyle). Paylasilan metindeki baglantilari cihazda degerlendirir;
 * ag kullanmaz, sonuc salt-okunur gosterilir.
 */
class PhishingScanActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        PhishingStore.restore(this)
        val text = intent?.getCharSequenceExtra(android.content.Intent.EXTRA_TEXT)
            ?.toString().orEmpty()
        val findings = PhishingScanner.scanText(text, PhishingStore.blocklist(this))
        // Ephemeral only: AutoPilot records verdict/provider/reason codes; SignalRequest's
        // shared text is never serialized or written to AuditLog.
        lifecycleScope.launch {
            AutopilotRuntime.evaluate(
                this@PhishingScanActivity,
                SecurityEvent.Manual(origin = "phishing_share"),
                SignalRequest(phishingText = text)
            )
        }
        setContent {
            XSecurityTheme {
                PhishingShareScreen(findings = findings, onClose = { finish() })
            }
        }
    }
}
