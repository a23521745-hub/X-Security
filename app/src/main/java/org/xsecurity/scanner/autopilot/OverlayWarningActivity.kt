package org.xsecurity.scanner.autopilot

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.quarantine.QuarantinePendingActionStore
import org.xsecurity.scanner.quarantine.QuarantineUserActions
import org.xsecurity.scanner.ui.theme.XSecurityTheme

/** Full-screen fallback shown when overlay permission is absent or denied by an OEM. */
class OverlayWarningActivity : ComponentActivity() {
    private var packageName by mutableStateOf<String?>(null)
    private var recordId by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        readArguments(intent)
        setContent {
            XSecurityTheme {
                WarningContent(
                    target = packageName?.let(::label) ?: getString(R.string.autopilot_unknown_target),
                    canManagePackage = !packageName.isNullOrBlank(),
                    onAllow = {
                        packageName?.let { QuarantineUserActions.allowFor24Hours(this, it, recordId) }
                        finish()
                    },
                    onUninstall = { launchUninstall() },
                    onDismiss = { finish() }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        readArguments(intent)
    }

    override fun onResume() {
        super.onResume()
        QuarantinePendingActionStore.consumeUninstall(this)?.let { pending ->
            pending.recordId?.let { org.xsecurity.scanner.quarantine.QuarantineUserActions.markUninstalledAfterUserConfirmation(this, it) }
        }
    }

    private fun launchUninstall() {
        val pkg = packageName ?: return
        val intent = QuarantineUserActions.uninstallIntent(this, pkg, recordId) ?: return
        QuarantinePendingActionStore.setUninstall(this, pkg, recordId)
        runCatching { startActivity(intent) }
    }

    private fun readArguments(intent: Intent?) {
        packageName = intent?.getStringExtra(OverlayWarning.EXTRA_PACKAGE)?.takeIf { it.isNotBlank() }
        recordId = intent?.getStringExtra(OverlayWarning.EXTRA_RECORD_ID)
    }

    private fun label(packageName: String): String = try {
        val info = packageManager.getApplicationInfo(packageName, 0)
        packageManager.getApplicationLabel(info).toString().ifBlank { packageName }
    } catch (_: Exception) {
        packageName
    }
}

@Composable
private fun WarningContent(
    target: String,
    canManagePackage: Boolean,
    onAllow: () -> Unit,
    onUninstall: () -> Unit,
    onDismiss: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(28.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = stringResource(R.string.autopilot_overlay_title),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(16.dp))
        Text(text = stringResource(R.string.autopilot_overlay_body, target), style = MaterialTheme.typography.bodyLarge)
        Spacer(Modifier.height(28.dp))
        if (canManagePackage) {
            Button(onClick = onAllow, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.autopilot_allow_24h))
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = onUninstall, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_uninstall))
            }
        }
        TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.autopilot_dismiss))
        }
    }
}
