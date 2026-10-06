package org.xsecurity.scanner.autopilot

import android.content.Intent
import android.graphics.drawable.ColorDrawable
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.quarantine.QuarantinePendingActionStore
import org.xsecurity.scanner.quarantine.QuarantineUserActions
import org.xsecurity.scanner.ui.theme.XSecurityTheme

/** Full-screen fallback shown when overlay permission is absent or denied by an OEM. */
class OverlayWarningActivity : ComponentActivity() {
    private var targetPackageName by mutableStateOf<String?>(null)
    private var recordId by mutableStateOf<String?>(null)
    private var interceptionMode by mutableStateOf(false)
    private var interceptionVerdict by mutableStateOf(SecuritySignal.Verdict.KNOWN_BAD)
    private var interceptionProvider by mutableStateOf(SecuritySignal.ProviderId.SCANNER)
    private var interceptionReason by mutableStateOf("")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        window?.setBackgroundDrawable(ColorDrawable(android.graphics.Color.rgb(12, 18, 30)))
        readArguments(intent)
        setContent {
            XSecurityTheme {
                val target = targetPackageName?.let(::label) ?: getString(R.string.autopilot_unknown_target)
                if (interceptionMode) {
                    InterceptionWarningContent(
                        target = target,
                        verdict = ForegroundInterceptionLabels.verdict(this, interceptionVerdict),
                        reason = ForegroundInterceptionLabels.reason(this, interceptionReason),
                        onGoBack = {
                            val details = currentInterception()
                            if (details != null && ForegroundInterceptionCoordinator.goBack(this, details)) finish()
                        },
                        onUninstall = { launchUninstall() },
                        onOpenAnyway = {
                            targetPackageName?.let {
                                if (QuarantineUserActions.allowFor24Hours(this, it, recordId)) finish()
                            }
                        }
                    )
                } else {
                    WarningContent(
                        target = target,
                        canManagePackage = !targetPackageName.isNullOrBlank(),
                        onAllow = {
                            targetPackageName?.let { QuarantineUserActions.allowFor24Hours(this, it, recordId) }
                            finish()
                        },
                        onUninstall = { launchUninstall() },
                        onDismiss = { finish() }
                    )
                }
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
            val removed = pending.recordId?.let {
                QuarantineUserActions.markUninstalledAfterUserConfirmation(this, it)
            } ?: !isPackageInstalled(pending.packageName)
            if (interceptionMode && removed) finish()
        }
    }

    private fun isPackageInstalled(packageName: String): Boolean = try {
        packageManager.getPackageInfo(packageName, 0)
        true
    } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
        false
    } catch (_: RuntimeException) {
        true
    }

    private fun launchUninstall() {
        val pkg = targetPackageName ?: return
        val intent = QuarantineUserActions.uninstallIntent(this, pkg, recordId) ?: return
        QuarantinePendingActionStore.setUninstall(this, pkg, recordId)
        runCatching { startActivity(intent) }
    }

    private fun readArguments(intent: Intent?) {
        targetPackageName = intent?.getStringExtra(OverlayWarning.EXTRA_PACKAGE)?.takeIf { it.isNotBlank() }
        recordId = intent?.getStringExtra(OverlayWarning.EXTRA_RECORD_ID)
        interceptionMode = intent?.getBooleanExtra(OverlayWarning.EXTRA_INTERCEPTION, false) == true
        interceptionVerdict = intent?.getStringExtra(OverlayWarning.EXTRA_VERDICT)?.let { raw ->
            runCatching { SecuritySignal.Verdict.valueOf(raw) }.getOrDefault(SecuritySignal.Verdict.KNOWN_BAD)
        } ?: SecuritySignal.Verdict.KNOWN_BAD
        interceptionProvider = intent?.getStringExtra(OverlayWarning.EXTRA_PROVIDER)?.let { raw ->
            runCatching { SecuritySignal.ProviderId.valueOf(raw) }.getOrDefault(SecuritySignal.ProviderId.SCANNER)
        } ?: SecuritySignal.ProviderId.SCANNER
        interceptionReason = intent?.getStringExtra(OverlayWarning.EXTRA_REASON).orEmpty()
    }

    private fun currentInterception(): ForegroundInterception? = targetPackageName?.let { packageName ->
        ForegroundInterception(
            packageName = packageName,
            verdict = interceptionVerdict,
            provider = interceptionProvider,
            reasonCode = interceptionReason,
            recordId = recordId
        )
    }

    private fun label(packageName: String): String = try {
        val info = packageManager.getApplicationInfo(packageName, 0)
        packageManager.getApplicationLabel(info).toString().ifBlank { packageName }
    } catch (_: Exception) {
        packageName
    }
}

@Composable
private fun InterceptionWarningContent(
    target: String,
    verdict: String,
    reason: String,
    onGoBack: () -> Unit,
    onUninstall: () -> Unit,
    onOpenAnyway: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0C121E))
            .padding(28.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = stringResource(R.string.autopilot_interception_title),
            style = MaterialTheme.typography.headlineSmall,
            color = Color.White,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.autopilot_interception_body, target),
            style = MaterialTheme.typography.bodyLarge,
            color = Color.White
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.autopilot_interception_details, verdict, reason),
            style = MaterialTheme.typography.bodyMedium,
            color = Color.LightGray
        )
        Spacer(Modifier.height(28.dp))
        Button(onClick = onGoBack, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.autopilot_go_back))
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onUninstall, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.action_uninstall))
        }
        Spacer(Modifier.height(8.dp))
        Button(onClick = onOpenAnyway, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.autopilot_open_anyway_24h))
        }
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
