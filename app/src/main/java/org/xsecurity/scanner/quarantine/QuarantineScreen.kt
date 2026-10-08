package org.xsecurity.scanner.quarantine

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowLeft
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Minimal quarantine list + user-only restore/uninstall controls.
 *
 * File records are labelled through [QuarantineHonesty]/[QuarantineWording]: while the original
 * file is still on the device the card says so and offers "Delete now"; it only reads
 * "quarantined" once the original is gone.
 */
@Composable
fun QuarantineScreen(
    records: List<QuarantineRecord>,
    onBack: () -> Unit,
    onAllow: (QuarantineRecord) -> Unit,
    onRestore: (QuarantineRecord) -> Unit,
    onUninstall: (QuarantineRecord) -> Unit,
    onRetry: (QuarantineRecord) -> Unit,
    onDeleteOriginal: (QuarantineRecord) -> Unit = {},
    onDeleteRecord: (QuarantineRecord) -> Unit = {}
) {
    val context = LocalContext.current
    val formatter = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault())
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .safeDrawingPadding()
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.KeyboardArrowLeft, contentDescription = stringResource(R.string.history_back))
            }
            Icon(Icons.Filled.Lock, contentDescription = null)
            Text(
                text = stringResource(R.string.quarantine_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(start = 8.dp)
            )
        }
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.quarantine_hint), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(12.dp))
        if (records.isEmpty()) {
            Text(stringResource(R.string.quarantine_empty), modifier = Modifier.padding(16.dp))
        } else {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                records.forEach { record ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                    ) {
                        val isFile = QuarantineHonesty.isFileRecord(record)
                        val display = QuarantineHonesty.displayState(record)
                        val residue = QuarantineHonesty.effectiveResidue(record)
                        val removalPending = QuarantineHonesty.originalRemovalPending(record)
                        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(record.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            if (!isFile) {
                                Text(record.packageName, style = MaterialTheme.typography.bodySmall)
                            } else {
                                Text(stringResource(R.string.quarantine_file_vault_item), style = MaterialTheme.typography.bodySmall)
                            }
                            val stateText = QuarantineWording.stateKey(display)
                                ?.let { QuarantineFileNotifications.resolve(context, it) }
                                ?: stateLabel(record.state)
                            Text(
                                text = stringResource(R.string.quarantine_state, stateText),
                                style = MaterialTheme.typography.bodyMedium
                            )
                            if (isFile && residue != null && record.state == QuarantineState.QUARANTINED) {
                                Text(
                                    text = QuarantineFileNotifications.resolve(context, QuarantineWording.residueKey(residue)),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    color = if (residue == OriginalResidue.ORIGINAL_PRESENT) MaterialTheme.colorScheme.error
                                    else MaterialTheme.colorScheme.primary
                                )
                                if (removalPending) {
                                    QuarantineWording.hintKey(record.cutResult)?.let { hintKey ->
                                        Text(
                                            QuarantineFileNotifications.resolve(context, hintKey),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                            Text(stringResource(R.string.quarantine_engine, record.engine))
                            Text(stringResource(R.string.quarantine_detected, formatter.format(Date(record.detectedAtMillis))))
                            record.sha256?.let { Text(stringResource(R.string.quarantine_hash, it.take(16))) }
                            record.failureCode?.let { Text(stringResource(R.string.quarantine_failed, failureLabel(it))) }
                            when (record.state) {
                                QuarantineState.QUARANTINED -> {
                                    if (isFile && removalPending) {
                                        Button(onClick = { onDeleteOriginal(record) }, modifier = Modifier.fillMaxWidth()) {
                                            Text(QuarantineFileNotifications.resolve(context, QuarantineWording.KEY_ACTION_DELETE_NOW))
                                        }
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        OutlinedButton(onClick = { onRestore(record) }) { Text(stringResource(R.string.quarantine_restore)) }
                                        if (!isFile) {
                                            Button(onClick = { onUninstall(record) }) { Text(stringResource(R.string.action_uninstall)) }
                                        } else {
                                            OutlinedButton(onClick = { onDeleteRecord(record) }) {
                                                Text(stringResource(R.string.quarantine_delete_record))
                                            }
                                        }
                                    }
                                    if (!isFile) {
                                        TextButton(onClick = { onAllow(record) }) {
                                            Text(stringResource(R.string.autopilot_allow_24h))
                                        }
                                    }
                                }
                                QuarantineState.FAILED -> {
                                    if (isFile) {
                                        OutlinedButton(onClick = { onDeleteRecord(record) }) {
                                            Text(stringResource(R.string.quarantine_delete_record))
                                        }
                                    } else {
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            OutlinedButton(onClick = { onRetry(record) }) { Text(stringResource(R.string.quarantine_retry)) }
                                            Button(onClick = { onUninstall(record) }) { Text(stringResource(R.string.action_uninstall)) }
                                        }
                                    }
                                }
                                QuarantineState.PENDING -> {
                                    Text(stringResource(R.string.quarantine_pending_assist))
                                    Button(onClick = { onUninstall(record) }) { Text(stringResource(R.string.action_uninstall)) }
                                }
                                QuarantineState.DETECTED, QuarantineState.RESTORED, QuarantineState.DELETED, QuarantineState.CANCELLED -> Unit
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun stateLabel(state: QuarantineState): String = when (state) {
    QuarantineState.DETECTED -> stringResource(R.string.quarantine_state_detected)
    QuarantineState.PENDING -> stringResource(R.string.quarantine_state_pending)
    QuarantineState.QUARANTINED -> stringResource(R.string.quarantine_state_quarantined)
    QuarantineState.RESTORED -> stringResource(R.string.quarantine_state_restored)
    QuarantineState.DELETED -> stringResource(R.string.quarantine_state_deleted)
    QuarantineState.FAILED -> stringResource(R.string.quarantine_state_failed)
    QuarantineState.CANCELLED -> stringResource(R.string.quarantine_state_cancelled)
}

@Composable
private fun failureLabel(code: String): String = when (code) {
    "system_package_safelisted" -> stringResource(R.string.quarantine_failure_system)
    "package_not_installed" -> stringResource(R.string.quarantine_failure_missing)
    "oem_accessibility_action_not_confirmed", "rootless_force_stop_unavailable" ->
        stringResource(R.string.quarantine_failure_oem)
    else -> stringResource(R.string.quarantine_failure_generic)
}
