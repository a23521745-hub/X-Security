package org.xsecurity.scanner.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.device.AppScanEntry
import org.xsecurity.scanner.device.DeviceScanPhase
import org.xsecurity.scanner.device.DeviceScanState
import org.xsecurity.scanner.device.DeviceScanSummary
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * "Tumunu tara" karti: kurulu uygulamalarin tamamini mevcut motorla tarar.
 *
 *  - Ilk kullanimda amac diyalogu: uygulama listesini okumanin nedeni (QUERY_ALL_PACKAGES)
 *    aciklanir; veri cihazdan cikmaz.
 *  - Tespit edilen uygulamalar icin "Kaldir" sistem kaldirma ekranini acar; uygulama
 *    hicbir zaman sessiz kaldirma yapmaz (bu mumkun degildir ve denenmez).
 */
@Composable
fun DeviceScanCard(
    state: DeviceScanState,
    scanBusy: Boolean,
    onScanAll: (includeSystemApps: Boolean) -> Unit,
    onUninstall: (packageName: String) -> Unit
) {
    var showRationale by rememberSaveable { mutableStateOf(false) }
    var includeSystem by rememberSaveable { mutableStateOf(false) }
    var showAll by rememberSaveable { mutableStateOf(false) }
    val formatter = remember { SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()) }

    if (showRationale) {
        AlertDialog(
            onDismissRequest = { showRationale = false },
            title = { Text(stringResource(R.string.device_scan_rationale_title)) },
            text = { Text(stringResource(R.string.device_scan_rationale_body)) },
            confirmButton = {
                TextButton(onClick = {
                    showRationale = false
                    onScanAll(includeSystem)
                }) { Text(stringResource(R.string.device_scan_rationale_ok)) }
            },
            dismissButton = {
                TextButton(onClick = { showRationale = false }) { Text(stringResource(R.string.action_cancel)) }
            }
        )
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(
                text = stringResource(R.string.device_scan_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = stringResource(R.string.device_scan_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            when {
                state.isRunning -> {
                    Text(
                        text = stringResource(
                            R.string.device_scan_progress,
                            state.scanned,
                            state.total,
                            state.currentLabel ?: ""
                        ),
                        style = MaterialTheme.typography.bodyMedium
                    )
                    LinearProgressIndicator(progress = { state.progress }, modifier = Modifier.fillMaxWidth())
                }
                state.phase == DeviceScanPhase.FAILED -> Text(
                    text = state.message ?: stringResource(R.string.status_failed),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
                state.phase == DeviceScanPhase.DONE -> {
                    val infected = DeviceScanSummary.infectedCount(state.entries)
                    val failed = DeviceScanSummary.failedCount(state.entries)
                    Text(
                        text = stringResource(
                            R.string.device_scan_summary,
                            state.entries.size,
                            infected,
                            failed,
                            state.cachedCount,
                            if (state.finishedAt > 0L) formatter.format(Date(state.finishedAt)) else ""
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (infected > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
                    )
                }
                else -> Text(
                    text = stringResource(R.string.device_scan_idle),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            state.infected.forEach { entry -> InfectedAppRow(entry = entry, onUninstall = onUninstall) }

            if (state.phase == DeviceScanPhase.DONE && state.entries.isNotEmpty()) {
                TextButton(onClick = { showAll = !showAll }) {
                    Text(
                        stringResource(
                            if (showAll) R.string.device_scan_hide_all else R.string.device_scan_show_all,
                            state.entries.size
                        )
                    )
                }
                if (showAll) {
                    state.entries.filterNot { it.isInfected }.take(MAX_LISTED).forEach { entry ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = entry.label,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.weight(1f, fill = false)
                            )
                            Text(
                                text = stringResource(
                                    if (entry.isFailed) R.string.device_scan_entry_failed else R.string.device_scan_entry_clean
                                ),
                                style = MaterialTheme.typography.bodySmall,
                                color = if (entry.isFailed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = includeSystem, onCheckedChange = { includeSystem = it }, enabled = !scanBusy)
                Text(
                    text = stringResource(R.string.device_scan_include_system),
                    style = MaterialTheme.typography.bodySmall
                )
            }

            Button(
                onClick = { if (state.rationaleAccepted) onScanAll(includeSystem) else showRationale = true },
                enabled = !scanBusy,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp)
            ) {
                Icon(imageVector = Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(if (scanBusy) R.string.action_scan_busy else R.string.device_scan_action))
            }
        }
    }
}

@Composable
private fun InfectedAppRow(entry: AppScanEntry, onUninstall: (String) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.35f),
                RoundedCornerShape(12.dp)
            )
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Row(verticalAlignment = Alignment.Top) {
            Icon(
                imageVector = Icons.Filled.Warning,
                contentDescription = null,
                modifier = Modifier.size(20.dp),
                tint = MaterialTheme.colorScheme.error
            )
            Spacer(modifier = Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(text = entry.label, style = MaterialTheme.typography.titleSmall)
                Text(
                    text = entry.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                entry.threats.take(3).forEach { threat ->
                    Text(
                        text = "• ${threat.name} (${threat.engine})",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
        Text(
            text = stringResource(R.string.device_scan_advice),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        OutlinedButton(onClick = { onUninstall(entry.packageName) }) {
            Icon(imageVector = Icons.Filled.Delete, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(stringResource(R.string.action_uninstall))
        }
    }
}

private const val MAX_LISTED = 200
