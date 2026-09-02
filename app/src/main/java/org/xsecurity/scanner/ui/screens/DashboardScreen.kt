package org.xsecurity.scanner.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.engine.ScanResult
import org.xsecurity.scanner.engine.ThreatMatch
import org.xsecurity.scanner.data.EngineInfo
import org.xsecurity.scanner.data.ScanHistoryEntry
import org.xsecurity.scanner.data.ScanPhase
import org.xsecurity.scanner.data.ScanUiState
import org.xsecurity.scanner.definitions.DefinitionsState
import org.xsecurity.scanner.device.DeviceScanState
import org.xsecurity.scanner.device.ProtectionMode
import org.xsecurity.scanner.device.ProtectionState
import org.xsecurity.scanner.ota.OtaState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Ana ekran.
 *
 * Onceki surum tamamen sabit metinler gosteriyordu ("Your Device is Secure",
 * "12,547 dosya tarandi", "Real-time Protection: Active") ve `ApkScanWorker`
 * sonuclarini hic okumuyordu. Artik tum alanlar [ScanUiState]'ten geliyor;
 * tarama tamamlanmadiysa arayuz "temiz" demiyor, hata/uyari gösteriyor.
 */
@Composable
fun DashboardScreen(
    state: ScanUiState,
    otaState: OtaState,
    defState: DefinitionsState,
    deviceState: DeviceScanState,
    protectionState: ProtectionState,
    installedVersionCode: Long,
    historyEntries: List<ScanHistoryEntry>,
    onScanApk: () -> Unit,
    onScanDevice: (includeSystemApps: Boolean) -> Unit,
    onUninstall: (packageName: String) -> Unit,
    onProtectionModeChange: (ProtectionMode) -> Unit,
    onProtectionQuietChange: (Boolean) -> Unit,
    onOpenHistory: () -> Unit,
    storageGranted: Boolean,
    protectionServiceRunning: Boolean,
    onRequestStorage: () -> Unit,
    onPickYaraRules: () -> Unit,
    onPickClamDatabase: () -> Unit,
    onReloadEngine: () -> Unit,
    onCancelScan: () -> Unit,
    onCheckUpdate: () -> Unit,
    onDownloadUpdate: () -> Unit,
    onInstallUpdate: () -> Unit,
    onCheckDefinitions: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Header()
        StatusCard(state = state, onCancelScan = onCancelScan)
        LastScanCard(state = state)
        ThreatsCard(result = state.lastResult)
        DeviceScanCard(
            state = deviceState,
            scanBusy = state.isBusy || deviceState.isRunning,
            onScanAll = onScanDevice,
            onUninstall = onUninstall
        )
        HistoryCard(entries = historyEntries, onOpenHistory = onOpenHistory)
        ProtectionCard(
            state = protectionState,
            onModeChange = onProtectionModeChange,
            onQuietChange = onProtectionQuietChange,
            storageGranted = storageGranted,
            serviceRunning = protectionServiceRunning,
            onRequestStorage = onRequestStorage
        )
        EngineCard(engine = state.engine, onPickYara = onPickYaraRules, onPickClam = onPickClamDatabase, onReload = onReloadEngine)
        OtaUpdateCard(
            state = otaState,
            installedVersionCode = installedVersionCode,
            onCheck = onCheckUpdate,
            onDownload = onDownloadUpdate,
            onInstall = onInstallUpdate
        )
        DefinitionsCard(
            state = defState,
            engine = state.engine,
            onCheck = onCheckDefinitions
        )
        ScanActionButton(enabled = !state.isBusy, onScanApk = onScanApk)
        Footnote()
    }
}

private val ScanUiState.isBusy: Boolean
    get() = phase == ScanPhase.QUEUED || phase == ScanPhase.SCANNING

@Composable
private fun Header() {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            text = stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = stringResource(R.string.dashboard_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun StatusCard(state: ScanUiState, onCancelScan: () -> Unit) {
    val result0 = state.lastResult
    val palette = when {
        state.phase == ScanPhase.SCANNING || state.phase == ScanPhase.QUEUED -> StatusPalette(
            icon = Icons.Filled.Refresh,
            title = stringResource(R.string.status_scanning),
            container = MaterialTheme.colorScheme.secondaryContainer,
            onContainer = MaterialTheme.colorScheme.onSecondaryContainer
        )
        state.phase == ScanPhase.FAILED -> StatusPalette(
            icon = Icons.Filled.Warning,
            title = stringResource(R.string.status_failed),
            container = MaterialTheme.colorScheme.errorContainer,
            onContainer = MaterialTheme.colorScheme.onErrorContainer
        )
        result0 == null -> StatusPalette(
            icon = Icons.Filled.Info,
            title = stringResource(R.string.status_idle),
            container = MaterialTheme.colorScheme.surfaceVariant,
            onContainer = MaterialTheme.colorScheme.onSurfaceVariant
        )
        result0.isInfected -> StatusPalette(
            icon = Icons.Filled.Warning,
            title = stringResource(R.string.status_threats, result0.threats.size),
            container = MaterialTheme.colorScheme.errorContainer,
            onContainer = MaterialTheme.colorScheme.onErrorContainer
        )
        else -> StatusPalette(
            icon = Icons.Filled.Check,
            title = stringResource(R.string.status_clean),
            container = MaterialTheme.colorScheme.primaryContainer,
            onContainer = MaterialTheme.colorScheme.onPrimaryContainer
        )
    }

    val result = state.lastResult
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = palette.container)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Icon(
                imageVector = palette.icon,
                contentDescription = null,
                modifier = Modifier.size(44.dp),
                tint = palette.onContainer
            )
            Text(
                text = palette.title,
                style = MaterialTheme.typography.titleLarge,
                color = palette.onContainer,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )
            val subtitle = when {
                !state.message.isNullOrBlank() -> state.message
                state.phase == ScanPhase.SCANNING -> stringResource(
                    R.string.status_scanning_percent,
                    (state.progress * 100f).toInt().coerceIn(0, 100)
                )
                state.phase == ScanPhase.QUEUED -> stringResource(R.string.status_queued)
                result != null && result.isComplete -> stringResource(
                    R.string.status_result_summary,
                    formatBytes(result.bytesScanned),
                    result.durationMillis
                )
                else -> stringResource(R.string.status_idle_hint)
            }
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = palette.onContainer,
                textAlign = TextAlign.Center
            )
            if (state.isBusy) {
                LinearProgressIndicator(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp)
                )
                OutlinedButton(onClick = onCancelScan) {
                    Text(stringResource(R.string.action_cancel))
                }
            }
            if (result != null && result.engineWarnings.isNotEmpty()) {
                WarningsBlock(result.engineWarnings, palette.onContainer)
            }
        }
    }
}

private class StatusPalette(
    val icon: ImageVector,
    val title: String,
    val container: Color,
    val onContainer: Color
)

@Composable
private fun LastScanCard(state: ScanUiState) {
    val formatter = remember { SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()) }
    SectionCard(title = stringResource(R.string.lastscan_title)) {
        InfoRow(
            label = stringResource(R.string.lastscan_finished),
            value = if (state.finishedAt > 0L) formatter.format(Date(state.finishedAt)) else stringResource(R.string.value_none)
        )
        InfoRow(
            label = stringResource(R.string.lastscan_count),
            value = state.scannedFiles.toString()
        )
        val result = state.lastResult
        if (result != null) {
            InfoRow(label = stringResource(R.string.lastscan_file), value = result.fileName)
            InfoRow(label = stringResource(R.string.lastscan_size), value = formatBytes(result.fileSize))
            InfoRow(
                label = stringResource(R.string.lastscan_hash),
                value = result.sha256?.take(16) ?: stringResource(R.string.value_none)
            )
            InfoRow(
                label = stringResource(R.string.lastscan_duration),
                value = stringResource(R.string.duration_ms, result.durationMillis)
            )
        }
    }
}

@Composable
private fun ThreatsCard(result: ScanResult?) {
    val threats = result?.threats.orEmpty()
    if (threats.isEmpty() && (result == null || !result.isComplete)) {
        // Tarama hata ile bittiyse "tehdit yok" izlenimi verme.
        SectionCard(title = stringResource(R.string.threats_title)) {
            Text(
                text = stringResource(R.string.threats_unknown),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        return
    }
    SectionCard(
        title = if (threats.isEmpty()) {
            stringResource(R.string.threats_none)
        } else {
            stringResource(R.string.threats_found, threats.size)
        }
    ) {
        if (threats.isEmpty()) {
            Text(
                text = stringResource(R.string.threats_none_hint),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            threats.take(MAX_VISIBLE_THREATS).forEach { threat ->
                ThreatRow(threat)
            }
            if (threats.size > MAX_VISIBLE_THREATS) {
                Text(
                    text = stringResource(R.string.threats_more, threats.size - MAX_VISIBLE_THREATS),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun ThreatRow(threat: ThreatMatch) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.35f),
                RoundedCornerShape(12.dp)
            )
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = Icons.Filled.Warning,
            contentDescription = null,
            modifier = Modifier.size(20.dp),
            tint = MaterialTheme.colorScheme.error
        )
        Spacer(modifier = Modifier.width(10.dp))
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(text = threat.name, style = MaterialTheme.typography.titleSmall)
            Text(
                text = listOfNotNull(threat.engine, threat.detail).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Kompakt "Tarama gecmisi" karti: kayıt sayisi + son tarama satiri; dokununca
 * [HistoryScreen] acilir. Tum liste o ekranda; burada tek satir ozet.
 */
@Composable
private fun HistoryCard(entries: List<ScanHistoryEntry>, onOpenHistory: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpenHistory),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = stringResource(R.string.history_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            if (entries.isEmpty()) {
                Text(
                    text = stringResource(R.string.history_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                val latest = entries.first()
                val (icon, typeLabel) = historyTypeBadge(latest.type)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = icon,
                        contentDescription = typeLabel,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = latest.title,
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    HistoryStatusChip(latest)
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = stringResource(R.string.history_count, entries.size),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = relativeLabel(latest.timestamp, remember { SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()) }),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun HistoryStatusChip(entry: ScanHistoryEntry) {
    val (label, color) = when {
        entry.isThreats ->
            stringResource(R.string.history_threats_count, entry.threatCount) to MaterialTheme.colorScheme.error
        entry.isFailed ->
            stringResource(R.string.history_failed) to MaterialTheme.colorScheme.onSurfaceVariant
        else ->
            stringResource(R.string.history_clean) to MaterialTheme.colorScheme.primary
    }
    Text(
        text = label,
        style = MaterialTheme.typography.labelLarge,
        color = color,
        fontWeight = FontWeight.Bold
    )
}

@Composable
private fun EngineCard(
    engine: EngineInfo?,
    onPickYara: () -> Unit,
    onPickClam: () -> Unit,
    onReload: () -> Unit
) {
    SectionCard(title = stringResource(R.string.engine_title)) {
        if (engine == null) {
            Text(
                text = stringResource(R.string.engine_not_loaded),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error
            )
        } else {
            InfoRow(
                label = stringResource(R.string.engine_yara_rules),
                value = engine.yaraRules.toString()
            )
            InfoRow(
                label = stringResource(R.string.engine_yara_patterns),
                value = engine.yaraPatterns.toString()
            )
            InfoRow(
                label = stringResource(R.string.engine_clam_signatures),
                value = engine.clamSignatures.toString()
            )
            InfoRow(
                label = stringResource(R.string.engine_hash_signatures),
                value = engine.hashSignatures.toString()
            )
            if (engine.warnings.isNotEmpty()) {
                WarningsBlock(engine.warnings, MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onPickYara, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.engine_pick_yara), style = MaterialTheme.typography.labelLarge)
            }
            OutlinedButton(onClick = onPickClam, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.engine_pick_clam), style = MaterialTheme.typography.labelLarge)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(onClick = onReload) {
                Icon(imageVector = Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.engine_reload))
            }
            Text(
                text = stringResource(R.string.engine_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun ScanActionButton(enabled: Boolean, onScanApk: () -> Unit) {
    Button(
        onClick = onScanApk,
        enabled = enabled,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors()
    ) {
        Icon(
            imageVector = if (enabled) Icons.Filled.PlayArrow else Icons.Filled.Refresh,
            contentDescription = null,
            modifier = Modifier.size(22.dp)
        )
        Spacer(modifier = Modifier.width(10.dp))
        Text(
            text = stringResource(if (enabled) R.string.action_scan else R.string.action_scan_busy),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(vertical = 8.dp)
        )
    }
}

@Composable
private fun Footnote() {
    Text(
        text = stringResource(R.string.dashboard_footnote, stringResource(R.string.app_version)),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(bottom = 8.dp)
    )
}

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
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
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            content()
        }
    }
}


@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = 12.dp)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.End,
            modifier = Modifier.weight(1f, fill = false)
        )
    }
}

@Composable
private fun WarningsBlock(warnings: List<String>, tint: Color) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                RoundedCornerShape(12.dp)
            )
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(
            text = stringResource(R.string.engine_warnings_title, warnings.size),
            style = MaterialTheme.typography.labelLarge,
            color = tint,
            fontWeight = FontWeight.SemiBold
        )
        warnings.take(MAX_VISIBLE_WARNINGS).forEach { warning ->
            Text(
                text = "• $warning",
                style = MaterialTheme.typography.bodySmall,
                color = tint
            )
        }
        if (warnings.size > MAX_VISIBLE_WARNINGS) {
            Text(
                text = stringResource(R.string.engine_warnings_more, warnings.size - MAX_VISIBLE_WARNINGS),
                style = MaterialTheme.typography.bodySmall,
                color = tint
            )
        }
    }
}

// internal: HistoryScreen'in detayindaki "taranan veri" satirinda da kullanilir.
internal fun formatBytes(bytes: Long): String {
    if (bytes <= 0L) return "0 B"
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var value = bytes.toDouble()
    var index = 0
    while (value >= 1024.0 && index < units.size - 1) {
        value /= 1024.0
        index++
    }
    return if (index == 0) {
        "${bytes} B"
    } else {
        String.format(Locale.US, "%.1f %s", value, units[index])
    }
}

private const val MAX_VISIBLE_THREATS = 12
private const val MAX_VISIBLE_WARNINGS = 6
