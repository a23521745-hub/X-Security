package org.xsecurity.scanner.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.KeyboardArrowLeft
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.data.ScanHistoryEntry
import org.xsecurity.scanner.data.ScanHistoryStore.COUNTER_CLAM_SIGNATURES
import org.xsecurity.scanner.data.ScanHistoryStore.COUNTER_HASH_SIGNATURES
import org.xsecurity.scanner.data.ScanHistoryStore.COUNTER_YARA_PATTERNS
import org.xsecurity.scanner.data.ScanHistoryStore.COUNTER_YARA_RULES
import org.xsecurity.scanner.data.ScanHistoryStore.TRIGGER_DOWNLOAD_WATCH
import org.xsecurity.scanner.data.ScanHistoryStore.TRIGGER_FILE_PICKER
import org.xsecurity.scanner.data.ScanHistoryStore.TRIGGER_INSTALL_SHIELD
import org.xsecurity.scanner.data.ScanHistoryStore.TRIGGER_MANUAL
import org.xsecurity.scanner.data.ScanHistoryType
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Tarama gecmisi ekranı: filtre chipleri + durum renkli satirlar + genisleyen detay.
 *
 *  - Satır: tip ikonu + başlık + göreli zaman + süre + durum (yeşil temiz / kırmızı N
 *    tehdit / gri hata). Dokununca satir altinda detay genisler (kesin zaman, tur +
 *    tetikleyici, bayt, taranan/işaretli/önbellek, tehditler, işaretli uygulamalar,
 *    motor sayaçlari, uyarilar).
 *  - Üst bar: geri, paylaş (ACTION_SEND metin raporu — metin [buildReport] ile kurulur),
 *    temizle (onay diyalogu).
 *  - Yeni activity/nav kütüphanesi yok: ekrani [org.xsecurity.scanner.ui.MainActivity]
 *    showHistory state'iyle ciziyor.
 */
@Composable
fun HistoryScreen(
    entries: List<ScanHistoryEntry>,
    onBack: () -> Unit,
    onShareReport: (report: String) -> Unit,
    onClearHistory: () -> Unit
) {
    var filter by remember { mutableStateOf<ScanHistoryType?>(null) }
    var expandedIndex by remember { mutableIntStateOf(-1) }
    var showClearDialog by remember { mutableStateOf(false) }
    val formatter = remember { SimpleDateFormat("dd.MM.yyyy HH:mm:ss", Locale.getDefault()) }

    val filtered = remember(entries, filter) { entries.filter { entry -> filter == null || entry.type == filter } }
    // Paylasim raporu kompozisyon sirasinda kurulur; onClick (composable OLMAYAN
    // lambda) icinde stringResource cagrili buildReport cagrilamamasi icin.
    val report = buildReport(filtered, formatter)

    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            title = { Text(stringResource(R.string.history_clear_title)) },
            text = { Text(stringResource(R.string.history_clear_body, entries.size)) },
            confirmButton = {
                TextButton(onClick = {
                    showClearDialog = false
                    onClearHistory()
                }) { Text(stringResource(R.string.history_clear_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) { Text(stringResource(R.string.action_cancel)) }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .safeDrawingPadding()
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.Filled.KeyboardArrowLeft,
                    contentDescription = stringResource(R.string.history_back),
                    modifier = Modifier.size(28.dp)
                )
            }
            Text(
                text = stringResource(R.string.history_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = {
                if (filtered.isNotEmpty()) onShareReport(report)
            }) {
                Icon(
                    imageVector = Icons.Filled.Share,
                    contentDescription = stringResource(R.string.history_share),
                    modifier = Modifier.size(22.dp)
                )
            }
            IconButton(onClick = { if (entries.isNotEmpty()) showClearDialog = true }) {
                Icon(
                    imageVector = Icons.Filled.Delete,
                    contentDescription = stringResource(R.string.history_clear),
                    modifier = Modifier.size(22.dp)
                )
            }
        }
        Spacer(modifier = Modifier.height(4.dp))
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            FilterChip(
                selected = filter == null,
                onClick = { filter = null; expandedIndex = -1 },
                label = { Text(stringResource(R.string.history_filter_all)) }
            )
            FilterChip(
                selected = filter == ScanHistoryType.DEVICE,
                onClick = { filter = ScanHistoryType.DEVICE; expandedIndex = -1 },
                label = { Text(stringResource(R.string.history_filter_device)) }
            )
            FilterChip(
                selected = filter == ScanHistoryType.FILE,
                onClick = { filter = ScanHistoryType.FILE; expandedIndex = -1 },
                label = { Text(stringResource(R.string.history_filter_file)) }
            )
            FilterChip(
                selected = filter == ScanHistoryType.INSTALL_SHIELD,
                onClick = { filter = ScanHistoryType.INSTALL_SHIELD; expandedIndex = -1 },
                label = { Text(stringResource(R.string.history_filter_install)) }
            )
            FilterChip(
                selected = filter == ScanHistoryType.REALTIME,
                onClick = { filter = ScanHistoryType.REALTIME; expandedIndex = -1 },
                label = { Text(stringResource(R.string.history_filter_download)) }
            )
        }
        Spacer(modifier = Modifier.height(12.dp))
        if (filtered.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Filled.List,
                        contentDescription = null,
                        modifier = Modifier.size(40.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = stringResource(R.string.history_empty),
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.history_empty_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                filtered.forEachIndexed { index, entry ->
                    HistoryRow(
                        entry = entry,
                        expanded = index == expandedIndex,
                        onToggle = { expandedIndex = if (expandedIndex == index) -1 else index },
                        formatter = formatter
                    )
                }
            }
        }
    }
}

/** Tip + etiket cifti; [DashboardScreen]'in kompakt kartinda da ayni ikonu kullanir. */
@Composable
internal fun historyTypeBadge(type: ScanHistoryType): Pair<ImageVector, String> = when (type) {
    ScanHistoryType.DEVICE -> Icons.Filled.Star to stringResource(R.string.history_type_device)
    ScanHistoryType.FILE -> Icons.Filled.List to stringResource(R.string.history_type_file)
    ScanHistoryType.INSTALL_SHIELD -> Icons.Filled.Lock to stringResource(R.string.history_type_install)
    ScanHistoryType.REALTIME -> Icons.Filled.Notifications to stringResource(R.string.history_type_download)
}

@Composable
private fun HistoryRow(
    entry: ScanHistoryEntry,
    expanded: Boolean,
    onToggle: () -> Unit,
    formatter: SimpleDateFormat
) {
    val (icon, typeLabel) = historyTypeBadge(entry.type)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = icon,
                    contentDescription = typeLabel,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    Text(
                        text = entry.title,
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "${relativeLabel(entry.timestamp, formatter)} · ${stringResource(R.string.duration_ms, entry.durationMillis)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                HistoryStatusBadge(entry)
            }
            if (expanded) {
                HistoryDetail(entry = entry, formatter = formatter)
            }
        }
    }
}

@Composable
private fun HistoryStatusBadge(entry: ScanHistoryEntry) {
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
private fun HistoryDetail(entry: ScanHistoryEntry, formatter: SimpleDateFormat) {
    val (_, typeLabel) = historyTypeBadge(entry.type)
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        InfoRow(label = stringResource(R.string.history_detail_time), value = formatter.format(Date(entry.timestamp)))
        InfoRow(
            label = stringResource(R.string.history_detail_type),
            value = "$typeLabel · ${triggerLabel(entry.trigger)}"
        )
        if (entry.appsScanned > 0) {
            Text(
                text = stringResource(
                    R.string.history_detail_apps,
                    entry.appsScanned,
                    entry.appsFlagged,
                    entry.appsCached
                ),
                style = MaterialTheme.typography.bodyMedium
            )
        }
        if (entry.bytesScanned > 0L) {
            InfoRow(
                label = stringResource(R.string.history_detail_bytes),
                value = formatBytes(entry.bytesScanned)
            )
        }
        if (entry.threats.isNotEmpty()) {
            Text(
                text = stringResource(R.string.history_threats_title),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.error,
                fontWeight = FontWeight.SemiBold
            )
            entry.threats.forEach { threat ->
                val detail = threat.detail?.let { " · $it" } ?: ""
                Text(
                    text = "• ${threat.engine} · ${threat.name}$detail",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
        if (entry.flaggedApps.isNotEmpty()) {
            Text(
                text = stringResource(R.string.history_flagged_apps),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold
            )
            entry.flaggedApps.forEach { app ->
                Text(
                    text = "${app.label} (${app.packageName})",
                    style = MaterialTheme.typography.bodySmall
                )
                if (app.threatNames.isNotEmpty()) {
                    Text(
                        text = app.threatNames.joinToString(", "),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        if (entry.engineCounters.isNotEmpty()) {
            Text(
                text = stringResource(R.string.history_engine_counters),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = stringResource(
                    R.string.history_counters_line,
                    entry.engineCounters[COUNTER_YARA_RULES] ?: 0,
                    entry.engineCounters[COUNTER_YARA_PATTERNS] ?: 0,
                    entry.engineCounters[COUNTER_CLAM_SIGNATURES] ?: 0,
                    entry.engineCounters[COUNTER_HASH_SIGNATURES] ?: 0
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (entry.warnings.isNotEmpty()) {
            Text(
                text = stringResource(R.string.history_warnings),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold
            )
            entry.warnings.take(MAX_DETAIL_WARNINGS).forEach { warning ->
                Text(
                    text = "• $warning",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
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
            modifier = Modifier.weight(1f, fill = false)
        )
    }
}

@Composable
private fun triggerLabel(trigger: String): String = when (trigger) {
    TRIGGER_MANUAL -> stringResource(R.string.history_trigger_manual)
    TRIGGER_FILE_PICKER -> stringResource(R.string.history_trigger_file_picker)
    TRIGGER_DOWNLOAD_WATCH -> stringResource(R.string.history_trigger_download_watch)
    TRIGGER_INSTALL_SHIELD -> stringResource(R.string.history_trigger_install_shield)
    else -> trigger
}

// internal: DashboardScreen'in kompakt gecmis kartinda da kullanilir.
@Composable
internal fun relativeLabel(timestamp: Long, formatter: SimpleDateFormat): String {
    val dayFormatter = remember { SimpleDateFormat("dd.MM.yyyy", Locale.getDefault()) }
    val diff = System.currentTimeMillis() - timestamp
    return when {
        diff < 0L -> formatter.format(Date(timestamp))
        diff < 60_000L -> stringResource(R.string.history_now)
        diff < 3_600_000L -> stringResource(R.string.history_minutes_ago, (diff / 60_000L).toInt())
        diff < 86_400_000L -> stringResource(R.string.history_hours_ago, (diff / 3_600_000L).toInt())
        diff < 7L * 86_400_000L -> stringResource(R.string.history_days_ago, (diff / 86_400_000L).toInt())
        else -> dayFormatter.format(Date(timestamp))
    }
}

/** Paylasim icin sade metin raporu (filtrelenmis liste, en yeni oncede). */
@Composable
private fun buildReport(entries: List<ScanHistoryEntry>, formatter: SimpleDateFormat): String {
    val lines = entries.take(MAX_REPORT_LINES).map { entry ->
        val (_, typeLabel) = historyTypeBadge(entry.type)
        val statusLabel = when {
            entry.isThreats -> stringResource(R.string.history_threats_count, entry.threatCount)
            entry.isFailed -> stringResource(R.string.history_failed)
            else -> stringResource(R.string.history_clean)
        }
        "${formatter.format(Date(entry.timestamp))} · $typeLabel: ${entry.title} · $statusLabel · ${stringResource(R.string.duration_ms, entry.durationMillis)}"
    }
    return buildString {
        appendLine(stringResource(R.string.history_share_subject))
        appendLine()
        lines.forEach { appendLine(it) }
        if (entries.size > MAX_REPORT_LINES) {
            appendLine(stringResource(R.string.history_report_more, entries.size - MAX_REPORT_LINES))
        }
    }
}

private const val MAX_DETAIL_WARNINGS = 6
private const val MAX_REPORT_LINES = 20
