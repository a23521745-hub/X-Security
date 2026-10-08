package org.xsecurity.scanner.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowLeft
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.privacy.PrivacyItem
import org.xsecurity.scanner.privacy.PrivacyPhase
import org.xsecurity.scanner.privacy.PrivacyRisk
import org.xsecurity.scanner.privacy.PrivacyState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Dashboard giris karti: ozet + dokununca ekran (HistoryCard deseni).
 */
@Composable
fun PrivacyCard(state: PrivacyState, onOpen: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Lock,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.privacy_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            val summary = when {
                state.neverScanned -> stringResource(R.string.privacy_card_unknown)
                state.items.isEmpty() -> stringResource(R.string.privacy_card_empty)
                else -> stringResource(R.string.privacy_card_summary, state.items.size)
            }
            Text(
                text = summary,
                style = MaterialTheme.typography.bodyMedium,
                color = if (state.items.isNotEmpty()) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                }
            )
            Text(
                text = stringResource(R.string.privacy_card_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Gizlilik Danismani ekrani: hassas izni VERILMIS uygulamalar, risk rozetiyle
 * sirali. Kaldirma sistem onay ekranina gider (sessiz kaldirma yok).
 * Yeni activity/nav kutuphanesi yok (HistoryScreen deseni).
 */
@Composable
fun PrivacyAdvisorScreen(
    state: PrivacyState,
    onBack: () -> Unit,
    onRescan: () -> Unit,
    onUninstall: (packageName: String) -> Unit
) {
    val formatter = remember { SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()) }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.KeyboardArrowLeft,
                    contentDescription = stringResource(R.string.history_back),
                    modifier = Modifier.size(28.dp)
                )
            }
            Text(
                text = stringResource(R.string.privacy_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = onRescan, enabled = state.phase != PrivacyPhase.SCANNING) {
                Icon(
                    imageVector = Icons.Filled.Refresh,
                    contentDescription = stringResource(R.string.privacy_rescan),
                    modifier = Modifier.size(22.dp)
                )
            }
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.privacy_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(4.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = stringResource(R.string.privacy_count, state.items.size),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = if (state.scannedAt > 0L) {
                    stringResource(
                        R.string.privacy_last_checked,
                        formatter.format(Date(state.scannedAt))
                    )
                } else {
                    stringResource(R.string.value_none)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.height(12.dp))
        when {
            state.phase == PrivacyPhase.SCANNING -> {
                Text(
                    text = stringResource(R.string.privacy_scanning),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            state.items.isEmpty() -> {
                Text(
                    text = stringResource(R.string.privacy_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            else -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    state.items.forEach { item ->
                        PrivacyRow(item = item, onUninstall = onUninstall)
                    }
                }
            }
        }
    }
}

@Composable
private fun PrivacyRow(item: PrivacyItem, onUninstall: (packageName: String) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = item.label.ifBlank { item.packageName },
                        style = MaterialTheme.typography.titleSmall
                    )
                    val packageLine = if (item.isSystem) {
                        "${item.packageName} · ${stringResource(R.string.privacy_system_app)}"
                    } else {
                        item.packageName
                    }
                    Text(
                        text = packageLine,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                RiskBadge(level = item.level)
            }
            // Etiketler composable baglamda onceden cozülür: joinToString
            // inline degildir, lambdasi icinden @Composable cagrilamaz.
            val groupNames = mapOf(
                PrivacyRisk.Group.CAMERA to stringResource(R.string.privacy_group_camera),
                PrivacyRisk.Group.MICROPHONE to stringResource(R.string.privacy_group_microphone),
                PrivacyRisk.Group.LOCATION to stringResource(R.string.privacy_group_location),
                PrivacyRisk.Group.SMS to stringResource(R.string.privacy_group_sms),
                PrivacyRisk.Group.CONTACTS to stringResource(R.string.privacy_group_contacts)
            )
            Text(
                text = item.groups.sortedBy { it.ordinal }.joinToString(" · ") { groupNames.getValue(it) },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            // Sistem uygulamalari da listelenir; kaldirma karari sistemindir
            // (devre disi birakma/kaldirma secenegi sistem ekraninda belirir).
            TextButton(
                onClick = { onUninstall(item.packageName) },
                modifier = Modifier.align(Alignment.End)
            ) {
                Text(stringResource(R.string.action_uninstall))
            }
        }
    }
}

@Composable
private fun RiskBadge(level: PrivacyRisk.Level) {
    val (label, color) = when (level) {
        PrivacyRisk.Level.HIGH ->
            stringResource(R.string.privacy_risk_high) to MaterialTheme.colorScheme.error
        PrivacyRisk.Level.MEDIUM ->
            stringResource(R.string.privacy_risk_medium) to MaterialTheme.colorScheme.tertiary
        PrivacyRisk.Level.LOW ->
            stringResource(R.string.privacy_risk_low) to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Text(
        text = label,
        style = MaterialTheme.typography.labelLarge,
        color = color,
        fontWeight = FontWeight.Bold
    )
}
