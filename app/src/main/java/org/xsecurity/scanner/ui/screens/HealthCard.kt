package org.xsecurity.scanner.ui.screens

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
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.health.DeviceHealth

/**
 * Dashboard rozeti: cihaz butunluk hukumeti + bulgular. Salt-okunur; hesaplama
 * [org.xsecurity.scanner.health.HealthStore]'dadir.
 */
@Composable
fun HealthCard(snapshot: DeviceHealth.Snapshot) {
    val (label, color, icon) = when (snapshot.verdict) {
        DeviceHealth.Verdict.HEALTHY -> Triple(
            stringResource(R.string.health_healthy),
            MaterialTheme.colorScheme.primary,
            Icons.Filled.Check
        )
        DeviceHealth.Verdict.WARNING -> Triple(
            stringResource(R.string.health_warning),
            MaterialTheme.colorScheme.tertiary,
            Icons.Filled.Warning
        )
        DeviceHealth.Verdict.AT_RISK -> Triple(
            stringResource(R.string.health_at_risk),
            MaterialTheme.colorScheme.error,
            Icons.Filled.Warning
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
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = stringResource(R.string.health_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = color
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelLarge,
                    color = color,
                    fontWeight = FontWeight.Bold
                )
            }
            if (snapshot.findings.isEmpty()) {
                Text(
                    text = stringResource(R.string.health_clean),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                snapshot.findings.forEach { finding ->
                    Text(
                        text = "• ${findingLabel(finding)}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = color
                    )
                }
            }
            Text(
                text = stringResource(R.string.health_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun findingLabel(finding: DeviceHealth.Finding): String = when (finding.id) {
    DeviceHealth.FindingId.ROOT_SU ->
        stringResource(R.string.health_finding_root_su, finding.detail ?: "")
    DeviceHealth.FindingId.TEST_KEYS ->
        stringResource(R.string.health_finding_test_keys)
    DeviceHealth.FindingId.ADB_ENABLED ->
        stringResource(R.string.health_finding_adb)
    else -> finding.id
}
