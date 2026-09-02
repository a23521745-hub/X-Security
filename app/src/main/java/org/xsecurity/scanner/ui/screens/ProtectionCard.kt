package org.xsecurity.scanner.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.device.ProtectionMode
import org.xsecurity.scanner.device.ProtectionState

/**
 * Koruma modu karti: Her zaman acik / Sadece kurulum ani / Kapali.
 * Her secenegin ne yaptigi (ve neyi yapmadigi) acikca yazilir.
 */
@Composable
fun ProtectionCard(
    state: ProtectionState,
    onModeChange: (ProtectionMode) -> Unit,
    onQuietChange: (Boolean) -> Unit,
    /** "Her zaman acik" icin depolama izni var mi (yoksa uyari satiri + izin dugmesi). */
    storageGranted: Boolean,
    serviceRunning: Boolean,
    onRequestStorage: () -> Unit
) {
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
            Text(
                text = stringResource(R.string.protection_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = stringResource(R.string.protection_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            ModeRow(
                selected = state.mode == ProtectionMode.ALWAYS,
                title = stringResource(R.string.protection_mode_always),
                description = stringResource(R.string.protection_mode_always_desc),
                onClick = { onModeChange(ProtectionMode.ALWAYS) }
            )
            if (state.mode == ProtectionMode.ALWAYS) {
                if (!storageGranted) {
                    Text(
                        text = stringResource(R.string.protection_storage_missing),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable(onClick = onRequestStorage)
                            .padding(start = 12.dp, top = 2.dp, bottom = 2.dp)
                    )
                } else {
                    Text(
                        text = stringResource(
                            if (serviceRunning) R.string.protection_status_running else R.string.protection_status_waiting
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 12.dp)
                    )
                }
            }
            ModeRow(
                selected = state.mode == ProtectionMode.INSTALL_ONLY,
                title = stringResource(R.string.protection_mode_install_only),
                description = stringResource(R.string.protection_mode_install_only_desc),
                onClick = { onModeChange(ProtectionMode.INSTALL_ONLY) }
            )
            ModeRow(
                selected = state.mode == ProtectionMode.OFF,
                title = stringResource(R.string.protection_mode_off),
                description = stringResource(R.string.protection_mode_off_desc),
                onClick = { onModeChange(ProtectionMode.OFF) }
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.protection_quiet_clean),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f)
                )
                Switch(
                    checked = state.quietWhenClean,
                    onCheckedChange = onQuietChange,
                    enabled = state.mode != ProtectionMode.OFF
                )
            }
        }
    }
}

@Composable
private fun ModeRow(selected: Boolean, title: String, description: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Column(modifier = Modifier.padding(start = 4.dp, top = 12.dp)) {
            Text(text = title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
