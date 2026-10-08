package org.xsecurity.scanner.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.edr.EdrStatusSnapshot

/**
 * Davranissal EDR durum karti: salt-okunur durum + callback deseni
 * ([ProtectionCard] gibi; kart kendisi servis baslatmaz/durdurmaz).
 *
 *  - Davranis izleyici: ALWAYS modunda bekleniyor mu, servis ayakta mi?
 *  - Overlay izleyici: erisilebilirlik servisi acik mi (degilse sistem ayar
 *    dugmesi; uygulama icinden acilamaz — Android zorunlulugu)?
 *  - Son 24 saatteki uyarilar ([EdrStatusSnapshot.alertsLast24h]).
 */
@Composable
fun EdrStatusCard(
    snapshot: EdrStatusSnapshot,
    onOpenAccessibilitySettings: () -> Unit
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
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(
                text = stringResource(R.string.edr_card_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            BehaviorRow(snapshot)
            AccessibilityRow(
                enabled = snapshot.accessibilityEnabled,
                onOpenSettings = onOpenAccessibilitySettings
            )
            AlertsRow(count = snapshot.alertsLast24h)
        }
    }
}

@Composable
private fun BehaviorRow(snapshot: EdrStatusSnapshot) {
    val (icon, text, tint) = when {
        !snapshot.behaviorExpected -> Triple(
            Icons.Filled.Info,
            stringResource(R.string.edr_card_behavior_off),
            MaterialTheme.colorScheme.onSurfaceVariant
        )
        snapshot.behaviorRunning -> Triple(
            Icons.Filled.Check,
            stringResource(R.string.edr_card_behavior_running),
            MaterialTheme.colorScheme.primary
        )
        else -> Triple(
            Icons.Filled.Warning,
            stringResource(R.string.edr_card_behavior_stopped),
            MaterialTheme.colorScheme.error
        )
    }
    StatusLine(icon = icon, text = text, tint = tint)
    if (snapshot.behaviorExpected && !snapshot.detailedWatching) {
        Text(
            text = stringResource(R.string.edr_card_behavior_passive),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 28.dp)
        )
    }
}

@Composable
private fun AccessibilityRow(enabled: Boolean, onOpenSettings: () -> Unit) {
    StatusLine(
        icon = if (enabled) Icons.Filled.Check else Icons.Filled.Info,
        text = stringResource(
            if (enabled) R.string.edr_card_accessibility_on else R.string.edr_card_accessibility_off
        ),
        tint = if (enabled) {
            MaterialTheme.colorScheme.primary
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        }
    )
    if (!enabled) {
        Text(
            text = stringResource(R.string.edr_card_accessibility_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 28.dp)
        )
        OutlinedButton(
            onClick = onOpenSettings,
            modifier = Modifier.padding(start = 28.dp)
        ) {
            Text(stringResource(R.string.edr_card_open_accessibility))
        }
    }
}

@Composable
private fun AlertsRow(count: Int) {
    StatusLine(
        icon = if (count > 0) Icons.Filled.Warning else Icons.Filled.Check,
        text = if (count > 0) {
            stringResource(R.string.edr_card_alerts, count)
        } else {
            stringResource(R.string.edr_card_no_alerts)
        },
        tint = if (count > 0) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        }
    )
}

@Composable
private fun StatusLine(icon: ImageVector, text: String, tint: androidx.compose.ui.graphics.Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(20.dp),
            tint = tint
        )
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = tint,
            modifier = Modifier.padding(start = 8.dp)
        )
    }
}
