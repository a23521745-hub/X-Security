package org.xsecurity.scanner.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.community.CommunityStore
import org.xsecurity.scanner.data.EngineInfo
import org.xsecurity.scanner.definitions.DefinitionsState
import org.xsecurity.scanner.definitions.DefinitionsStatus

/**
 * Imza veritabani (tanim paketi) karti.
 *
 * APK guncellemesinden farki: tanim paketi imzali da olsa **otomatik kurulur**
 * (klasik freshclam davranisi). Kart bunu acikca soyler; dugme yalnizca
 * "simdi kontrol et" ise yarar.
 */
@Composable
fun DefinitionsCard(
    state: DefinitionsState,
    engine: EngineInfo?,
    onCheck: () -> Unit
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
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Lock,
                    contentDescription = null,
                    modifier = Modifier.padding(end = 8.dp)
                )
                Text(
                    text = stringResource(R.string.def_card_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            Text(
                text = stringResource(
                    R.string.def_installed,
                    state.installedDefVersion,
                    engine?.yaraRules ?: 0,
                    engine?.clamSignatures ?: 0,
                    engine?.hashSignatures ?: 0
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Body(state)
            CommunitySection()
            Actions(state, onCheck)
        }
    }
}

@Composable
private fun Body(state: DefinitionsState) {
    val available = state.available
    val text: String = when (state.status) {
        DefinitionsStatus.CHECKING -> stringResource(R.string.def_checking)
        DefinitionsStatus.UP_TO_DATE -> stringResource(R.string.def_up_to_date, state.installedDefVersion)
        DefinitionsStatus.DOWNLOADING ->
            stringResource(R.string.def_downloading, (state.progress * 100f).toInt().coerceIn(0, 100))
        DefinitionsStatus.UPDATE_AVAILABLE ->
            if (available != null) {
                stringResource(R.string.def_update_available, available.defVersion, state.installedDefVersion)
            } else {
                stringResource(R.string.def_idle_hint)
            }
        DefinitionsStatus.ERROR -> stringResource(R.string.def_error, state.message ?: "")
        DefinitionsStatus.NOT_CONFIGURED -> stringResource(R.string.def_not_configured)
        DefinitionsStatus.IDLE -> stringResource(R.string.def_idle_hint)
    }
    Text(text = text, style = MaterialTheme.typography.bodyMedium)

    // Bilgilendirici not: orn. kullanici veritabani korunuyor.
    if (state.status == DefinitionsStatus.UPDATE_AVAILABLE && !state.message.isNullOrBlank()) {
        Text(
            text = state.message.orEmpty(),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }

    if (state.status == DefinitionsStatus.DOWNLOADING) {
        // `progress` degeri dogrudan Float olarak verilir: lambda alan
        // (`progress: () -> Float`) imza yalnizca yeni Material3 surumlerinde var;
        // Float imza hem eski hem yeni surumlerde derlenir.
        LinearProgressIndicator(
            progress = state.progress.coerceIn(0f, 1f),
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun Actions(state: DefinitionsState, onCheck: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        when (state.status) {
            DefinitionsStatus.UPDATE_AVAILABLE -> {
                Button(onClick = onCheck) {
                    Icon(imageVector = Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.width(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.def_update))
                }
            }
            DefinitionsStatus.NOT_CONFIGURED -> {
                OutlinedButton(onClick = onCheck, enabled = false) {
                    Icon(imageVector = Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.width(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.def_check))
                }
            }
            else -> {
                OutlinedButton(onClick = onCheck, enabled = !state.isBusy) {
                    Icon(imageVector = Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.width(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.def_check))
                }
            }
        }
    }
}

@Composable
private fun CommunitySection() {
    val context = LocalContext.current
    val sources by CommunityStore.state.collectAsState()
    if (sources.isEmpty()) return

    Text(
        text = stringResource(R.string.community_title),
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold
    )
    Text(
        text = stringResource(R.string.community_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    for (item in sources) {
        val source = item.source
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = source.label, style = MaterialTheme.typography.bodyMedium)
                val status: String = when {
                    item.error != null -> item.error
                    item.updating -> stringResource(R.string.community_updating)
                    item.updatedAt == 0L -> stringResource(R.string.community_not_installed)
                    item.installedEntries > 0 -> stringResource(
                        R.string.community_entries, item.installedEntries
                    ) + " · " + java.text.DateFormat.getDateInstance(java.text.DateFormat.SHORT)
                        .format(java.util.Date(item.updatedAt))
                    else -> stringResource(R.string.community_rules, item.installedRules) + " · " +
                        java.text.DateFormat.getDateInstance(java.text.DateFormat.SHORT)
                            .format(java.util.Date(item.updatedAt))
                }
                Text(
                    text = status,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (item.error != null) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )
                if (source.license.isNotBlank()) {
                    Text(
                        text = source.license + " · " + source.attribution,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Switch(
                checked = item.enabled,
                onCheckedChange = { checked -> CommunityStore.setEnabled(context, source, checked) }
            )
        }
    }
}
