package org.xsecurity.scanner.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.xsecurity.scanner.R
import org.xsecurity.scanner.ota.OtaState
import org.xsecurity.scanner.ota.OtaStatus

/**
 * Uygulama içi guncelleme karti.
 *
 * Guvenlik durusu: guncelleme kontrolu, indirme ve kurulumun tamami kullanicinin
 * acik eylemiyle baslar. Indirilen paket kurulmadan once RSA imzasi + SHA-256 ile
 * dogrulanir; "Kur" yalnizca sistemin paket kurulum ekranini acar (sessiz kurulum yok).
 */
@Composable
fun OtaUpdateCard(
    state: OtaState,
    installedVersionCode: Long,
    onCheck: () -> Unit,
    onDownload: () -> Unit,
    onInstall: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
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
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    modifier = Modifier.padding(end = 8.dp)
                )
                Text(
                    text = stringResource(R.string.ota_card_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            Text(
                text = stringResource(R.string.ota_installed_version, installedVersionCode),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Body(state)

            Actions(
                state = state,
                onCheck = onCheck,
                onDownload = onDownload,
                onInstall = onInstall
            )
        }
    }
}

@Composable
private fun Body(state: OtaState) {
    val info = state.available
    val text: String = when (state.status) {
        OtaStatus.CHECKING -> stringResource(R.string.ota_checking)
        OtaStatus.UP_TO_DATE -> stringResource(R.string.ota_up_to_date)
        OtaStatus.DOWNLOADING ->
            stringResource(R.string.ota_downloading, (state.progress * 100f).toInt().coerceIn(0, 100))
        OtaStatus.UPDATE_AVAILABLE, OtaStatus.READY_TO_INSTALL ->
            if (info != null) {
                stringResource(R.string.ota_update_available, info.versionName, info.versionCode)
            } else {
                stringResource(R.string.ota_idle_hint)
            }
        OtaStatus.ERROR -> stringResource(R.string.ota_error, state.message ?: "")
        OtaStatus.NOT_CONFIGURED -> stringResource(R.string.ota_not_configured)
        OtaStatus.IDLE -> stringResource(R.string.ota_idle_hint)
    }
    Text(text = text, style = MaterialTheme.typography.bodyMedium)

    if (state.status == OtaStatus.READY_TO_INSTALL && !info?.releaseNotes.isNullOrBlank()) {
        Text(
            text = stringResource(R.string.ota_release_notes, info?.releaseNotes.orEmpty()),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }

    if (state.status == OtaStatus.DOWNLOADING) {
        LinearProgressIndicator(
            progress = { state.progress.coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun Actions(
    state: OtaState,
    onCheck: () -> Unit,
    onDownload: () -> Unit,
    onInstall: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        when (state.status) {
            OtaStatus.UPDATE_AVAILABLE -> {
                Button(onClick = onDownload) {
                    Icon(imageVector = Icons.Filled.Download, contentDescription = null, modifier = Modifier.width(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.ota_download))
                }
            }
            OtaStatus.READY_TO_INSTALL -> {
                Button(onClick = onInstall) {
                    Icon(imageVector = Icons.Filled.Check, contentDescription = null, modifier = Modifier.width(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.ota_install))
                }
            }
            else -> {
                OutlinedButton(onClick = onCheck, enabled = !state.isBusy) {
                    Icon(imageVector = Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.width(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.ota_check))
                }
            }
        }
    }
}
