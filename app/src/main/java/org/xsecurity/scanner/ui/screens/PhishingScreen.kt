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
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
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
import org.xsecurity.scanner.phishing.PhishingBlocklistState
import org.xsecurity.scanner.phishing.PhishingHeuristics
import org.xsecurity.scanner.phishing.PhishingScanner
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Dashboard giris karti: ozet + dokununca ekran (HistoryCard deseni).
 */
@Composable
fun PhishingCard(onOpen: () -> Unit) {
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
                    imageVector = Icons.Filled.Share,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.phishing_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                text = stringResource(R.string.phishing_card_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Baglanti/oltalama ekrani: metin yapistir, tara, sonuclari gor. Blok listesi
 * satiri guncelleme dugmesini de tasir (manuel; arka plan trafigi yok).
 */
@Composable
fun PhishingScreen(
    blocklist: Set<String>,
    blocklistState: PhishingBlocklistState,
    onUpdateList: () -> Unit,
    onBack: () -> Unit
) {
    var input by rememberSaveable { mutableStateOf("") }
    var findings by remember { mutableStateOf<List<PhishingHeuristics.Finding>?>(null) }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
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
                text = stringResource(R.string.phishing_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.phishing_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(12.dp))
        OutlinedTextField(
            value = input,
            onValueChange = { input = it },
            modifier = Modifier
                .fillMaxWidth()
                .height(160.dp),
            placeholder = { Text(stringResource(R.string.phishing_input_hint)) }
        )
        Spacer(modifier = Modifier.height(12.dp))
        Button(onClick = { findings = PhishingScanner.scanText(input, blocklist) }) {
            Text(stringResource(R.string.phishing_scan))
        }
        Spacer(modifier = Modifier.height(12.dp))
        FindingsBlock(findings = findings)
        Spacer(modifier = Modifier.height(12.dp))
        BlocklistRow(state = blocklistState, onUpdateList = onUpdateList)
    }
}

/**
 * Paylasim hedefinden ([PhishingScanActivity]) acilan salt-okunur sonuc ekrani:
 * paylasilan metindeki baglantilar ve hukumleri.
 */
@Composable
fun PhishingShareScreen(
    findings: List<PhishingHeuristics.Finding>,
    onClose: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onClose) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.KeyboardArrowLeft,
                    contentDescription = stringResource(R.string.history_back),
                    modifier = Modifier.size(28.dp)
                )
            }
            Text(
                text = stringResource(R.string.phishing_share_label),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        if (findings.isEmpty()) {
            Text(
                text = stringResource(R.string.phishing_shared_empty),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            FindingsBlock(findings = findings)
        }
    }
}

@Composable
private fun FindingsBlock(findings: List<PhishingHeuristics.Finding>?) {
    if (findings == null) return
    if (findings.isEmpty()) {
        Text(
            text = stringResource(R.string.phishing_no_urls),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            text = stringResource(R.string.phishing_found, findings.size),
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold
        )
        findings.forEach { finding -> FindingRow(finding = finding) }
    }
}

@Composable
private fun FindingRow(finding: PhishingHeuristics.Finding) {
    val (label, color) = when (finding.verdict) {
        PhishingHeuristics.Verdict.MALICIOUS ->
            stringResource(R.string.phishing_verdict_malicious) to MaterialTheme.colorScheme.error
        PhishingHeuristics.Verdict.SUSPICIOUS ->
            stringResource(R.string.phishing_verdict_suspicious) to MaterialTheme.colorScheme.tertiary
        PhishingHeuristics.Verdict.SAFE ->
            stringResource(R.string.phishing_verdict_safe) to MaterialTheme.colorScheme.primary
    }
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
                Icon(
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
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
            Text(text = finding.url, style = MaterialTheme.typography.bodyMedium)
            finding.reasons.forEach { reason ->
                Text(
                    text = "• ${reasonLabel(reason)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun reasonLabel(reason: PhishingHeuristics.Reason): String = when (reason) {
    PhishingHeuristics.Reason.BLOCKLISTED -> stringResource(R.string.phishing_reason_blocklisted)
    PhishingHeuristics.Reason.IP_HOST -> stringResource(R.string.phishing_reason_ip_host)
    PhishingHeuristics.Reason.AT_SIGN -> stringResource(R.string.phishing_reason_at_sign)
    PhishingHeuristics.Reason.PUNYCODE -> stringResource(R.string.phishing_reason_punycode)
    PhishingHeuristics.Reason.SHORTENER -> stringResource(R.string.phishing_reason_shortener)
}

@Composable
private fun BlocklistRow(state: PhishingBlocklistState, onUpdateList: () -> Unit) {
    val formatter = remember { SimpleDateFormat("dd.MM.yyyy", Locale.getDefault()) }
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
            Text(
                text = stringResource(R.string.phishing_blocklist_title),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = stringResource(
                    R.string.phishing_blocklist_status,
                    state.entries,
                    if (state.updatedAt > 0L) {
                        formatter.format(Date(state.updatedAt))
                    } else {
                        stringResource(R.string.value_none)
                    }
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            val error = state.error
            if (error != null) {
                Text(
                    text = stringResource(R.string.phishing_blocklist_error, error),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
            OutlinedButton(onClick = onUpdateList, enabled = !state.updating) {
                Text(
                    stringResource(
                        if (state.updating) {
                            R.string.phishing_blocklist_updating
                        } else {
                            R.string.phishing_blocklist_update
                        }
                    )
                )
            }
        }
    }
}
