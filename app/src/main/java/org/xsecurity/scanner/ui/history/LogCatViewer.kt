package org.xsecurity.scanner.ui.history

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.xsecurity.scanner.R

/**
 * "Gelişmiş (Canlı LogCat)" sekmesi: terminal benzeri canlı log görünümü.
 *
 *  - Koyu zemin + monospace yazı tipi, seviyeye göre renklendirme.
 *  - Otomatik kaydırma anahtarı, duraklat/sürdür düğmeleri, filtre alanı.
 *  - Yaşam döngüsü: sekmeye girince [LogCatReaderRepository.start], çıkınca
 *    `DisposableEffect.onDispose` ile [LogCatReaderRepository.stop]
 *    (projedeki ViewModel'siz mimaride `onCleared` eşdeğeri) — logcat süreci
 *    (`Process.destroy()`) sızdırmaz. Duraklatma da süreci öldürür (pil).
 */
@Composable
fun LogCatViewer(modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    val repository = remember { LogCatReaderRepository(scope) }
    val entries by repository.entries.collectAsState()
    val error by repository.error.collectAsState()

    var paused by remember { mutableStateOf(false) }
    var autoScroll by remember { mutableStateOf(true) }
    var filter by remember { mutableStateOf("") }

    // Sekme açıkken oku; sekmeyi terk edince (veya duraklatınca) süreci öldür.
    DisposableEffect(repository, paused) {
        if (!paused) repository.start()
        onDispose { repository.stop() }
    }

    val visible = remember(entries, filter) {
        if (filter.isBlank()) {
            entries
        } else {
            entries.filter { entry ->
                entry.tag.contains(filter, ignoreCase = true) ||
                    entry.message.contains(filter, ignoreCase = true)
            }
        }
    }
    val listState = rememberLazyListState()
    LaunchedEffect(visible.size, autoScroll, paused) {
        if (autoScroll && !paused && visible.isNotEmpty()) {
            listState.scrollToItem(visible.lastIndex)
        }
    }

    Column(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .background(
                        if (paused) LogAmber else LogGreen,
                        CircleShape
                    )
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = stringResource(if (paused) R.string.logcat_paused else R.string.logcat_live),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.logcat_lines, visible.size),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.weight(1f))
            Text(
                text = stringResource(R.string.logcat_autoscroll),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.width(4.dp))
            Switch(checked = autoScroll, onCheckedChange = { autoScroll = it })
        }

        OutlinedTextField(
            value = filter,
            onValueChange = { filter = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text(stringResource(R.string.logcat_filter_hint)) },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
        )

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { paused = !paused }) {
                Text(stringResource(if (paused) R.string.logcat_resume else R.string.logcat_pause))
            }
            OutlinedButton(onClick = { repository.clear() }) {
                Text(stringResource(R.string.logcat_clear))
            }
        }

        error?.let { message ->
            Text(
                text = stringResource(R.string.logcat_error, message),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }

        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(TerminalBackground, RoundedCornerShape(12.dp))
                .padding(8.dp)
        ) {
            if (visible.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        text = stringResource(R.string.logcat_empty),
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = TerminalDim,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            } else {
                SelectionContainer {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(2.dp)
                    ) {
                        // Özel anahtar yok: aynı milisaniyedeki özdeş satırlar anahtar
                        // çakışması çıkarırdı; terminal akışı için sıra anahtarı yeterli.
                        items(visible) { entry ->
                            LogLine(entry = entry)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LogLine(entry: LogEntry) {
    val text = remember(entry) {
        buildAnnotatedString {
            if (entry.timestamp.isNotEmpty()) {
                withStyle(SpanStyle(color = TerminalDim)) { append(entry.timestamp) }
                append(" ")
            }
            withStyle(SpanStyle(color = levelColor(entry.level), fontWeight = FontWeight.Bold)) {
                append(entry.level.toString())
            }
            append(" ")
            withStyle(SpanStyle(color = LogTag)) { append(entry.tag.ifEmpty { "?" }) }
            append(": ")
            withStyle(SpanStyle(color = TerminalForeground)) { append(entry.message) }
        }
    }
    Text(
        text = text,
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        lineHeight = 14.sp,
        softWrap = true
    )
}

private fun levelColor(level: Char): Color = when (level) {
    'V' -> LogGray
    'D' -> LogBlue
    'I' -> LogGreen
    'W' -> LogAmber
    'E' -> LogRed
    else -> LogPurple
}

private val TerminalBackground = Color(0xFF0B0F14)
private val TerminalForeground = Color(0xFFE6E6E6)
private val TerminalDim = Color(0xFF8B949E)
private val LogTag = Color(0xFF79C0FF)
private val LogGray = Color(0xFF9E9E9E)
private val LogBlue = Color(0xFF64B5F6)
private val LogGreen = Color(0xFF81C784)
private val LogAmber = Color(0xFFFFB74D)
private val LogRed = Color(0xFFE57373)
private val LogPurple = Color(0xFFCE93D8)
