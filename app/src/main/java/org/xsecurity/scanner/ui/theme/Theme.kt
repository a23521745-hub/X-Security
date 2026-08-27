package org.xsecurity.scanner.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val LightColors = lightColorScheme(
    primary = Color(0xFF006687),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFC7E8FF),
    onPrimaryContainer = Color(0xFF001E30),
    secondary = Color(0xFF516070),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFD4E5F7),
    onSecondaryContainer = Color(0xFF0D1B2A),
    tertiary = Color(0xFF6C5D7F),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFF2DAFF),
    onTertiaryContainer = Color(0xFF251638),
    error = Color(0xFFB3261E),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFF9DEDC),
    onErrorContainer = Color(0xFF410E0B),
    background = Color(0xFFFBFCFF),
    onBackground = Color(0xFF1A1B1F),
    surface = Color(0xFFFBFCFF),
    onSurface = Color(0xFF1A1B1F),
    surfaceVariant = Color(0xFFDDE1E7),
    onSurfaceVariant = Color(0xFF49454E),
    outline = Color(0xFF79747E),
    outlineVariant = Color(0xFFC4C7C5),
    scrim = Color(0xFF000000)
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF8FD0F5),
    onPrimary = Color(0xFF003547),
    primaryContainer = Color(0xFF004C69),
    onPrimaryContainer = Color(0xFFC7E8FF),
    secondary = Color(0xFFB8CADB),
    onSecondary = Color(0xFF223040),
    secondaryContainer = Color(0xFF3A4857),
    onSecondaryContainer = Color(0xFFD4E5F7),
    tertiary = Color(0xFFD6BEE5),
    onTertiary = Color(0xFF3C2B52),
    tertiaryContainer = Color(0xFF54426A),
    onTertiaryContainer = Color(0xFFF2DAFF),
    error = Color(0xFFF2B8B5),
    onError = Color(0xFF601410),
    errorContainer = Color(0xFF8C1D18),
    onErrorContainer = Color(0xFFF9DEDC),
    background = Color(0xFF1A1B1F),
    onBackground = Color(0xFFE3E2E6),
    surface = Color(0xFF1A1B1F),
    onSurface = Color(0xFFE3E2E6),
    surfaceVariant = Color(0xFF43474E),
    onSurfaceVariant = Color(0xFFC4C7C5),
    outline = Color(0xFF8E9199),
    outlineVariant = Color(0xFF43474E),
    scrim = Color(0xFF000000)
)

/**
 * Tema.
 *
 * Onceki surum `SideEffect` icinde `window.statusBarColor = colorScheme.primary` atiyordu:
 *  - API 35'te alanin hicbir etkisi yok (deprecated/no-op),
 *  - onemlisi light temada koyu mavi çubuğa `isAppearanceLightStatusBars = true` ile
 *    KOYU ikon yerlesiyordu (okunmaz kontrast),
 *  - `(view.context as Activity)` cast'i Activity olmayan baglamda cokertebilirdi.
 * Simdi kenar-dan-kenara ve sistem çubuğu stilleri `enableEdgeToEdge()` ile
 * `MainActivity`'de ayaralaniyor; tema yalnizca renk semasini sagliyor.
 */
@Composable
fun XSecurityTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)

        darkTheme -> DarkColors
        else -> LightColors
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = XSecurityTypography,
        content = content
    )
}
