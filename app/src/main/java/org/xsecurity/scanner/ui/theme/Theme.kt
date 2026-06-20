package org.xsecurity.scanner.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

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
    background = Color(0xFFFEFCFF),
    onBackground = Color(0xFF1A1B1F),
    surface = Color(0xFFFEFCFF),
    onSurface = Color(0xFF1A1B1F),
    surfaceVariant = Color(0xFFDDE1E7),
    onSurfaceVariant = Color(0xFF49454E),
    outline = Color(0xFF79747E),
    outlineVariant = Color(0xFFC4C7C5),
    scrim = Color(0xFF000000),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFA8CBEE),
    onPrimary = Color(0xFF003350),
    primaryContainer = Color(0xFF004B73),
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
    onBackground = Color(0xFFE6E1E6),
    surface = Color(0xFF1A1B1F),
    onSurface = Color(0xFFE6E1E6),
    surfaceVariant = Color(0xFF49454E),
    onSurfaceVariant = Color(0xFFC4C7C5),
    outline = Color(0xFF8F9297),
    outlineVariant = Color(0xFF49454E),
    scrim = Color(0xFF000000),
)

@Composable
fun XSecurityTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.primary.toArgb()
            WindowCompat.getInsetsController(window, view)?.isAppearanceLightStatusBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = XSecurityTypography,
        content = content
    )
}
