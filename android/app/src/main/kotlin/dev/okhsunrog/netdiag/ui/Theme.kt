package dev.okhsunrog.netdiag.ui

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
import androidx.compose.ui.text.font.FontFamily
import dev.okhsunrog.netdiag.proto.CheckStatus
import dev.okhsunrog.netdiag.proto.EventSeverity
import dev.okhsunrog.netdiag.proto.FindingSeverity

/**
 * Status colours.
 *
 * Deliberately not taken from the Material scheme: pass/fail/warn has to read
 * the same way in light and dark, and it must not shift if the device's
 * dynamic colour changes. Each pair is checked for contrast against its own
 * surface rather than relying on the theme's defaults.
 */
object StatusColors {
    val passLight = Color(0xFF1B5E20)
    val passDark = Color(0xFF81C784)
    val failLight = Color(0xFFB3261E)
    val failDark = Color(0xFFEF9A9A)
    val warnLight = Color(0xFF8A5100)
    val warnDark = Color(0xFFFFB74D)
    val infoLight = Color(0xFF1A4D7A)
    val infoDark = Color(0xFF90CAF9)
    val skipLight = Color(0xFF5F6368)
    val skipDark = Color(0xFF9AA0A6)
}

@Composable
fun statusColor(status: CheckStatus): Color {
    val dark = isSystemInDarkTheme()
    return when (status) {
        CheckStatus.CHECK_STATUS_PASS ->
            if (dark) StatusColors.passDark else StatusColors.passLight
        CheckStatus.CHECK_STATUS_FAIL ->
            if (dark) StatusColors.failDark else StatusColors.failLight
        CheckStatus.CHECK_STATUS_WARN ->
            if (dark) StatusColors.warnDark else StatusColors.warnLight
        CheckStatus.CHECK_STATUS_INFO ->
            if (dark) StatusColors.infoDark else StatusColors.infoLight
        else -> if (dark) StatusColors.skipDark else StatusColors.skipLight
    }
}

@Composable
fun severityColor(severity: FindingSeverity): Color {
    val dark = isSystemInDarkTheme()
    return when (severity) {
        FindingSeverity.FINDING_SEVERITY_CRITICAL,
        FindingSeverity.FINDING_SEVERITY_HIGH,
        -> if (dark) StatusColors.failDark else StatusColors.failLight
        FindingSeverity.FINDING_SEVERITY_MEDIUM ->
            if (dark) StatusColors.warnDark else StatusColors.warnLight
        FindingSeverity.FINDING_SEVERITY_LOW ->
            if (dark) StatusColors.infoDark else StatusColors.infoLight
        else -> if (dark) StatusColors.skipDark else StatusColors.skipLight
    }
}

@Composable
fun eventSeverityColor(severity: EventSeverity): Color {
    val dark = isSystemInDarkTheme()
    return when (severity) {
        EventSeverity.EVENT_SEVERITY_WARNING ->
            if (dark) StatusColors.failDark else StatusColors.failLight
        EventSeverity.EVENT_SEVERITY_NOTICE ->
            if (dark) StatusColors.warnDark else StatusColors.warnLight
        EventSeverity.EVENT_SEVERITY_INFO ->
            if (dark) StatusColors.infoDark else StatusColors.infoLight
        else -> if (dark) StatusColors.skipDark else StatusColors.skipLight
    }
}

/**
 * Monospace is not decoration here. Addresses, routing rules and socket tuples
 * are scanned column-wise and compared character by character, and a
 * proportional font makes `10.1.1.1` and `10.11.1.1` hard to tell apart.
 */
val MonoFamily = FontFamily.Monospace

private val LightScheme = lightColorScheme()
private val DarkScheme = darkColorScheme()

@Composable
fun NetDiagTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkScheme
        else -> LightScheme
    }

    MaterialTheme(
        colorScheme = scheme,
        content = content,
    )
}
