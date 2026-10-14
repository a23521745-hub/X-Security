package org.xsecurity.scanner.ui

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import org.xsecurity.scanner.autopilot.SystemPackageCache
import org.xsecurity.scanner.autopilot.SystemPackageSafelist
import org.xsecurity.scanner.perf.PerfProbe

/**
 * Remember-keyed [SystemPackageCache] for list surfaces (hoisted out of per-row composition).
 *
 * The cache lives as long as the composition that asked for it; it is invalidated by the
 * `ACTION_PACKAGE_ADDED` / `ACTION_PACKAGE_REMOVED` / `ACTION_PACKAGE_CHANGED` broadcasts
 * (with the `package:` data scheme, so only real package events arrive). A broadcast without a
 * usable package name clears the whole cache — never trust a partially-known invalidation.
 *
 * Nothing about the decision changed: the answer still comes from [SystemPackageSafelist]
 * (fail-safe), only the number of PackageManager binder calls per recomposition drops from
 * one-per-row to one-per-package-per-process (plus one refresh per package event).
 */
@Composable
fun rememberSystemPackageCache(): SystemPackageCache {
    val context = LocalContext.current
    val cache = remember(context) {
        SystemPackageCache { packageName -> SystemPackageSafelist.isSystemPackage(context, packageName) }
    }

    DisposableEffect(context, cache) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(receiverContext: Context?, intent: Intent?) {
                val changed = intent?.data?.schemeSpecificPart
                cache.invalidate(changed?.takeIf { it.isNotBlank() })
                PerfProbe.logSafelistCache(cache.stats())
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_CHANGED)
            addDataScheme("package")
        }
        val registered = runCatching {
            // Sistem yayini: RECEIVER_EXPORTED (API 33+ zorunlu bayrak; Compat eskiyi yonetir) —
            // depodaki InstallShieldReceiver ile ayni desen.
            ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_EXPORTED)
        }.isSuccess
        onDispose {
            if (registered) runCatching { context.unregisterReceiver(receiver) }
        }
    }

    return cache
}
