package org.xsecurity.scanner.autopilot

import android.content.Context
import androidx.core.content.edit
import org.json.JSONObject
import org.xsecurity.scanner.core.Digest
import org.xsecurity.scanner.device.InstalledAppsSource
import java.io.File

/**
 * Stores only positive scanner verdict metadata. Launch checks validate package version/update
 * metadata and use the stored hash; they never rescan or re-hash APKs on app launch.
 */
object KnownBadVerdictCache {
    private const val PREFS = "xsec_known_bad_verdicts"
    private const val KEY_PREFIX = "known_bad_"
    private val reasonPattern = Regex("[A-Za-z0-9_]{1,80}")

    /** Called after a scanner result, while AutoPilotRuntime is already on Dispatchers.IO. */
    fun remember(context: Context, packageName: String, signal: SecuritySignal): Boolean {
        if (packageName.isBlank() || signal.provider != SecuritySignal.ProviderId.SCANNER ||
            signal.verdict != SecuritySignal.Verdict.KNOWN_BAD ||
            SystemPackageSafelist.isSystemPackage(context, packageName)
        ) return false

        return try {
            val app = InstalledAppsSource.loadOne(context.applicationContext, packageName) ?: return false
            if (app.isSystem || app.isUpdatedSystem) return false
            val apkPaths = app.apkPaths.sorted()
            if (apkPaths.isEmpty()) return false
            val apkHashes = ArrayList<String>(apkPaths.size)
            for (path in apkPaths) {
                val apk = File(path)
                if (!apk.isFile || !apk.canRead()) return false
                apkHashes += Digest.sha256Hex(apk)
            }
            val contentHash = Digest.sha256Hex(apkHashes.joinToString("\n").toByteArray(Charsets.UTF_8))
            val reason = signal.reasonCode.takeIf(reasonPattern::matches) ?: "scanner_known_bad"
            val entry = CachedKnownBadVerdict(
                packageName = packageName,
                apkSha256 = contentHash,
                versionCode = app.versionCode,
                lastUpdateTime = app.lastUpdateTime,
                reasonCode = reason,
                provider = signal.provider
            )
            preferences(context).edit { putString(key(packageName), encode(entry)) }
            true
        } catch (_: Exception) {
            false
        }
    }

    /** Returns a verdict only for the same installed version; stale/uninstalled entries are removed. */
    fun get(context: Context, packageName: String): CachedKnownBadVerdict? {
        if (packageName.isBlank()) return null
        val prefs = preferences(context)
        val entryKey = key(packageName)
        val raw = prefs.getString(entryKey, null) ?: return null
        val entry = runCatching { decode(raw) }.getOrNull() ?: run {
            prefs.edit { remove(entryKey) }
            return null
        }
        val app = InstalledAppsSource.loadOne(context.applicationContext, packageName)
        if (app == null || app.isSystem || app.isUpdatedSystem ||
            SystemPackageSafelist.isSystemPackage(context, packageName) || !entry.matchesInstalled(app)
        ) {
            prefs.edit { remove(key(packageName)) }
            return null
        }
        return entry
    }

    fun invalidate(context: Context, packageName: String) {
        if (packageName.isNotBlank()) preferences(context).edit { remove(key(packageName)) }
    }

    private fun encode(entry: CachedKnownBadVerdict): String = JSONObject()
        .put("package", entry.packageName)
        .put("sha256", entry.apkSha256)
        .put("versionCode", entry.versionCode)
        .put("lastUpdateTime", entry.lastUpdateTime)
        .put("reason", entry.reasonCode)
        .put("provider", entry.provider.name)
        .toString()

    private fun decode(raw: String): CachedKnownBadVerdict {
        val json = JSONObject(raw)
        val reason = json.getString("reason")
        require(reasonPattern.matches(reason))
        val hash = json.getString("sha256")
        require(hash.matches(Regex("[a-f0-9]{64}")))
        val provider = SecuritySignal.ProviderId.valueOf(json.getString("provider"))
        require(provider == SecuritySignal.ProviderId.SCANNER)
        return CachedKnownBadVerdict(
            packageName = json.getString("package"),
            apkSha256 = hash,
            versionCode = json.getLong("versionCode"),
            lastUpdateTime = json.getLong("lastUpdateTime"),
            reasonCode = reason,
            provider = provider
        )
    }

    private fun preferences(context: Context) = context.applicationContext
        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun key(packageName: String): String = KEY_PREFIX + packageName
}
