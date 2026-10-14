package org.xsecurity.scanner.autopilot

/**
 * Memoizing (remember-keyed) holder for the system-package safelist answer.
 *
 * WHY (measured jank offender, not a guess): [SystemPackageSafelist.isSystemPackage] is a
 * PackageManager binder call. Surfaces that render one row per record used to call it **inside**
 * the row composable, i.e. once per row and again on every recomposition of that list — a 400-row
 * quarantine list produced 400 binder round trips per recomposition (and closing/opening the
 * details dialog, a record-set change or a locale/theme change each produced another 400).
 *
 * This class keeps the same **fail-safe** semantics as [SystemPackageSafelist] (unknown/unresolvable
 * package => treated as system => "no action taken") but answers from memory after the first
 * lookup per package. Invalidation is explicit ([invalidate]); the Compose side calls it from a
 * `ACTION_PACKAGE_ADDED` / `ACTION_PACKAGE_REMOVED` / `ACTION_PACKAGE_CHANGED` receiver, so a
 * freshly installed/updated/removed package is re-classified instead of being answered from a
 * stale entry.
 *
 * Pure Kotlin (no Android types) so the cache policy — and its hit/miss accounting — is unit
 * testable and benchmarkable on the JVM.
 *
 * Threading: every mutation is guarded by one lock; the lookup itself runs outside the lock (a
 * binder call must never serialize unrelated readers), and the first answer written wins so two
 * concurrent misses cannot disagree.
 */
class SystemPackageCache(
    /**
     * Resolves the authoritative answer for one package. Must fail **closed** (true = treat as a
     * system package / no action) for anything it cannot classify. Production passes
     * `SystemPackageSafelist::isSystemPackage`, which already fails closed on `RuntimeException`.
     */
    private val lookup: (String) -> Boolean
) {

    /** What the cache did since it was created; used by the perf probe and by tests. */
    data class Stats(val lookups: Int, val hits: Int, val entries: Int) {
        /** Answers served without a binder call, as a fraction of all answers (0..1). */
        val hitRatio: Float get() {
            val total = lookups + hits
            return if (total == 0) 0f else hits.toFloat() / total.toFloat()
        }
    }

    private val lock = Any()
    private val answers = HashMap<String, Boolean>()
    private var lookups = 0
    private var hits = 0

    /**
     * Cached classification for [packageName].
     *
     * A blank name is fail-safe "system" (no lookup, nothing to act on); a lookup that throws is
     * fail-safe "system" as well and is **not** cached, so a transient binder failure cannot pin a
     * package out of the safelist for the rest of the process.
     */
    fun isSystem(packageName: String?): Boolean {
        val key = packageName?.trim().orEmpty()
        if (key.isEmpty()) return true

        synchronized(lock) {
            answers[key]?.let { cached ->
                hits++
                return cached
            }
        }

        val resolved = try {
            lookup(key)
        } catch (_: Throwable) {
            // Fail closed, but do not cache a failure: the next caller retries the lookup.
            return true
        }

        synchronized(lock) {
            val existing = answers[key]
            if (existing != null) {
                hits++
                return existing
            }
            answers[key] = resolved
            lookups++
        }
        return resolved
    }

    /**
     * Drops the entry for [packageName]; `null` clears everything. Called for package
     * add/remove/change broadcasts and after any user-visible action that changes classification
     * (e.g. uninstall confirmation).
     */
    fun invalidate(packageName: String? = null) {
        synchronized(lock) {
            val key = packageName?.trim().orEmpty()
            if (key.isEmpty()) answers.clear() else answers.remove(key)
        }
    }

    fun stats(): Stats = synchronized(lock) { Stats(lookups, hits, answers.size) }
}
