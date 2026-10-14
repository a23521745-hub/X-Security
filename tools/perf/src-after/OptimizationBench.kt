package perf

import org.xsecurity.scanner.autopilot.SystemPackageCache
import org.xsecurity.scanner.core.ProgressCoalescer

/**
 * Measurements of the two hotfix mechanisms, executed against the **production** classes
 * (`SystemPackageCache`, `ProgressCoalescer`) — not against a copy of their logic.
 *
 * Compiled only when those sources exist (i.e. on the fixed tree), so the baseline run stays
 * honest: it prints the *mechanism model* (what the old code did per render / per scanned app)
 * and this file adds what the shipped classes actually cost.
 */
object OptimizationBench {

    private const val ROWS = 400
    private const val RENDERS = 30

    /** Baseline mechanism: one PackageManager query per row, on every recomposition of the list. */
    fun baselineLookupsPerScreen(rows: Int = ROWS, renders: Int = RENDERS): Int = rows * renders

    fun report() {
        println("== optimization mechanisms (production classes, JVM) ==")

        // --- package safelist ---------------------------------------------------------------
        var binderCalls = 0
        val cache = SystemPackageCache { packageName ->
            binderCalls++
            packageName.count { it == '.' } >= 2 && packageName.startsWith("com.android")
        }
        val rows = (0 until ROWS).map { index ->
            if (index % 3 == 0) "com.android.system.$index" else "com.example.app$index"
        }
        val startedAt = System.nanoTime()
        repeat(RENDERS) { rows.forEach { cache.isSystem(it) } }
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000.0
        val stats = cache.stats()
        val baseline = baselineLookupsPerScreen()
        println("  quarantine list: $ROWS rows x $RENDERS recompositions")
        println("    baseline PackageManager queries : $baseline")
        println("    after    PackageManager queries : ${stats.lookups} (cache hits ${stats.hits}, entries ${stats.entries})")
        println("    reduction                       : ${"%.1f".format(baseline.toDouble() / stats.lookups.coerceAtLeast(1))}x")
        println("    cache overhead for $ROWS x $RENDERS answers: ${"%.2f".format(elapsedMs)} ms total (JVM, no binder)")

        // --- progress publication ------------------------------------------------------------
        var publishes = 0
        var now = 0L
        val clockGate = ProgressCoalescer(minPercentStep = 5, minIntervalMillis = 500, clock = { now })
        for (done in 1..ROWS) {
            now += 200
            if (clockGate.shouldPublish(done, ROWS)) publishes++
        }
        println("  400-app scan progress publications")
        println("    baseline (one per app)          : $ROWS")
        println("    after    (5% step + 500 ms floor): $publishes")
        println("    duplicate final publish           : ${clockGate.shouldPublish(ROWS, ROWS)} (false = 100% posted exactly once)")
        println("    total publishes including start   : ${publishes + 1}")

        // --- decision identity of the pure classes (sanity, not a benchmark) -----------------
        println(
            "  sanity: blank package is fail-safe=${SystemPackageCache { false }.isSystem("")}, " +
                "first publish=${ProgressCoalescer().shouldPublish(0, 10)}"
        )
    }
}
