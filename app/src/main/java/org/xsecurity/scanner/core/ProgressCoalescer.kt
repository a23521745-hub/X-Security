package org.xsecurity.scanner.core

/**
 * Rate limit for user-visible progress (notification + list republish).
 *
 * WHY (measured offender, not a guess): the device scan published progress once **per scanned
 * app** — both a notification post (`ScanNotifications.showProgress`) and a full list republish
 * (`DeviceScanStore.markProgress`) — so a 400-app scan produced 400 notification updates and 400
 * whole-list recompositions (each carrying up to 400 entries). The single-file scan path already
 * limited itself to 5% steps; this class makes that rule explicit, shared and testable, and adds a
 * time floor so a fast scan cannot outrun the UI either.
 *
 * Semantics (pinned by tests):
 *  - the first call always publishes (the user sees progress immediately);
 *  - later calls publish when the percentage step advanced **and** the time floor elapsed, so the
 *    number of publishes per scan stays around `100 / minPercentStep`;
 *  - the transition to 100% always publishes (never swallowed), a repeat of 100% does not.
 *
 * Pure Kotlin: [clock] is injected, so JVM tests control time exactly.
 */
class ProgressCoalescer(
    private val minPercentStep: Int = 5,
    private val minIntervalMillis: Long = 500L,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {

    private var lastPercent = -1
    private var lastPublishAt = 0L

    /**
     * True when this progress value should be published to the UI / notification.
     *
     * `@Synchronized`: the device scan completes targets on several threads, so the gate is
     * entered concurrently; it must never hand out two publishes for the same step.
     */
    @Synchronized
    fun shouldPublish(done: Int, total: Int): Boolean {
        val percent = percentOf(done, total)
        val now = clock()
        val publish = when {
            lastPercent < 0 -> true
            percent >= 100 && lastPercent < 100 -> true
            percent < lastPercent + minPercentStep -> false
            now - lastPublishAt < minIntervalMillis -> false
            else -> true
        }
        if (publish) {
            lastPercent = percent
            lastPublishAt = now
        }
        return publish
    }

    /** Records a publish that happened outside this gate (a forced start/completion/reset). */
    @Synchronized
    fun markPublished(done: Int, total: Int) {
        lastPercent = percentOf(done, total)
        lastPublishAt = clock()
    }

    /** Forgets history: a new scan starts from a clean gate. */
    @Synchronized
    fun reset() {
        lastPercent = -1
        lastPublishAt = 0L
    }

    private fun percentOf(done: Int, total: Int): Int {
        val safeTotal = total.coerceAtLeast(1)
        val safeDone = done.coerceIn(0, safeTotal)
        return ((safeDone.toLong() * 100L) / safeTotal.toLong()).toInt().coerceIn(0, 100)
    }
}
