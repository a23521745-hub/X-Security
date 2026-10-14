package org.xsecurity.scanner.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Perf hotfix regression lock for the notification/list progress storm.
 *
 * Baseline (measured in the audit): a 400-app device scan republished progress **once per app** —
 * 400 `ScanNotifications.showProgress` posts and 400 full entry-list republishes. The gate must
 * keep the user-visible information (start, ~5% steps, 100%) while dropping the intermediate
 * republishes.
 */
class ProgressCoalescerTest {

    private class FakeClock(var now: Long = 0L) : () -> Long {
        override fun invoke(): Long = now
        fun advance(millis: Long) {
            now += millis
        }
    }

    @Test
    fun `first call always publishes - the user sees progress immediately`() {
        val clock = FakeClock()
        val gate = ProgressCoalescer(minPercentStep = 5, minIntervalMillis = 500, clock = clock)
        assertTrue(gate.shouldPublish(0, 400))
    }

    @Test
    fun `sub-step progress is dropped even when time passes`() {
        val clock = FakeClock()
        val gate = ProgressCoalescer(minPercentStep = 5, minIntervalMillis = 500, clock = clock)
        assertTrue(gate.shouldPublish(0, 400))       // 0%
        clock.advance(5_000)
        assertFalse(gate.shouldPublish(1, 400))      // 0%
        assertFalse(gate.shouldPublish(19, 400))     // 4%
        assertTrue(gate.shouldPublish(20, 400))      // 5%
    }

    @Test
    fun `step reached before the time floor is still dropped`() {
        val clock = FakeClock()
        val gate = ProgressCoalescer(minPercentStep = 5, minIntervalMillis = 500, clock = clock)
        assertTrue(gate.shouldPublish(0, 100))
        gate.markPublished(0, 100)
        assertFalse(gate.shouldPublish(10, 100))     // step ok, 0 ms elapsed
        clock.advance(499)
        assertFalse(gate.shouldPublish(10, 100))
        clock.advance(1)
        assertTrue(gate.shouldPublish(10, 100))
    }

    @Test
    fun `final 100 percent always publishes and only once`() {
        val clock = FakeClock()
        val gate = ProgressCoalescer(minPercentStep = 5, minIntervalMillis = 500, clock = clock)
        assertTrue(gate.shouldPublish(1, 100))       // first
        assertTrue(gate.shouldPublish(100, 100))     // 100% wins over the time floor
        assertFalse(gate.shouldPublish(100, 100))    // no duplicate completion post
    }

    @Test
    fun `a 400 app scan publishes at most ~20 times instead of 400`() {
        val clock = FakeClock()
        val gate = ProgressCoalescer(minPercentStep = 5, minIntervalMillis = 500, clock = clock)
        var publishes = 0
        for (done in 1..400) {
            if (gate.shouldPublish(done, 400)) publishes++
            clock.advance(200) // 400 apps in 80 s
        }
        // 5% steps of 400 apps = 20 boundaries, the first call and the final one included.
        assertTrue("publishes=$publishes", publishes in 19..21)
        assertTrue("baseline was 400", publishes <= 21)
    }

    @Test
    fun `reset starts a new scan with a clean gate`() {
        val clock = FakeClock()
        val gate = ProgressCoalescer(minPercentStep = 5, minIntervalMillis = 500, clock = clock)
        assertTrue(gate.shouldPublish(0, 10))
        assertFalse(gate.shouldPublish(1, 10))
        gate.reset()
        assertTrue(gate.shouldPublish(0, 10))
    }

    @Test
    fun `markPublished records a forced publish so the next step is measured from it`() {
        val clock = FakeClock()
        val gate = ProgressCoalescer(minPercentStep = 5, minIntervalMillis = 500, clock = clock)
        gate.markPublished(50, 100)
        assertFalse(gate.shouldPublish(52, 100))
        clock.advance(500)
        assertTrue(gate.shouldPublish(55, 100))
        assertEquals(500L, clock.now)
    }
}
