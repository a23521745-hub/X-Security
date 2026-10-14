package org.xsecurity.scanner.autopilot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Perf hotfix regression lock: the system-package answer must be resolved **once per package**,
 * not once per row (and once per recomposition) — the PackageManager binder call that caused the
 * Exynos 2400 list jank.
 *
 * Fail-safe semantics are pinned here too: an unclassifiable package is still treated as a system
 * package ("no action taken"), exactly like [SystemPackageSafelist].
 */
class SystemPackageCacheTest {

    @Test
    fun `one lookup per package no matter how many rows ask`() {
        val calls = mutableListOf<String>()
        val cache = SystemPackageCache { packageName ->
            calls += packageName
            packageName == "com.android.systemui"
        }

        repeat(40) {
            assertTrue(cache.isSystem("com.android.systemui"))
            assertFalse(cache.isSystem("com.example.game"))
        }

        // Two distinct packages, 80 questions, exactly two binder calls.
        assertEquals(listOf("com.android.systemui", "com.example.game"), calls)
        val stats = cache.stats()
        assertEquals(2, stats.lookups)
        assertEquals(78, stats.hits)
        assertEquals(2, stats.entries)
    }

    @Test
    fun `invalidation on package events re-classifies only that package`() {
        val calls = mutableListOf<String>()
        var systemFlag = false
        val cache = SystemPackageCache { packageName ->
            calls += packageName
            systemFlag
        }

        assertFalse(cache.isSystem("com.example.app"))
        systemFlag = true
        assertFalse(cache.isSystem("com.example.app")) // still cached: no event yet
        assertEquals(1, calls.size)

        cache.invalidate("com.example.app") // ACTION_PACKAGE_CHANGED / REMOVED / ADDED
        assertTrue(cache.isSystem("com.example.app"))
        assertEquals(2, calls.size)
    }

    @Test
    fun `invalidate without a package name clears every entry`() {
        var calls = 0
        val cache = SystemPackageCache { calls++; false }
        cache.isSystem("a")
        cache.isSystem("b")
        cache.invalidate(null)
        cache.isSystem("a")
        assertEquals(3, calls)
        assertEquals(1, cache.stats().entries)
    }

    @Test
    fun `blank package name is fail-safe and never reaches the lookup`() {
        var calls = 0
        val cache = SystemPackageCache { calls++; false }
        assertTrue(cache.isSystem(null))
        assertTrue(cache.isSystem("   "))
        assertEquals(0, calls)
    }

    @Test
    fun `failing lookup fails closed and is not cached`() {
        var attempts = 0
        val cache = SystemPackageCache {
            attempts++
            throw IllegalStateException("binder died")
        }
        assertTrue(cache.isSystem("com.example.app"))
        assertTrue(cache.isSystem("com.example.app"))
        // A transient failure must be retried, not pinned for the rest of the process.
        assertEquals(2, attempts)
    }

    @Test
    fun `concurrent readers still resolve each package once`() {
        val calls = java.util.concurrent.atomic.AtomicInteger(0)
        val cache = SystemPackageCache { calls.incrementAndGet(); true }
        val threads = (1..8).map {
            Thread { repeat(100) { cache.isSystem("com.example.app") } }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        assertTrue(calls.get() >= 1)
        assertEquals(1, cache.stats().lookups)
        assertTrue(cache.stats().hits >= 799)
    }

    @Test
    fun `hit ratio reflects served-from-memory answers`() {
        val cache = SystemPackageCache { it.startsWith("com.android.") }
        assertTrue(cache.isSystem("com.android.settings"))
        assertTrue(cache.isSystem("com.android.settings"))
        assertFalse(cache.isSystem("com.example.game"))
        assertEquals(2, cache.stats().lookups)
        assertEquals(1, cache.stats().hits)
        assertEquals(1f / 3f, cache.stats().hitRatio, 0.0001f)
    }
}
