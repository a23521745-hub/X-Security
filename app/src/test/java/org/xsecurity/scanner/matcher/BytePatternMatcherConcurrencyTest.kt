package org.xsecurity.scanner.matcher

import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch

/**
 * [BytePatternMatcher] eszamanlilik testleri.
 *
 * Matcher artik salt-okunur paylasilan bir nesne: "bu kalip bu taramada eslesti"
 * bayragi tarama-yerel oldugundan, TEK matcher ornegini N thread ile (farkli
 * desenlerden sorumlu, ayni kalip seti uzerinde) paralel taramak guvenli olmalidir.
 * Onceki paylasilan `consumed` mutasyonu bu testlerde rastgele esleme kayiplari
 * olarak yakalanirdi.
 */
class BytePatternMatcherConcurrencyTest {

    private val threadCount = 8
    private val iterations = 20

    @Test
    fun sharedMatcherFindsEveryPatternUnderParallelScans() {
        // N thread, N farkli desen (farkli igne); hepsi ayni paylasilan matcher icinde.
        val needles = (0 until threadCount).map { "XSECNEEDLE%02dMARK".format(it) }
        val patterns = needles.mapIndexed { index, needle -> BytePattern(index, needle.encodeToByteArray()) }
        val matcher = BytePatternMatcher(patterns, chunkSize = 1024)
        val data = buildBuffer(needles)

        val failures = Collections.synchronizedList(ArrayList<String>())
        val start = CountDownLatch(1)
        val threads = (0 until threadCount).map { threadIndex ->
            Thread {
                start.await()
                repeat(iterations) { iteration ->
                    // Chunk boyutunu degistirerek parca sinirlarini (carry) farkli
                    // kiyilarda eslestir; tum igneler her taramada bulunmali.
                    val result = matcher.scan(data, chunkSize = 512 + ((iteration * 97) % 1024))
                    needles.forEachIndexed { patternIndex, _ ->
                        if (!result.matchedIds.contains(patternIndex)) {
                            failures += "thread=$threadIndex iteration=$iteration missing pattern $patternIndex"
                        }
                    }
                }
            }
        }
        threads.forEach { it.start() }
        start.countDown()
        threads.forEach { it.join() }

        assertTrue("paylasilan matcher paralel taramada esleme kaybetmemeli: $failures", failures.isEmpty())
    }

    @Test
    fun parallelScansNeverLeakStateBetweenThreads() {
        // Bir thread igneli (kirli) veriyi, diger thread ignesiz (temiz) veriyi
        // paralel tarar: kirli taraf igneyi her seferinde bulmali, temiz taraf
        // ASLA esleme raporlamamali (durum kacagi yok).
        val needle = "XSECNEEDLE-CLEAN-E"
        val matcher = BytePatternMatcher(listOf(BytePattern(0, needle.encodeToByteArray())), chunkSize = 512)

        val dirty = ByteArray(64 * 1024) { (it * 31 + 17) % 127 }
        val needleBytes = needle.encodeToByteArray()
        System.arraycopy(needleBytes, 0, dirty, 32 * 1024, needleBytes.size)
        val clean = ByteArray(64 * 1024) { (it * 41 + 7) % 127 }

        val failures = Collections.synchronizedList(ArrayList<String>())
        val start = CountDownLatch(1)
        val dirtyThread = Thread {
            start.await()
            repeat(iterations) {
                if (!matcher.scan(dirty).matchedIds.contains(0)) failures += "dirty scan missed the needle"
            }
        }
        val cleanThread = Thread {
            start.await()
            repeat(iterations) {
                if (matcher.scan(clean).matchedIds.isNotEmpty()) failures += "clean scan reported a match"
            }
        }
        dirtyThread.start()
        cleanThread.start()
        start.countDown()
        dirtyThread.join()
        cleanThread.join()

        assertTrue(failures.toString(), failures.isEmpty())
    }

    /**
     * Tum igneler tek buffer icine, (1) parca sinirini asan konumda (1020+),
     * (2) bufferun ortasinda, (3) sonuna yakin; dolgu deterministiktir.
     */
    private fun buildBuffer(needles: List<String>): ByteArray {
        val size = 96 * 1024
        val data = ByteArray(size) { (it * 31 + 17) % 127 }
        needles.forEachIndexed { index, needle ->
            val bytes = needle.encodeToByteArray()
            val offsets = listOf(64 + index * 97, 1020 + index * 13, size - bytes.size - 13 - index * 11)
            for (offset in offsets) {
                System.arraycopy(bytes, 0, data, offset, bytes.size)
            }
        }
        return data
    }
}
