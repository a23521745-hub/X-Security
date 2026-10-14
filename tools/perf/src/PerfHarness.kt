package perf

import org.xsecurity.scanner.engine.ScanEngines
import org.xsecurity.scanner.engine.ScanResult
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.system.exitProcess

/**
 * X-Security in-sandbox perf harness (JVM).
 *
 * Measures the parts of the optimization protocol that are measurable without a device, using the
 * **production** engine code and the **production** signature files that ship in the APK:
 *
 *  1. engine load (parse of the bundled YARA/ClamAV databases) — the work that must never run on
 *     the UI thread (cold start / first scan);
 *  2. scan throughput (MB/s) over a generated corpus and over a ZIP/APK-shaped container, plus
 *     the allocation volume of both paths (HotSpot per-thread allocation counter);
 *  3. the baseline *mechanism* counts for the two list/notification offenders (per-row
 *     PackageManager query, per-app progress publication). On the fixed tree, `OptimizationBench`
 *     adds the real production classes' numbers.
 *
 * What this harness CANNOT measure: absolute cold-start time, frame jank, PSS and WorkManager
 * wakeups on a real device. Those rows are produced by `tools/perf/device-probe.sh` on the target
 * phone and pasted into the audit table; the harness never guesses them.
 */
object PerfHarness {

    private const val RAW_BYTES = 64L * 1024 * 1024
    private const val APK_DEX_BYTES = 8L * 1024 * 1024

    @JvmStatic
    fun main(args: Array<String>) {
        val root = File(args.getOrNull(0) ?: ".")
        if (!root.isDirectory) {
            System.err.println("usage: PerfHarness <repo-root>")
            exitProcess(2)
        }
        val signatures = File(root, "app/src/main/assets/signatures")
        val yara = File(signatures, "rules.yar").takeIf { it.isFile }
        val clam = File(signatures, "signatures.ndb").takeIf { it.isFile }
        val hashes = File(signatures, "hashes.hsb").takeIf { it.isFile }

        println("== X-Security perf harness (JVM ${System.getProperty("java.version")}) ==")
        println("repo: ${root.absolutePath}")
        println("signature files: yara=${yara?.length() ?: 0}B ndb=${clam?.length() ?: 0}B hsb=${hashes?.length() ?: 0}B")

        // ---- 1. engine load -----------------------------------------------------------------
        println()
        println("== engine load (production parsers, bundled database) ==")
        repeat(3) { round ->
            ScanEngines.invalidate()
            val threadBean = java.lang.management.ManagementFactory.getThreadMXBean()
            val allocatedBefore = allocatedBytes(threadBean)
            val startedAt = System.nanoTime()
            val engine = ScanEngines.acquire(yara, clam, hashes, force = true)
            val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000.0
            val allocatedMb = (allocatedBytes(threadBean) - allocatedBefore) / 1024.0 / 1024.0
            engine.fold(
                onSuccess = {
                    println(
                        "  run ${round + 1}: ${"%.1f".format(elapsedMs)} ms  " +
                            "allocated=${"%.1f".format(allocatedMb)} MB  fingerprint=${it.fingerprint.take(16)}"
                    )
                },
                onFailure = { println("  run ${round + 1}: FAILED ${it.message}") }
            )
        }
        val engine = ScanEngines.acquire(yara, clam, hashes, force = true).getOrElse {
            System.err.println("engine unavailable: ${it.message}")
            exitProcess(1)
        }

        // ---- 2. scan throughput -------------------------------------------------------------
        println()
        println("== scan throughput (streaming matcher + APK/ZIP entry scan) ==")
        val scratch = File(System.getProperty("java.io.tmpdir"), "xsec-perf").apply { mkdirs() }
        val rawCorpus = File(scratch, "corpus-64m.bin")
        writePseudoRandom(rawCorpus, RAW_BYTES)
        val apkCorpus = File(scratch, "corpus.apk")
        writeSyntheticApk(apkCorpus)

        measure("raw ${rawCorpus.length() / 1024 / 1024} MiB", engine) { engine.scan(rawCorpus) }
        measure("zip/apk ${apkCorpus.length() / 1024 / 1024} MiB", engine) { engine.scan(apkCorpus) }

        println()
        println("== baseline mechanism counts (the two list/notification offenders) ==")
        val rows = 400
        val renders = 30
        println("  quarantine list: $rows rows x $renders recompositions")
        println("    PackageManager queries before hoisting: ${rows * renders} (one per row per recomposition)")
        println("  device scan: $rows apps")
        println("    progress publications before coalescing: $rows (notification + full list republish)")

        // The fixed-tree measurements live in a source file that imports the new production
        // classes; it is only compiled into the "after" run, so it is reached reflectively here.
        val optimizationBench = runCatching { Class.forName("perf.OptimizationBench") }.getOrNull()
        if (optimizationBench != null) {
            println()
            runCatching {
                optimizationBench.getMethod("report").invoke(optimizationBench.getField("INSTANCE").get(null))
            }.onFailure { println("  (OptimizationBench failed: ${it.message})") }
        } else {
            println()
            println("  (OptimizationBench absent: this run predates the new production classes)")
        }

        println()
        println("== note ==")
        println("  device rows (cold start p50, jank, PSS, wakeups/hour) are produced by tools/perf/device-probe.sh")
        println("  local artifacts: ${rawCorpus.absolutePath} (${rawCorpus.length()} B), ${apkCorpus.absolutePath}")
    }

    private fun measure(label: String, engine: org.xsecurity.scanner.engine.ApkScannerEngine, scan: () -> ScanResult) {
        val runs = 3
        val times = ArrayList<Double>(runs)
        val allocations = ArrayList<Double>(runs)
        var bytes = 0L
        var status = ""
        repeat(runs) {
            val threadBean = java.lang.management.ManagementFactory.getThreadMXBean()
            val allocatedBefore = allocatedBytes(threadBean)
            val startedAt = System.nanoTime()
            val result = scan()
            times += (System.nanoTime() - startedAt) / 1_000_000.0
            allocations += (allocatedBytes(threadBean) - allocatedBefore) / 1024.0 / 1024.0
            bytes = result.bytesScanned
            status = result.status.name
        }
        val medianMs = times.sorted()[runs / 2]
        val megabytes = bytes.toDouble() / 1024.0 / 1024.0
        val mbPerSecond = if (medianMs <= 0.0) 0.0 else megabytes / (medianMs / 1000.0)
        println(
            "  $label: status=$status bytesScanned=${bytes} " +
                "median=${"%.1f".format(medianMs)} ms throughput=${"%.1f".format(mbPerSecond)} MB/s " +
                "allocated=${"%.1f".format(allocations.sorted()[runs / 2])} MB"
        )
    }

    private fun allocatedBytes(bean: java.lang.management.ThreadMXBean): Long = try {
        (bean as? com.sun.management.ThreadMXBean)?.currentThreadAllocatedBytes ?: -1L
    } catch (_: Throwable) {
        -1L
    }

    private fun writePseudoRandom(file: File, bytes: Long) {
        if (file.isFile && file.length() == bytes) return
        var state = 0x9E3779B97F4A7C15uL
        val buffer = ByteArray(1 shl 16)
        file.outputStream().buffered(1 shl 20).use { out ->
            var written = 0L
            while (written < bytes) {
                for (index in buffer.indices) {
                    state = state xor (state shl 13)
                    state = state xor (state shr 7)
                    state = state xor (state shl 17)
                    buffer[index] = (state and 0xFFu).toByte()
                }
                val chunk = minOf(buffer.size.toLong(), bytes - written).toInt()
                out.write(buffer, 0, chunk)
                written += chunk
            }
        }
    }

    /** APK-shaped container: deflated `classes.dex` plus the usual ZIP members. */
    private fun writeSyntheticApk(file: File) {
        if (file.isFile && file.length() > 1024) return
        val dexBytes = ByteArray(APK_DEX_BYTES.toInt())
        var state = 0x2545F4914F6CDD1DuL
        for (index in dexBytes.indices) {
            state = state xor (state shl 13)
            state = state xor (state shr 7)
            state = state xor (state shl 17)
            dexBytes[index] = (state and 0xFFu).toByte()
        }
        // A little in-dex evidence so the scanner's ZIP entry path has something to look at.
        val needle = "com/metasploit/stage".toByteArray(Charsets.US_ASCII)
        System.arraycopy(needle, 0, dexBytes, 4096, needle.size)

        ZipOutputStream(file.outputStream().buffered(1 shl 20)).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(ByteArray(64 * 1024))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(dexBytes)
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/payload.bin"))
            zip.write(ByteArray(256 * 1024) { 0x41 })
            zip.closeEntry()
        }
    }
}
