package org.jetbrains.teamcity.builds.oidc.cache.bench

import io.mockk.every
import io.mockk.mockk
import org.HdrHistogram.Histogram
import jetbrains.buildServer.serverSide.ProjectManager
import jetbrains.buildServer.serverSide.SProject
import jetbrains.buildServer.serverSide.TeamCityNode
import jetbrains.buildServer.serverSide.TeamCityNodes
import jetbrains.buildServer.serverSide.executors.ExecutorServices
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.cache.MultiNodeJWKCache
import java.io.File
import java.time.Clock
import java.util.Locale
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.LongAdder
import java.util.concurrent.locks.LockSupport

/**
 * Concurrent load benchmark for [MultiNodeJWKCache], measuring read/write throughput and the resulting
 * DB-query load on the global JWK cache. The same harness compiles and runs unchanged on `master` and
 * the `cache-rework` branch (it only touches the stable public API + `globalCleanup()`).
 *
 * Run it twice via [main]: a zero-latency "count" pass (pure ops/sec + exact query counts) and a
 * "latency" pass that simulates per-query DB round-trips to expose lock-contention effects.
 */

// ---------------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------------

/** Benchmark configuration. Every field is overridable via a `-Dbench.*` system property (see defaults below). */
class BenchConfig {
    // Concurrent reader threads, each looping fetchCachedJWKs()
    val readers = intProp("bench.readers", 2000)

    // Concurrent writer threads, each looping a weighted mix of trackKey/globalCleanup/purge
    val writers = intProp("bench.writers", 20)

    // Seconds the full workload runs before measurement starts (results discarded) so HotSpot reaches steady-state C2.
    val warmupSec = intProp("bench.warmupSec", 10)
    // Seconds of the measurement window over which throughput, latency, and DB queries are recorded.
    val measureSec = intProp("bench.measureSec", 30)

    // Target pause between successive reads per reader thread, microseconds. Small => high read pressure;
    // 0 => no pause (maximum offered load). Actual pause is randomized around this value by readJitterPct.
    val readIntervalMicros = longProp("bench.readIntervalMicros", 100)
    // Jitter applied to each reader pause, as a percentage (±) of readIntervalMicros. Desynchronizes readers so
    // 2000 threads don't march in lockstep (an artificial thundering herd). 0 => fixed interval; 50 => uniform in
    // [0.5x, 1.5x] of the interval (mean stays at readIntervalMicros). Clamped to 0..100.
    val readJitterPct = intProp("bench.readJitterPct", 50).coerceIn(0, 100)

    // Number of JWKs pre-loaded into the cache before measuring, so reads return a realistic non-empty working set.
    val seedKeys = intProp("bench.seedKeys", 10)

    // Writer op weights: each writer iteration picks an op at random in proportion to these (out of their sum).
    val trackKeyWeight = intProp("bench.w.trackKey", 100)  // the common case: register/refresh a key
    val cleanupWeight = intProp("bench.w.cleanup", 10)     // more frequent than purge, still slow (holds the write lock)
    val purgeWeight = intProp("bench.w.purge", 1)         // rare, ~1/10 of trackKey: revoke everything

    // Pause between successive ops per writer thread, microseconds. 0 => writers run as fast as possible (open-loop,
    // which lets them saturate — useful for max write throughput, but inflates total DB load on the faster branch).
    val writerPauseMicros = longProp("bench.writerPauseMicros", 200)

    // Simulated OTHER cluster nodes writing to the shared JWK store, per second. Each write bumps the shared update
    // marker, forcing this node's next refresh to issue the conditional body-fetch query. Set 0 for pure single-node.
    val peerWritesPerSec = intProp("bench.peerWritesPerSec", 10)

    companion object {
        fun intProp(k: String, d: Int) = System.getProperty(k)?.toIntOrNull() ?: d
        fun longProp(k: String, d: Long) = System.getProperty(k)?.toLongOrNull() ?: d
    }
}

// Latency histograms use HdrHistogram (microsecond values, 3 significant digits, auto-resizing).
private fun newHistogram() = Histogram(3)

// ---------------------------------------------------------------------------------------------------
// Per-run result aggregation
// ---------------------------------------------------------------------------------------------------

private const val OP_TRACK = 0
private const val OP_CLEANUP = 1
private const val OP_PURGE = 2
private val OP_NAMES = arrayOf("trackKey", "globalCleanup", "purge")

class RunResult(
    val mode: String,
    val cfg: BenchConfig,
    val latency: QueryLatency,
    val wallSeconds: Double,
    val reads: Long,
    val readErrors: Long,
    val readHist: Histogram,
    val writeOps: LongArray,        // indexed by OP_*
    val writeErrors: LongArray,
    val writeHist: Array<Histogram>,
    val jwkQueries: QuerySnapshot,  // delta over the measurement window (global JWK cache only)
    val seededKeys: Int
)

// ---------------------------------------------------------------------------------------------------
// The benchmark
// ---------------------------------------------------------------------------------------------------

class JWKCacheBenchmark(private val cfg: BenchConfig, private val latency: QueryLatency, private val mode: String) {

    private val jwkQueries = StorageQueries("jwk")
    private val jwkStorage = CountingFakeStorage(jwkQueries, latency)
    // The per-node expiration storage is functional but non-counting — its DB load is out of scope.
    private val nodeStorage = FakeStorage(latency)

    @Volatile private var running = false
    @Volatile private var recording = false

    private val sink = LongAdder() // defeats dead-code elimination of read results

    // The current signing-key generation, shared by all writers. trackKey always targets this one key, so after
    // it is first inserted, repeated trackKey calls are no-ops on the global JWK store (the key is already present)
    // — matching production, where the active key only changes on rotation. A purge revokes everything and bumps the
    // generation, so the next trackKey introduces a fresh key. Starts past the seeded range to avoid colliding with
    // (and being blocked by the revocation marker of) a pre-seeded key.
    private val keyGen = AtomicLong(cfg.seedKeys.toLong())
    private fun activeKid() = "kid-${keyGen.get()}"

    private fun buildCache(): MultiNodeJWKCache {
        val prefix = OIDCConstants.JWKCache.STORAGE_ID_PREFIX
        val nodeId = "node-1"
        val rootProject = mockk<SProject> {
            every { getCustomDataStorage("$prefix-jwk") } returns jwkStorage
            every { getCustomDataStorage("$prefix-$nodeId-expirations") } returns nodeStorage
        }
        val currentNode = mockk<TeamCityNode> {
            every { id } returns nodeId
            every { isMainNode } returns true
        }
        val nodes = mockk<TeamCityNodes> {
            every { this@mockk.currentNode } returns currentNode
            every { this@mockk.nodes } returns listOf(currentNode)  // loop skips current node -> global-cache-only cleanup
        }
        val pm = mockk<ProjectManager> { every { this@mockk.rootProject } returns rootProject }
        val executor = mockk<ScheduledExecutorService>(relaxed = true)
        val executors = mockk<ExecutorServices> { every { normalExecutorService } returns executor }
        // Real system clock so expiry math in trackKey/globalCleanup behaves naturally.
        return MultiNodeJWKCache(nodes, pm, executors, Clock.systemUTC())
    }

    fun run(): RunResult {
        val cache = buildCache()

        // Seed the global cache so reads return a realistic, non-empty working set.
        val farFuture = Instant.now().plusSeconds(7200)
        for (i in 0 until cfg.seedKeys) {
            cache.trackKey("kid-$i", """{"kid":"kid-$i","kty":"RSA","n":"seed"}""", farFuture)
        }
        val seededNow = cache.fetchCachedJWKs().size
        require(seededNow > 0) { "Seeding failed: fetchCachedJWKs() returned empty after seeding $seededKeysMsg" }

        val start = CountDownLatch(1)
        val readyReaders = CountDownLatch(cfg.readers)
        val readyWriters = CountDownLatch(cfg.writers)

        val readerWorkers = List(cfg.readers) { ReaderWorker(cache, start, readyReaders) }
        val writerWorkers = List(cfg.writers) { WriterWorker(cache, start, readyWriters) }
        // Peer-node writers simulate other cluster nodes updating the shared JWK store (see [PeerWorker]).
        val peerWorkers = if (cfg.peerWritesPerSec > 0) listOf(PeerWorker(start)) else emptyList()

        val threads = ArrayList<Thread>(readerWorkers.size + writerWorkers.size + peerWorkers.size)
        // small stacks to keep thousands of reader threads cheap on memory
        readerWorkers.forEachIndexed { i, w -> threads += Thread(null, w, "reader-$i", 256 * 1024) }
        writerWorkers.forEachIndexed { i, w -> threads += Thread(null, w, "writer-$i", 512 * 1024) }
        peerWorkers.forEachIndexed { i, w -> threads += Thread(null, w, "peer-$i", 256 * 1024) }

        threads.forEach { it.isDaemon = true; it.start() }
        readyReaders.await()
        readyWriters.await()

        running = true
        start.countDown()

        Thread.sleep(cfg.warmupSec * 1000L)

        // Begin measurement window: snapshot query counters, then record.
        val jwkBase = jwkQueries.snapshot()
        val wallStart = System.nanoTime()
        recording = true
        Thread.sleep(cfg.measureSec * 1000L)
        recording = false
        val wallSeconds = (System.nanoTime() - wallStart) / 1e9

        val jwkDelta = delta(jwkBase, jwkQueries.snapshot())

        running = false
        threads.forEach { it.join(5000) }

        // Aggregate from the worker objects.
        val readHist = newHistogram()
        var reads = 0L; var readErr = 0L
        for (w in readerWorkers) { readHist.add(w.hist); reads += w.count; readErr += w.errors }

        val writeOps = LongArray(3); val writeErr = LongArray(3)
        val writeHist = Array(3) { newHistogram() }
        for (w in writerWorkers) for (op in 0..2) {
            writeOps[op] += w.counts[op]
            writeErr[op] += w.errors[op]
            writeHist[op].add(w.hist[op])
        }

        // touch the sink so JIT can't elide reads
        if (sink.sum() < 0) println("unreachable $sink")

        return RunResult(mode, cfg, latency, wallSeconds, reads, readErr, readHist,
            writeOps, writeErr, writeHist, jwkDelta, seededNow)
    }

    /** Reader thread: loops `fetchCachedJWKs()` and records throughput/latency while [recording]. */
    private inner class ReaderWorker(
        private val cache: MultiNodeJWKCache,
        private val start: CountDownLatch,
        private val ready: CountDownLatch,
    ) : Runnable {
        val hist = newHistogram()
        var count = 0L
        var errors = 0L

        override fun run() {
            ready.countDown()
            start.await()
            val rnd = ThreadLocalRandom.current()
            val intervalNanos = cfg.readIntervalMicros * 1000
            // Half-width of the uniform jitter window; total span is 2x this, centered on intervalNanos.
            val jitterNanos = intervalNanos * cfg.readJitterPct / 100
            while (running) {
                val rec = recording
                val t0 = if (rec) System.nanoTime() else 0L
                try {
                    val res = cache.fetchCachedJWKs()
                    if (rec) {
                        sink.add(res.size.toLong())
                        hist.recordValue((System.nanoTime() - t0) / 1000)
                        count++
                    }
                } catch (e: Throwable) {
                    if (rec) errors++
                }
                if (intervalNanos > 0) {
                    // Park for a value uniform in [interval - jitter, interval + jitter); mean stays at the interval.
                    val park = if (jitterNanos > 0) (intervalNanos - jitterNanos) + rnd.nextLong(2 * jitterNanos) else intervalNanos
                    LockSupport.parkNanos(park)
                }
            }
        }
    }

    /** Writer thread: picks a weighted op (trackKey / globalCleanup / purge) each iteration. */
    private inner class WriterWorker(
        private val cache: MultiNodeJWKCache,
        private val start: CountDownLatch,
        private val ready: CountDownLatch,
    ) : Runnable {
        val counts = LongArray(3)
        val errors = LongArray(3)
        val hist = Array(3) { newHistogram() }

        private val totalWeight = cfg.trackKeyWeight + cfg.cleanupWeight + cfg.purgeWeight

        override fun run() {
            ready.countDown()
            start.await()
            val rnd = ThreadLocalRandom.current()
            val pauseNanos = cfg.writerPauseMicros * 1000
            while (running) {
                val pick = rnd.nextInt(totalWeight)
                val op = when {
                    pick < cfg.trackKeyWeight -> OP_TRACK
                    pick < cfg.trackKeyWeight + cfg.cleanupWeight -> OP_CLEANUP
                    else -> OP_PURGE
                }
                val rec = recording
                val t0 = if (rec) System.nanoTime() else 0L
                try {
                    when (op) {
                        // All writers track the same current key (every issued token bumps its expiry); after the
                        // first insert this is a no-op on the global JWK store until the key rotates.
                        OP_TRACK -> {
                            val kid = activeKid()
                            cache.trackKey(kid, """{"kid":"$kid","kty":"RSA","n":"body"}""", Instant.now().plusSeconds(3600))
                        }
                        OP_CLEANUP -> cache.globalCleanup()
                        // Revoke everything, then rotate: the next trackKey introduces a fresh key.
                        OP_PURGE -> { cache.purge(); keyGen.incrementAndGet() }
                    }
                    if (rec) {
                        hist[op].recordValue((System.nanoTime() - t0) / 1000)
                        counts[op]++
                    }
                } catch (e: Throwable) {
                    if (rec) errors[op]++
                }
                if (pauseNanos > 0) LockSupport.parkNanos(pauseNanos)
            }
        }
    }

    /**
     * Peer-node writer: simulates other cluster nodes updating the shared JWK store, which forces this node's
     * refresh to perform the conditional body-fetch query. It re-writes the current active key (the one this node
     * tracks too), so it bumps the marker without introducing churn.
     */
    private inner class PeerWorker(
        private val start: CountDownLatch,
    ) : Runnable {
        override fun run() {
            start.await()
            var n = 0L
            val periodNanos = 1_000_000_000L / cfg.peerWritesPerSec
            while (running) {
                val kid = activeKid()
                jwkStorage.simulatePeerWrite(kid, """{"kid":"$kid","kty":"RSA","n":"peer-${n}"}""")
                n++
                LockSupport.parkNanos(periodNanos)
            }
        }
    }

    private val seededKeysMsg get() = "${cfg.seedKeys} keys"

    private fun delta(base: QuerySnapshot, end: QuerySnapshot) = QuerySnapshot(
        base.label,
        end.timestampChecks - base.timestampChecks,
        end.bodyFetches - base.bodyFetches,
        end.flushWrites - base.flushWrites
    )
}

// ---------------------------------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------------------------------

// Locale.ROOT so grouping/decimal separators are stable ('.'/',') regardless of the CI machine's locale.
private fun fmt(n: Long): String = String.format(Locale.ROOT, "%,d", n)
private fun fmtD(d: Double): String = String.format(Locale.ROOT, "%,.1f", d)

private fun usToStr(us: Long): String =
    if (us >= 1000) String.format(Locale.ROOT, "%.2f ms", us / 1000.0) else "$us us"

fun renderRunMarkdown(r: RunResult): String {
    val sb = StringBuilder()
    val c = r.cfg
    sb.appendLine("### Mode: `${r.mode}`")
    sb.appendLine()
    sb.appendLine("- latency: timestampCheck=${r.latency.timestampCheckMs}ms, bodyFetch=${r.latency.bodyFetchMs}ms, flush=${r.latency.flushMs}ms")
    sb.appendLine("- readers=${c.readers}, writers=${c.writers}, warmup=${c.warmupSec}s, measure=${c.measureSec}s (wall ${fmtD(r.wallSeconds)}s)")
    sb.appendLine("- readInterval=${c.readIntervalMicros}us ±${c.readJitterPct}%, writerPause=${c.writerPauseMicros}us, seeded JWKs=${r.seededKeys}, peerWrites/s=${c.peerWritesPerSec}")
    sb.appendLine()

    // Reads
    val rps = r.reads / r.wallSeconds
    sb.appendLine("#### Reads (`fetchCachedJWKs`)")
    sb.appendLine("| metric | value |")
    sb.appendLine("|---|---|")
    sb.appendLine("| total reads | ${fmt(r.reads)} |")
    sb.appendLine("| **throughput** | **${fmtD(rps)} ops/sec** |")
    sb.appendLine("| latency mean | ${usToStr(r.readHist.mean.toLong())} |")
    sb.appendLine("| latency p50 | ${usToStr(r.readHist.getValueAtPercentile(50.0))} |")
    sb.appendLine("| latency p99 | ${usToStr(r.readHist.getValueAtPercentile(99.0))} |")
    sb.appendLine("| latency max | ${usToStr(r.readHist.maxValue)} |")
    sb.appendLine("| errors | ${fmt(r.readErrors)} |")
    sb.appendLine()

    // Writes
    val totalWrites = r.writeOps.sum()
    val wps = totalWrites / r.wallSeconds
    sb.appendLine("#### Writes")
    sb.appendLine("| op | count | ops/sec | mean | p99 | max | errors |")
    sb.appendLine("|---|---|---|---|---|---|---|")
    for (op in 0..2) {
        val h = r.writeHist[op]
        sb.appendLine("| ${OP_NAMES[op]} | ${fmt(r.writeOps[op])} | ${fmtD(r.writeOps[op] / r.wallSeconds)} | ${usToStr(h.mean.toLong())} | ${usToStr(h.getValueAtPercentile(99.0))} | ${usToStr(h.maxValue)} | ${fmt(r.writeErrors[op])} |")
    }
    sb.appendLine("| **total** | ${fmt(totalWrites)} | ${fmtD(wps)} | | | | ${fmt(r.writeErrors.sum())} |")
    sb.appendLine()

    // DB queries (global JWK cache only)
    val q = r.jwkQueries
    sb.appendLine("#### DB queries (global JWK cache, measurement window)")
    sb.appendLine("| timestamp-checks | body-fetches | flush-writes | total |")
    sb.appendLine("|---|---|---|---|")
    sb.appendLine("| ${fmt(q.timestampChecks)} | ${fmt(q.bodyFetches)} | ${fmt(q.flushWrites)} | ${fmt(q.total)} |")
    sb.appendLine()
    sb.appendLine("- total DB queries: **${fmt(q.total)}**  (${fmtD(q.total / r.wallSeconds)} queries/sec)")
    sb.appendLine("- DB queries per read: **${fmtD(if (r.reads > 0) q.total.toDouble() / r.reads else 0.0)}**")
    sb.appendLine()
    return sb.toString()
}

/** Plain-text, aligned-column rendering — readable in CI logs and terminals without a markdown renderer. */
fun renderRunText(r: RunResult): String {
    val sb = StringBuilder()
    val c = r.cfg
    fun kv(label: String, value: String) = sb.appendLine("  %-18s %s".format(label, value))
    // op count ops/sec mean p99 max errors
    val rowFmt = "  %-14s %13s %12s %11s %11s %11s %8s"

    sb.appendLine("--- Mode: ${r.mode} ---")
    sb.appendLine("latency: timestampCheck=${r.latency.timestampCheckMs}ms bodyFetch=${r.latency.bodyFetchMs}ms flush=${r.latency.flushMs}ms")
    sb.appendLine("config:  readers=${c.readers} writers=${c.writers} warmup=${c.warmupSec}s measure=${c.measureSec}s (wall ${fmtD(r.wallSeconds)}s)")
    sb.appendLine("         readInterval=${c.readIntervalMicros}us ±${c.readJitterPct}% writerPause=${c.writerPauseMicros}us seededJWKs=${r.seededKeys} peerWrites/s=${c.peerWritesPerSec}")
    sb.appendLine()

    sb.appendLine("Reads (fetchCachedJWKs)")
    kv("throughput", "${fmtD(r.reads / r.wallSeconds)} ops/sec")
    kv("total reads", fmt(r.reads))
    kv("latency mean", usToStr(r.readHist.mean.toLong()))
    kv("latency p50", usToStr(r.readHist.getValueAtPercentile(50.0)))
    kv("latency p99", usToStr(r.readHist.getValueAtPercentile(99.0)))
    kv("latency max", usToStr(r.readHist.maxValue))
    kv("errors", fmt(r.readErrors))
    sb.appendLine()

    sb.appendLine("Writes")
    sb.appendLine(rowFmt.format("op", "count", "ops/sec", "mean", "p99", "max", "errors"))
    for (op in 0..2) {
        val h = r.writeHist[op]
        sb.appendLine(rowFmt.format(
            OP_NAMES[op], fmt(r.writeOps[op]), fmtD(r.writeOps[op] / r.wallSeconds),
            usToStr(h.mean.toLong()), usToStr(h.getValueAtPercentile(99.0)), usToStr(h.maxValue), fmt(r.writeErrors[op])))
    }
    val totalWrites = r.writeOps.sum()
    sb.appendLine(rowFmt.format(
        "total", fmt(totalWrites), fmtD(totalWrites / r.wallSeconds), "", "", "", fmt(r.writeErrors.sum())))
    sb.appendLine()

    val q = r.jwkQueries
    sb.appendLine("DB queries (global JWK cache)")
    kv("timestamp-checks", fmt(q.timestampChecks))
    kv("body-fetches", fmt(q.bodyFetches))
    kv("flush-writes", fmt(q.flushWrites))
    kv("total", "${fmt(q.total)}  (${fmtD(q.total / r.wallSeconds)}/sec)")
    kv("per read", fmtD(if (r.reads > 0) q.total.toDouble() / r.reads else 0.0))
    sb.appendLine()
    return sb.toString()
}

// ---------------------------------------------------------------------------------------------------
// CSV rendering — one header row + one row per run, for spreadsheet/Excel processing.
// Numbers are raw (no thousands separators, '.' decimal) and latencies are in microseconds, so Excel parses
// every cell as a number. Use the -Dbench.out file (stdout is interleaved with progress lines).
// ---------------------------------------------------------------------------------------------------

private fun csvNum(d: Double) = String.format(Locale.ROOT, "%.3f", d)
private fun csvQuote(s: String) = "\"" + s.replace("\"", "\"\"") + "\""

private fun csvColumns(): List<String> {
    val cols = mutableListOf(
        "label", "mode",
        "lat_timestampMs", "lat_bodyMs", "lat_flushMs",
        "readers", "writers", "warmupSec", "measureSec",
        "readIntervalMicros", "readJitterPct", "seedKeys", "peerWritesPerSec", "writerPauseMicros",
        "wallSeconds",
        "reads", "read_opsPerSec", "read_mean_us", "read_p50_us", "read_p99_us", "read_max_us", "read_errors",
    )
    for (op in OP_NAMES) cols += listOf("${op}_count", "${op}_opsPerSec", "${op}_mean_us", "${op}_p99_us", "${op}_max_us", "${op}_errors")
    cols += listOf(
        "writes_total", "writes_opsPerSec", "writes_errors",
        "jwk_timestampChecks", "jwk_bodyFetches", "jwk_flushWrites", "jwk_total", "jwk_queriesPerSec", "jwk_queriesPerRead",
    )
    return cols
}

fun renderCsvHeader(): String = csvColumns().joinToString(",") + "\n"

fun renderCsvRow(r: RunResult): String {
    val c = r.cfg
    val cells = mutableListOf(
        csvQuote(System.getProperty("bench.label", "unknown")), r.mode,
        r.latency.timestampCheckMs.toString(), r.latency.bodyFetchMs.toString(), r.latency.flushMs.toString(),
        c.readers.toString(), c.writers.toString(), c.warmupSec.toString(), c.measureSec.toString(),
        c.readIntervalMicros.toString(), c.readJitterPct.toString(), c.seedKeys.toString(),
        c.peerWritesPerSec.toString(), c.writerPauseMicros.toString(),
        csvNum(r.wallSeconds),
        r.reads.toString(), csvNum(r.reads / r.wallSeconds),
        r.readHist.mean.toLong().toString(), r.readHist.getValueAtPercentile(50.0).toString(),
        r.readHist.getValueAtPercentile(99.0).toString(), r.readHist.maxValue.toString(), r.readErrors.toString(),
    )
    for (op in 0..2) {
        val h = r.writeHist[op]
        cells += listOf(
            r.writeOps[op].toString(), csvNum(r.writeOps[op] / r.wallSeconds),
            h.mean.toLong().toString(), h.getValueAtPercentile(99.0).toString(), h.maxValue.toString(),
            r.writeErrors[op].toString(),
        )
    }
    val q = r.jwkQueries
    cells += listOf(
        r.writeOps.sum().toString(), csvNum(r.writeOps.sum() / r.wallSeconds), r.writeErrors.sum().toString(),
        q.timestampChecks.toString(), q.bodyFetches.toString(), q.flushWrites.toString(), q.total.toString(),
        csvNum(q.total / r.wallSeconds), csvNum(if (r.reads > 0) q.total.toDouble() / r.reads else 0.0),
    )
    return cells.joinToString(",") + "\n"
}

// ---------------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------------

fun main() {
    val cfg = BenchConfig()
    val label = System.getProperty("bench.label", "unknown")
    val modeProp = System.getProperty("bench.mode", "both")

    // Output format: plain text (default, CLI/CI-friendly), markdown (bench.format=md), or CSV (bench.format=csv).
    val jvm = "${System.getProperty("java.version")} | cores: ${Runtime.getRuntime().availableProcessors()}"
    val (header, render, ext) = when (System.getProperty("bench.format", "text").lowercase()) {
        "csv" ->
            Triple(renderCsvHeader(), ::renderCsvRow, "csv")
        "md", "markdown" ->
            Triple("# MultiNodeJWKCache benchmark — `$label`\n\nJVM: $jvm\n\n", ::renderRunMarkdown, "md")
        else -> {
            val bar = "=".repeat(72)
            Triple("$bar\nMultiNodeJWKCache benchmark — $label\nJVM: $jvm\n$bar\n\n", ::renderRunText, "txt")
        }
    }
    val out = System.getProperty("bench.out") ?: "bench-results.$ext"
    val outFile = File(out)

    // CSV append mode: if the file already exists, skip the header so rows from successive runs accumulate in one
    // sheet without repeating the column names. For all other formats (or a new CSV file) write normally.
    val isCsv = System.getProperty("bench.format", "text").lowercase() == "csv"
    val appendMode = isCsv && outFile.exists()

    val runs = ArrayList<RunResult>()
    fun doRun(mode: String, lat: QueryLatency) {
        System.gc()
        println(">>> Running mode=$mode (latency=${lat.enabled}) ...")
        val res = JWKCacheBenchmark(cfg, lat, mode).run()
        runs += res
        print(render(res))
    }

    if (!appendMode) print(header)

    if (modeProp == "count" || modeProp == "both") {
        doRun("count", QueryLatency())
    }
    if (modeProp == "latency" || modeProp == "both") {
        val lat = QueryLatency(
            timestampCheckMs = BenchConfig.longProp("bench.lat.timestampMs", 3),
            bodyFetchMs = BenchConfig.longProp("bench.lat.bodyMs", 80),
            flushMs = BenchConfig.longProp("bench.lat.flushMs", 80)
        )
        doRun("latency", lat)
    }

    val reportBody = runs.joinToString("") { render(it) }
    if (appendMode) {
        outFile.appendText(reportBody)
    } else {
        outFile.writeText(header + reportBody)
    }
    println("\n>>> Wrote report to ${outFile.absolutePath}")
}
