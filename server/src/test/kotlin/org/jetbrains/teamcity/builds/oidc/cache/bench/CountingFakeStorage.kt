package org.jetbrains.teamcity.builds.oidc.cache.bench

import jetbrains.buildServer.serverSide.CustomDataConflictException
import jetbrains.buildServer.serverSide.CustomDataStorage
import jetbrains.buildServer.serverSide.CustomDataStorage.ConflictResolution
import java.util.Date
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.LongAdder
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Per-storage DB-query counters.
 *
 * - [timestampChecks]: every `refresh()` issues one `select update_date ... part_num = 0` (the marker check).
 * - [bodyFetches]: a `refresh()` additionally loads the body only when the marker changed since the last load.
 * - [flushWrites]: every `flush(...)`/`putValuesAndFlush(...)` of a *dirty* storage performs one write batch
 *   (a marker-conflicting flush still issues the write — it just matches 0 rows — and adds one [bodyFetches]
 *   read to resolve, then either throws under FAIL or reloads under IGNORE_OURS).
 */
class StorageQueries(val label: String) {
    val timestampChecks = LongAdder()
    val bodyFetches = LongAdder()
    val flushWrites = LongAdder()

    fun snapshot() = QuerySnapshot(label, timestampChecks.sum(), bodyFetches.sum(), flushWrites.sum())
}

data class QuerySnapshot(
    val label: String,
    val timestampChecks: Long,
    val bodyFetches: Long,
    val flushWrites: Long
) {
    val total: Long get() = timestampChecks + bodyFetches + flushWrites
}

/**
 * Simulated per-query DB latencies (milliseconds). All zero in "count" mode.
 */
data class QueryLatency(
    val timestampCheckMs: Long = 0,
    val bodyFetchMs: Long = 0,
    val flushMs: Long = 0
) {
    val enabled: Boolean get() = timestampCheckMs > 0 || bodyFetchMs > 0 || flushMs > 0
}

/**
 * A faithful, thread-safe stand-in for a TeamCity [CustomDataStorage] used for benchmarking.
 *
 * It models the two-phase DB access of the real DB-backed storage:
 *  - `refresh()` always checks the update marker (one query) and only re-loads the body when the marker moved;
 *  - `flush(...)` writes (one query) only when the in-memory data is dirty.
 *
 * Authoritative ("on-disk") state is kept separately from this instance's loaded view so that the
 * "fetch the body only if it changed" branch is exercised exactly as in production. Access is serialized
 * with a [ReentrantLock].
 *
 * This base class does not count anything — use it for storages whose DB load we don't care about (e.g. the
 * per-node expiration storage). [CountingFakeStorage] adds query counting for the global JWK cache.
 */
open class FakeStorage(
    private val latency: QueryLatency
) : CustomDataStorage {

    private val lock = ReentrantLock()

    // Authoritative "database" state.
    private val dbData: MutableMap<String, String> = HashMap()
    private val dbMarker = AtomicLong(0)

    // This instance's loaded view.
    private val localData: MutableMap<String, String> = HashMap()
    private var loaded = false
    private var loadedMarker = -1L
    private var dirty = false
    private var loadTimeMs = 0L

    /** DB-query hooks, called under the storage lock. No-ops here; [CountingFakeStorage] records them. */
    protected open fun onTimestampCheck() {}
    protected open fun onBodyFetch() {}
    protected open fun onFlushWrite() {}

    private fun sleep(ms: Long) {
        if (ms > 0) Thread.sleep(ms)
    }

    private fun loadFromDbLocked() {
        onBodyFetch()
        sleep(latency.bodyFetchMs)
        localData.clear()
        localData.putAll(dbData)
        loadedMarker = dbMarker.get()
        loaded = true
        loadTimeMs = System.currentTimeMillis()
        // A reload replaces the in-memory view with the persisted state, so any uncommitted local edits are
        // dropped (matches the real storage replacing its CustomData on refresh). Prevents a stale phantom flush
        // after a conflict-driven retry.
        dirty = false
    }

    override fun refresh() = lock.withLock {
        // Always one marker-check query (`select update_date ... part_num = 0`).
        onTimestampCheck()
        sleep(latency.timestampCheckMs)
        if (!loaded || loadedMarker != dbMarker.get()) {
            loadFromDbLocked()
        }
    }

    private fun ensureLoaded() {
        // getValue/getValues lazily load if never loaded.
        if (!loaded) loadFromDbLocked()
    }

    override fun getValues(): MutableMap<String, String>? = lock.withLock {
        ensureLoaded()
        if (localData.isEmpty()) HashMap() else HashMap(localData)
    }

    override fun getValue(key: String): String? = lock.withLock {
        ensureLoaded()
        localData[key]
    }

    override fun putValue(key: String, value: String?) = lock.withLock {
        if (value == null) localData.remove(key) else localData[key] = value
        dirty = true
    }

    override fun putValues(data: MutableMap<String, String>) = lock.withLock {
        localData.clear()
        localData.putAll(data)
        dirty = true
    }

    override fun updateValues(newOrChangedValues: MutableMap<String, String>, removedKeys: MutableSet<String>) = lock.withLock {
        localData.putAll(newOrChangedValues)
        removedKeys.forEach { if (!newOrChangedValues.containsKey(it)) localData.remove(it) }
        dirty = true
    }

    private fun flushLocked(mode: ConflictResolution) {
        if (!dirty) return

        // Models `doFlushData` -> `updateBody(cd, withUpdateMarkerCheck = mode != IGNORE_THEIRS)`.
        // With the marker check, the in-place UPDATE carries `... and update_date = :prevMarker`; if another
        // writer (here: a peer node, see [simulatePeerWrite]) bumped the marker since we loaded, it matches 0
        // rows -> conflict. IGNORE_THEIRS skips the check and overwrites unconditionally.
        val conflict = mode != ConflictResolution.IGNORE_THEIRS && loaded && loadedMarker != dbMarker.get()

        // The UPDATE batch is always issued (one write round-trip); on a conflict it simply matches 0 rows.
        onFlushWrite()
        sleep(latency.flushMs)

        if (conflict) {
            // doFlushData re-reads the current body from the DB to resolve the conflict (one more query).
            onBodyFetch()
            sleep(latency.bodyFetchMs)
            if (mode == ConflictResolution.FAIL) {
                // Surfaced to the cache, which refreshes and retries (jwkWrite / globalCleanup retry loops).
                throw CustomDataConflictException("conflict: storage updated by another writer since load")
            }
            // IGNORE_OURS: drop our changes, adopt the DB state. We did not write, so the marker is unchanged.
            localData.clear()
            localData.putAll(dbData)
            loadedMarker = dbMarker.get()
            dirty = false
            return
        }

        // Our write wins: publish and bump the authoritative marker.
        dbData.clear()
        dbData.putAll(localData)
        loadedMarker = dbMarker.incrementAndGet()
        dirty = false
    }

    override fun flush() = lock.withLock { flushLocked(ConflictResolution.IGNORE_OURS) }

    @Throws(CustomDataConflictException::class)
    override fun flush(conflictResolutionMode: ConflictResolution) = lock.withLock { flushLocked(conflictResolutionMode) }

    override fun putValuesAndFlush(data: MutableMap<String, String>) = lock.withLock {
        localData.clear(); localData.putAll(data); dirty = true; flushLocked(ConflictResolution.IGNORE_OURS)
    }

    override fun putValuesAndFlush(data: MutableMap<String, String>, conflictResolution: ConflictResolution) = lock.withLock {
        localData.clear(); localData.putAll(data); dirty = true; flushLocked(conflictResolution)
    }

    override fun scheduleFlush() = lock.withLock { flushLocked(ConflictResolution.IGNORE_OURS) }

    override fun clear() = lock.withLock {
        localData.clear()
        dirty = true
    }

    override fun isDirty(): Boolean = lock.withLock { dirty }

    override fun getDataLoadTime(): Date? = lock.withLock {
        if (loadTimeMs == 0L) null else Date(loadTimeMs)
    }

    override fun dispose() {
        // no-op
    }

    /**
     * Simulates another cluster node writing to the shared storage: it bumps the authoritative update
     * marker (and the body) without going through this instance, so this node's next [refresh] observes a
     * stale marker and issues the conditional body-fetch query — exactly the two-phase DB access being modelled.
     */
    fun simulatePeerWrite(key: String, value: String) = lock.withLock {
        dbData[key] = value
        dbMarker.incrementAndGet()
    }
}

/**
 * A [FakeStorage] that records its DB queries into [queries] — used for the global JWK cache, the only storage
 * whose DB load the benchmark reports.
 */
class CountingFakeStorage(
    private val queries: StorageQueries,
    latency: QueryLatency
) : FakeStorage(latency) {
    override fun onTimestampCheck() = queries.timestampChecks.increment()
    override fun onBodyFetch() = queries.bodyFetches.increment()
    override fun onFlushWrite() = queries.flushWrites.increment()
}
