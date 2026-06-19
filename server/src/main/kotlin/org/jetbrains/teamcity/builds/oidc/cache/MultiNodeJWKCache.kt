package org.jetbrains.teamcity.builds.oidc.cache

import com.intellij.openapi.diagnostic.Logger
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.serverSide.CustomDataConflictException
import jetbrains.buildServer.serverSide.CustomDataStorage
import jetbrains.buildServer.serverSide.CustomDataStorage.ConflictResolution
import jetbrains.buildServer.serverSide.ProjectManager
import jetbrains.buildServer.serverSide.TeamCityNodes
import jetbrains.buildServer.serverSide.executors.ExecutorServices
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import org.jetbrains.teamcity.builds.oidc.util.tryRead
import org.jetbrains.teamcity.builds.oidc.util.tryWrite
import org.jetbrains.teamcity.builds.oidc.util.withTryLock
import java.time.Clock
import java.time.Duration
import java.time.Instant
import org.springframework.beans.factory.DisposableBean
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.collections.iterator
import kotlin.concurrent.withLock

/**
 * Implementation of JWK cache storage for distributed cases.
 *
 * Each TeamCity node has its own [CustomDataStorage] to store token expiration timestamps for tokens
 * issued by it.
 *
 * There's also a common storage for JWK bodies. All nodes can write to and read from it. The main node
 * is responsible for cleaning up unused public keys.
 *
 * Stored JWKs can be fetched with [fetchCachedJWKs] method. To prevent an excessive DB load, the JWKs map will only
 * be refreshed from the DB once every [OIDCConstants.JWKCache.FETCH_CACHE_EXPIRATION_MS] milliseconds.
 */
class MultiNodeJWKCache @JvmOverloads constructor(
    private val teamCityNodes: TeamCityNodes,
    private val projectManager: ProjectManager,
    executorServices: ExecutorServices,
    private val clock: Clock = Clock.systemUTC()
): JWKCache, DisposableBean {
    private val LOG = Logger.getInstance(Loggers.SERVER_CATEGORY + "." + this.javaClass.name)

    /**
     * A lock used to limit concurrent writes to the common JWK storage.
     * Read locks must only be taken by methods that don't make the storage dirty or flush it.
     * Whenever a method writes to the storage, it must acquire a write lock.
     */
    private val jwkStorageLock = ReentrantReadWriteLock()

    // Facilities for `fetchCachedJWKs`: we use snapshotting to reduce the load on DB-backed storage.
    private data class JWKSnapshot(
        val jwks: Map<String, String>,
        val expirationNanos: Long
    )
    // The lock used to limit concurrent refreshes from `fetchCachedJWKs`
    private val jwkSnapshotFetchRefreshLock = ReentrantLock()
    private val jwkSnapshot: AtomicReference<JWKSnapshot?> = AtomicReference(null)

    private val currentNode = teamCityNodes.currentNode
    private val currentNodeID = currentNode.id
    private val currentNodeStorageWriteLock = ReentrantLock()
    private val openedNodeStorages = ConcurrentHashMap<String, CustomDataStorage>()

    /**
     * Handle to the recurring cleanup task scheduled on TeamCity's shared executor. Kept so it can be
     * cancelled on [destroy]; otherwise the task (and this instance, via the bound method reference)
     * would outlive the plugin and pin its classloader.
     */
    private val cleanupTask: ScheduledFuture<*>?

    init {
        // Schedule cleanup on main node
        cleanupTask = if (currentNode.isMainNode) {
            executorServices.normalExecutorService.scheduleAtFixedRate(
                {
                    try {
                        globalCleanup()
                    } catch (e: Exception) {
                        LOG.error("Failed to run global cleanup", e)
                    }
                },
                OIDCConstants.JWKCache.CLEANUP_INTERVAL_MINUTES,
                OIDCConstants.JWKCache.CLEANUP_INTERVAL_MINUTES,
                TimeUnit.MINUTES
            )
        } else {
            null
        }
    }

    override fun destroy() {
        cleanupTask?.cancel(false)
        openedNodeStorages.clear()
    }

    /**
     * Shared storage for JWK bodies.
     *
     * Must be accessed with [jwkStorageLock] to prevent concurrent access issues.
     */
    private val jwkStorage: CustomDataStorage by lazy {
        projectManager.rootProject.getCustomDataStorage("${OIDCConstants.JWKCache.STORAGE_ID_PREFIX}-jwk")
    }

    /**
     * Returns a timestamp storage for a given node.
     */
    private fun nodeStorage(nodeId: String): CustomDataStorage =
        openedNodeStorages.getOrPut(nodeId) {
            projectManager.rootProject.getCustomDataStorage("${OIDCConstants.JWKCache.STORAGE_ID_PREFIX}-$nodeId-expirations")
        }

    /**
     * Storage for expiration timestamps for tokens issued by the current node.
     *
     * Must be accessed with [currentNodeStorageWriteLock] to prevent concurrent access issues.
     */
    private val currentNodeStorage by lazy {
        nodeStorage(currentNodeID)
    }

    /**
     * Generates a [JWKSnapshot] from a custom storage values map, filtering out revoked JWKs.
     */
    private fun prepareSnapshot(jwks: Map<String, String>?): JWKSnapshot {
        val filtered = jwks?.filter { !it.value.startsWith(OIDCConstants.JWKCache.REVOCATION_PREFIX) }
        val expiration = System.nanoTime() + (OIDCConstants.JWKCache.FETCH_CACHE_EXPIRATION_MS * 1_000_000L)
        return JWKSnapshot(filtered ?: emptyMap(), expiration)
    }

    /**
     * JWK storage strategy resolution conflict: try flushing with FAIL (to track conflicts) N times, refresh before each try.
     */
    private inline fun jwkWrite(action: (CustomDataStorage) -> Boolean) = jwkStorageLock.tryWrite(30L) {
        repeat(OIDCConstants.JWKCache.MAX_JWK_WRITE_RETRIES) { attempt ->
            try {
                jwkStorage.refresh()
                val result = action(jwkStorage)
                if (result) jwkStorage.flush(CustomDataStorage.ConflictResolution.FAIL)
                // Update the snapshot on a successful write. Doesn't matter much if it will be overwritten by readers,
                // so no lock.
                jwkSnapshot.set(prepareSnapshot(jwkStorage.values))
                return@tryWrite
            } catch (e: CustomDataConflictException) {
                if (attempt == OIDCConstants.JWKCache.MAX_JWK_WRITE_RETRIES - 1) throw e
            }
        }
    }

    /**
     * Updates the expiration timestamp for a given JWK, adding it to the JWK cache if missing.
     *
     * @param kid The key ID of the JWK to update.
     * @param jwkJson The JSON representation of the JWK.
     * @param expiresAt The instant at which the issued JWT expires.
     */
    override fun trackKey(kid: String, jwkJson: String, expiresAt: Instant) {
        // Update expiration timestamp
        currentNodeStorageWriteLock.withLock {
            if (currentNodeStorage.dataLoadTime == null) currentNodeStorage.refresh()
            // Save the new expiration first
            currentNodeStorage.putValue(kid, expiresAt.epochSecond.toString())

            // Filter expired key references
            val now = clock.instant().epochSecond
            currentNodeStorage.values?.filter<String, String> { now >= it.value.toLong() }
                ?.forEach { (k, _) -> currentNodeStorage.putValue(k, null) }

            // Save the updated expiration
            currentNodeStorage.flush(ConflictResolution.IGNORE_THEIRS)
        }

        // Put the JWK if not present. We're doing this after the expiration timestamp to improve
        // the chances of global cleanup to notice the updated expiration status.
        // TODO Maybe `jwkWrite` should use a distributed lock instead of retries?
        jwkWrite { jwkStorage ->
            if (jwkStorage.getValue(kid) != null) {
                // Key already exists, do not flush
                return@jwkWrite false
            }
            jwkStorage.putValue(kid, jwkJson)
            true
        }
    }

    /**
     * Returns the current local snapshot of the JWK cache.
     *
     * If the snapshot is older than [OIDCConstants.JWKCache.FETCH_CACHE_EXPIRATION_MS],
     * a new snapshot is fetched and returned.
     */
    override fun fetchCachedJWKs(): Map<String, String> {
        val currentSnapshot = jwkSnapshot.get()
        if (currentSnapshot != null && currentSnapshot.expirationNanos > System.nanoTime()) {
            return currentSnapshot.jwks
        }

        jwkSnapshotFetchRefreshLock.withTryLock(5L) {
            // Double-check before taking `jwkStorageLock`
            val lockedSnapshot = jwkSnapshot.get()
            if (lockedSnapshot != null && lockedSnapshot.expirationNanos > System.nanoTime()) {
                return lockedSnapshot.jwks
            }

            jwkStorageLock.tryRead(5L) {
                jwkStorage.refresh()
                val newSnapshot = prepareSnapshot(jwkStorage.values)

                jwkSnapshot.set(newSnapshot)
                return newSnapshot.jwks
            }
        }
    }

    /**
     * Revokes all JWKs from the global cache.
     *
     * When a JWK is revoked, it will be marked as expired and will not be returned by [fetchCachedJWKs].
     * Technically, revoked JWK KIDs (but not their bodies) will still be stored until cleaned up by [globalCleanup].
     */
    override fun purge() {
        // No need for retries here, we override the entire storage.
        jwkStorageLock.tryWrite(30L) {
            // Override existing JWKs with a revocation flag.
            val now = clock.instant()
            jwkStorage.refresh()
            jwkStorage.putValuesAndFlush(
                jwkStorage.values?.map { it.key to OIDCConstants.JWKCache.REVOCATION_PREFIX + now.epochSecond }?.toMap() ?: emptyMap(),
                CustomDataStorage.ConflictResolution.IGNORE_THEIRS
            )
            // Reset the local snapshot
            jwkSnapshot.set(null)
        }

        currentNodeStorageWriteLock.withLock {
            // Also, clear our own storage since none of the JWKs stored there are valid anymore.
            currentNodeStorage.clear()
            currentNodeStorage.flush(CustomDataStorage.ConflictResolution.IGNORE_THEIRS)
        }
    }

    /**
     * A periodic cleanup task that removes expired or revoked JWKs from the global cache.
     *
     * It also cleans up storages owned by nodes that are offline for too long.
     */
    fun globalCleanup() {
        if (!currentNode.isMainNode) {
            throw IllegalStateException("Only the main node can perform global cleanup")
        }

        // We cannot reuse jwkWrite helper here because we need more granular locking
        repeat(OIDCConstants.JWKCache.MAX_JWK_WRITE_RETRIES) { attempt ->
            val now = clock.instant()
            val offlineNodeGracePeriodEnd = now.minus(Duration.ofMinutes(OIDCConstants.JWKCache.OFFLINE_NODE_GRACE_PERIOD_MINUTES))
            val revocationGracePeriodEnd = now.minus(Duration.ofMinutes(OIDCConstants.JWKCache.REVOCATION_GRACE_PERIOD_MINUTES))

            val remainingKids = mutableSetOf<String>()

            // Previously, we locked current storage here for the entire cleanup process. However, the current node
            // will never meet the orphaned node criteria (unless something goes really wrong), so it's safe to assume
            // we only want to add the current node's KIDs to the remaining list.
            currentNodeStorageWriteLock.withLock {
                if (currentNodeStorage.dataLoadTime == null) currentNodeStorage.refresh()
                currentNodeStorage.values?.forEach { remainingKids.add(it.key) }
            }

            // Perform orphaned storages cleanup: for each node that's offline for too long, remove its timestamps
            // if those are expired.
            for (node in teamCityNodes.nodes) {
                // Skip the current node as we already processed it above
                if (node.id == currentNodeID) continue

                val storage = nodeStorage(node.id)
                storage.refresh()

                val entries = storage.values ?: continue
                val nodeIsGone = !node.isOnline
                        && node.lastActivityTime.toInstant().isBefore(offlineNodeGracePeriodEnd)

                // If this node is alive and well, no need to touch its storage. But we still want to delete
                // unused keys from the global store, so only consider keys as remaining if the timestamps
                // are not expired.
                if (!nodeIsGone) {
                    remainingKids.addAll(entries.filter {
                        it.value.toLongOrNull()
                            ?.let { ts -> now.isBefore(Instant.ofEpochSecond(ts)) } ?: false
                    }.keys)
                    continue
                }

                // If this node is offline for too long, remove expired timestamps
                val orphanExpiredKids = mutableSetOf<String>()
                for ((kid, value) in entries) {
                    val expiry = value.toLongOrNull()?.let { Instant.ofEpochSecond(it) } ?: continue
                    if (now.isAfter(expiry)) {
                        orphanExpiredKids.add(kid)
                    } else {
                        remainingKids.add(kid)
                    }
                }

                // Clean up orphaned storage
                if (orphanExpiredKids.isNotEmpty()) {
                    storage.updateValues(emptyMap(), orphanExpiredKids)
                    storage.flush(ConflictResolution.IGNORE_THEIRS)
                }
            }

            // Now that we've cleaned up orphaned storages, drop JWKs that are no longer needed
            // (== no nodes have valid expiration timestamps referring to them or the revocation timeout passed).
            try {
                jwkStorageLock.tryWrite(3L) {
                    jwkStorage.refresh()
                    val storedJWKs = jwkStorage.values ?: return

                    // Drop the revoked JWKs as well (once they have passed the revocation grace period).
                    val revokedAfterGrace = storedJWKs.filter { entry ->
                        if (!entry.value.startsWith(OIDCConstants.JWKCache.REVOCATION_PREFIX)) return@filter false

                        val revokedAt = entry.value
                            .removePrefix(OIDCConstants.JWKCache.REVOCATION_PREFIX)
                            .toLongOrNull()
                            ?.let { Instant.ofEpochSecond(it) }
                            ?: return@filter true

                        revokedAt.isBefore(revocationGracePeriodEnd)
                    }.keys
                    val kidsToRemove = (storedJWKs.keys - remainingKids) + revokedAfterGrace
                    kidsToRemove.forEach { jwkStorage.putValue(it, null) }

                    // Save the changes
                    jwkStorage.flush(CustomDataStorage.ConflictResolution.FAIL)
                    // Reset the local snapshot
                    jwkSnapshot.set(null)
                    return
                }
            } catch (e: CustomDataConflictException) {
                if (attempt == OIDCConstants.JWKCache.MAX_JWK_WRITE_RETRIES - 1) throw e
            }
        }
    }
}
