package org.jetbrains.teamcity.builds.oidc.cache

import io.mockk.*
import jetbrains.buildServer.BaseTestCase
import jetbrains.buildServer.serverSide.CustomDataConflictException
import jetbrains.buildServer.serverSide.CustomDataStorage
import jetbrains.buildServer.serverSide.ProjectManager
import jetbrains.buildServer.serverSide.SProject
import jetbrains.buildServer.serverSide.TeamCityNode
import jetbrains.buildServer.serverSide.TeamCityNodes
import jetbrains.buildServer.serverSide.executors.ExecutorServices
import org.assertj.core.api.Assertions
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

class MultiNodeJWKCacheTest : BaseTestCase() {

    companion object {
        private const val NODE_ID = "node-1"
    }

    private val fixedNow = Instant.parse("2026-01-01T12:00:00Z")

    private lateinit var teamCityNodes: TeamCityNodes
    private lateinit var currentNode: TeamCityNode
    private lateinit var projectManager: ProjectManager
    private lateinit var rootProject: SProject
    private lateinit var executorServices: ExecutorServices
    private lateinit var normalExecutorService: ScheduledExecutorService
    private lateinit var clock: Clock
    private lateinit var jwkStorage: CustomDataStorage
    private lateinit var currentNodeStorage: CustomDataStorage

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        jwkStorage = mockk(relaxed = true)
        currentNodeStorage = mockk(relaxed = true)
        normalExecutorService = mockk(relaxed = true)
        rootProject = mockk {
            every { getCustomDataStorage("${OIDCConstants.JWKCache.STORAGE_ID_PREFIX}-jwk") } returns jwkStorage
            every { getCustomDataStorage("${OIDCConstants.JWKCache.STORAGE_ID_PREFIX}-$NODE_ID-expirations") } returns currentNodeStorage
        }
        currentNode = mockk {
            every { id } returns NODE_ID
            every { isMainNode } returns true
        }
        clock = mockk { every { instant() } returns fixedNow }
        teamCityNodes = mockk { every { currentNode } returns this@MultiNodeJWKCacheTest.currentNode }
        projectManager = mockk { every { rootProject } returns this@MultiNodeJWKCacheTest.rootProject }
        executorServices = mockk {
            every { normalExecutorService } returns this@MultiNodeJWKCacheTest.normalExecutorService
        }
    }

    private fun createCache() = MultiNodeJWKCache(
        teamCityNodes, projectManager, executorServices, clock
    )

    private fun mockNode(
        nodeId: String,
        isOnline: Boolean = true,
        lastActivityTime: Instant = fixedNow,
        storage: CustomDataStorage = mockk(relaxed = true)
    ): TeamCityNode {
        every { rootProject.getCustomDataStorage("${OIDCConstants.JWKCache.STORAGE_ID_PREFIX}-$nodeId-expirations") } returns storage
        return mockk {
            every { id } returns nodeId
            every { this@mockk.isOnline } returns isOnline
            every { this@mockk.isMainNode } returns false
            every { this@mockk.lastActivityTime } returns Date.from(lastActivityTime)
        }
    }

    // ---- init ----

    @Test
    fun init_mainNode_schedulesGlobalCleanupPeriodically() {
        createCache()

        verify { normalExecutorService.scheduleAtFixedRate(any(), 60L, 60L, TimeUnit.MINUTES) }
    }

    @Test
    fun init_secondaryNode_doesNotScheduleGlobalCleanup() {
        every { currentNode.isMainNode } returns false

        createCache()

        verify(exactly = 0) { normalExecutorService.scheduleAtFixedRate(any(), any(), any(), any()) }
    }

    // ---- destroy ----

    @Test
    fun destroy_mainNode_cancelsScheduledCleanup() {
        val cleanupTask = mockk<ScheduledFuture<*>>(relaxed = true)
        every { normalExecutorService.scheduleAtFixedRate(any(), any(), any(), any()) } returns cleanupTask

        createCache().destroy()

        verify { cleanupTask.cancel(false) }
    }

    @Test
    fun destroy_secondaryNode_doesNotFail() {
        every { currentNode.isMainNode } returns false

        // No task was scheduled, so destroy must be a no-op rather than throwing.
        createCache().destroy()
    }

    // ---- trackKey ----

    @Test
    fun trackKey_storesFreshExpirationToCurrentNodeStorage() {
        val expiresAt = fixedNow.plusSeconds(3600)

        createCache().trackKey("kid1", "{}", expiresAt)

        verify { currentNodeStorage.putValue("kid1", expiresAt.epochSecond.toString()) }
    }

    @Test
    fun trackKey_cleansUpStaleExpirationsFromCurrentNodeStorage() {
        val expiredEpoch = fixedNow.minusSeconds(100).epochSecond.toString()
        val validEpoch = fixedNow.plusSeconds(100).epochSecond.toString()
        every { currentNodeStorage.values } returns mapOf("expired-kid" to expiredEpoch, "valid-kid" to validEpoch)

        createCache().trackKey("new-kid", "{}", fixedNow.plusSeconds(3600))

        verify { currentNodeStorage.putValue("expired-kid", null) }
        verify(exactly = 0) { currentNodeStorage.putValue("valid-kid", null) }
    }

    @Test
    fun trackKey_flushesOverridingRemoteStateOfCurrentNodeStorage() {
        createCache().trackKey("kid1", "{}", fixedNow.plusSeconds(3600))

        verify { currentNodeStorage.flush(CustomDataStorage.ConflictResolution.IGNORE_THEIRS) }
    }

    @Test
    fun trackKey_refreshesAndStoresJwkInGlobalStorage() {
        every { jwkStorage.getValue("kid1") } returns null

        createCache().trackKey("kid1", """{"kid":"kid1"}""", fixedNow.plusSeconds(3600))

        verifyOrder {
            jwkStorage.refresh()
            jwkStorage.putValue("kid1", """{"kid":"kid1"}""")
            jwkStorage.flush(CustomDataStorage.ConflictResolution.FAIL)
        }
    }

    @Test
    fun trackKey_keyAlreadyExistsInJwkStorage_doesNotStoreOrFlush() {
        every { jwkStorage.getValue("kid1") } returns """{"kid":"kid1"}"""

        createCache().trackKey("kid1", """{"kid":"kid1"}""", fixedNow.plusSeconds(3600))

        verify(exactly = 0) { jwkStorage.putValue(any(), any()) }
        verify(exactly = 0) { jwkStorage.flush(any()) }
    }

    @Test
    fun trackKey_jwkStorageWriteConflict_retriesAndSucceeds() {
        every { jwkStorage.getValue("kid1") } returns null
        var flushCalls = 0
        every { jwkStorage.flush(CustomDataStorage.ConflictResolution.FAIL) } answers {
            if (++flushCalls == 1) throw CustomDataConflictException("conflict")
        }

        createCache().trackKey("kid1", "{}", fixedNow.plusSeconds(3600))

        verify(exactly = 2) { jwkStorage.refresh() }
        verify(exactly = 2) { jwkStorage.putValue("kid1", "{}") }
        verify(exactly = 2) { jwkStorage.flush(CustomDataStorage.ConflictResolution.FAIL) }
    }

    @Test
    fun trackKey_jwkStorageWriteConflict_keyAppearsOnRetry_doesNotStoreKeyAgain() {
        every { jwkStorage.getValue("kid1") } returnsMany listOf(null, "{}")
        every { jwkStorage.flush(CustomDataStorage.ConflictResolution.FAIL) } throws CustomDataConflictException("conflict")

        createCache().trackKey("kid1", "{}", fixedNow.plusSeconds(3600))

        verify(exactly = 1) { jwkStorage.putValue("kid1", "{}") }
        verify(exactly = 1) { jwkStorage.flush(CustomDataStorage.ConflictResolution.FAIL) }
    }

    @Test
    fun trackKey_allJwkStorageRetriesExhausted_throwsCustomDataConflictException() {
        every { jwkStorage.getValue("kid1") } returns null
        every { jwkStorage.flush(CustomDataStorage.ConflictResolution.FAIL) } throws CustomDataConflictException("conflict")

        val thrown = Assertions.catchThrowableOfType(CustomDataConflictException::class.java) {
            createCache().trackKey("kid1", "{}", fixedNow.plusSeconds(3600))
        }

        Assertions.assertThat(thrown).isNotNull()
        clearFailure()
    }

    @Test
    fun trackKey_coldCurrentNodeStorage_refreshesBeforeWriting() {
        every { currentNodeStorage.dataLoadTime } returns null

        createCache().trackKey("kid1", "{}", fixedNow.plusSeconds(3600))

        verifyOrder {
            currentNodeStorage.refresh()
            currentNodeStorage.putValue("kid1", any())
        }
    }

    @Test
    fun trackKey_warmCurrentNodeStorage_doesNotRefresh() {
        every { currentNodeStorage.dataLoadTime } returns Date.from(fixedNow)

        createCache().trackKey("kid1", "{}", fixedNow.plusSeconds(3600))

        verify(exactly = 0) { currentNodeStorage.refresh() }
        verify { currentNodeStorage.putValue("kid1", any()) }
        verify { currentNodeStorage.flush(CustomDataStorage.ConflictResolution.IGNORE_THEIRS) }
    }

    @Test
    fun trackKey_calledTwice_refreshesCurrentNodeStorageOnlyOnFirstCall() {
        every { currentNodeStorage.dataLoadTime } returnsMany listOf(null, Date.from(fixedNow))

        val cache = createCache()
        cache.trackKey("kid1", "{}", fixedNow.plusSeconds(3600))
        cache.trackKey("kid2", "{}", fixedNow.plusSeconds(3600))

        verify(exactly = 1) { currentNodeStorage.refresh() }
        verify(exactly = 2) { currentNodeStorage.flush(CustomDataStorage.ConflictResolution.IGNORE_THEIRS) }
    }

    // ---- fetchCachedJWKs ----

    @Test
    fun fetchCachedJWKs_refreshesAndReturnsValues() {
        every { jwkStorage.values } returns mapOf("k1" to "v1", "k2" to "v2")

        val result = createCache().fetchCachedJWKs()

        verify { jwkStorage.refresh() }
        Assertions.assertThat(result).containsExactlyInAnyOrderEntriesOf(mapOf("k1" to "v1", "k2" to "v2"))
    }

    @Test
    fun fetchCachedJWKs_noStoredValues_returnsEmptyMap() {
        every { jwkStorage.values } returns null

        val result = createCache().fetchCachedJWKs()

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun fetchCachedJWKs_filtersOutRevokedValues() {
        every { jwkStorage.values } returns mapOf("k1" to "v1", "k2" to "revoked:1234567890")

        val result = createCache().fetchCachedJWKs()

        Assertions.assertThat(result).containsExactlyInAnyOrderEntriesOf(mapOf("k1" to "v1"))
        Assertions.assertThat(result).doesNotContainKey("k2")
    }

    // ---- purge ----

    @Test
    fun purge_refreshesRevokesAllJwksAndFlushes() {
        every { jwkStorage.values } returns mapOf("k1" to "old-v1", "k2" to "old-v2")

        createCache().purge()

        val expectedValues = mapOf(
            "k1" to "revoked:${fixedNow.epochSecond}",
            "k2" to "revoked:${fixedNow.epochSecond}"
        )
        verify { jwkStorage.refresh() }
        verify { jwkStorage.putValuesAndFlush(expectedValues, CustomDataStorage.ConflictResolution.IGNORE_THEIRS) }
    }

    @Test
    fun purge_noStoredValues_flushesEmptyRevocationMap() {
        every { jwkStorage.values } returns null

        createCache().purge()

        verify { jwkStorage.putValuesAndFlush(emptyMap(), CustomDataStorage.ConflictResolution.IGNORE_THEIRS) }
    }

    @Test
    fun purge_clearsAndFlushesCurrentNodeStorage() {
        every { jwkStorage.values } returns emptyMap()

        createCache().purge()

        verify { currentNodeStorage.clear() }
        verify { currentNodeStorage.flush(CustomDataStorage.ConflictResolution.IGNORE_THEIRS) }
    }

    // ---- globalCleanup ----

    @Test
    fun globalCleanup_noStoredJwkValues_doesNotFlushJwkStorage() {
        every { teamCityNodes.nodes } returns emptyList()
        every { jwkStorage.values } returns null

        createCache().globalCleanup()

        verify(exactly = 0) { jwkStorage.flush(any()) }
        verify(exactly = 0) { jwkStorage.putValue(any(), any()) }
    }

    @Test
    fun globalCleanup_secondaryNode_throwsIllegalStateException() {
        every { currentNode.isMainNode } returns false
        val cache = createCache()

        val thrown = Assertions.catchThrowableOfType(IllegalStateException::class.java) { cache.globalCleanup() }

        Assertions.assertThat(thrown).isNotNull()
        clearFailure()
    }

    @Test
    fun globalCleanup_onlineNode_refreshesStorage() {
        val onlineStorage = mockk<CustomDataStorage>(relaxed = true) {
            every { values } returns mapOf("kid1" to fixedNow.plusSeconds(3600).epochSecond.toString())
        }
        val onlineNode = mockNode("node-2", isOnline = true, storage = onlineStorage)
        every { teamCityNodes.nodes } returns listOf(onlineNode)
        every { jwkStorage.values } returns mapOf("kid1" to "jwk-body")

        createCache().globalCleanup()

        verify { onlineStorage.refresh() }
    }

    @Test
    fun globalCleanup_orphanNode_refreshesStorage() {
        val expiredEpoch = fixedNow.minusSeconds(3600).epochSecond.toString()
        val validEpoch = fixedNow.plusSeconds(3600).epochSecond.toString()
        val orphanStorage = mockk<CustomDataStorage>(relaxed = true) {
            every { values } returns mapOf("expired-kid" to expiredEpoch, "valid-kid" to validEpoch)
        }
        val orphanNode = mockNode(
            "node-2",
            isOnline = false,
            lastActivityTime = fixedNow.minus(180, ChronoUnit.MINUTES),
            storage = orphanStorage
        )
        every { teamCityNodes.nodes } returns listOf(orphanNode)
        every { jwkStorage.values } returns mapOf("expired-kid" to "jwk1", "valid-kid" to "jwk2")

        createCache().globalCleanup()

        verify { orphanStorage.refresh() }
    }

    @Test
    fun globalCleanup_onlineNode_doesNotUpdateItsStorage() {
        val onlineStorage = mockk<CustomDataStorage>(relaxed = true) {
            every { values } returns mapOf("kid1" to fixedNow.plusSeconds(3600).epochSecond.toString())
        }
        val onlineNode = mockNode("node-2", isOnline = true, storage = onlineStorage)
        every { teamCityNodes.nodes } returns listOf(onlineNode)
        every { jwkStorage.values } returns mapOf("kid1" to "jwk-body")

        createCache().globalCleanup()

        verify(exactly = 0) { onlineStorage.updateValues(any(), any()) }
        verify(exactly = 0) { onlineStorage.flush(any()) }
    }

    @Test
    fun globalCleanup_recentlyOfflineNode_doesNotUpdateItsStorage() {
        val recentlyOfflineStorage = mockk<CustomDataStorage>(relaxed = true) {
            every { values } returns mapOf("kid1" to fixedNow.plusSeconds(3600).epochSecond.toString())
        }
        val recentlyOfflineNode = mockNode(
            "node-2",
            isOnline = false,
            lastActivityTime = fixedNow.minus(60, ChronoUnit.MINUTES),
            storage = recentlyOfflineStorage
        )
        every { teamCityNodes.nodes } returns listOf(recentlyOfflineNode)
        every { jwkStorage.values } returns mapOf("kid1" to "jwk-body")

        createCache().globalCleanup()

        verify(exactly = 0) { recentlyOfflineStorage.updateValues(any(), any()) }
        verify(exactly = 0) { recentlyOfflineStorage.flush(any()) }
    }

    @Test
    fun globalCleanup_orphanNode_deletesOnlyExpiredTimestamps() {
        val expiredEpoch = fixedNow.minusSeconds(3600).epochSecond.toString()
        val validEpoch = fixedNow.plusSeconds(3600).epochSecond.toString()
        val orphanStorage = mockk<CustomDataStorage>(relaxed = true) {
            every { values } returns mapOf("expired-kid" to expiredEpoch, "valid-kid" to validEpoch)
        }
        val orphanNode = mockNode(
            "node-2",
            isOnline = false,
            lastActivityTime = fixedNow.minus(180, ChronoUnit.MINUTES),
            storage = orphanStorage
        )
        every { teamCityNodes.nodes } returns listOf(orphanNode)
        every { jwkStorage.values } returns mapOf("expired-kid" to "jwk1", "valid-kid" to "jwk2")

        createCache().globalCleanup()

        verify { orphanStorage.updateValues(emptyMap(), setOf("expired-kid")) }
        verify { orphanStorage.flush(CustomDataStorage.ConflictResolution.IGNORE_THEIRS) }
        verify(exactly = 0) { orphanStorage.updateValues(any(), match { "valid-kid" in it }) }
    }

    @Test
    fun globalCleanup_revokedToken_deletedAfterRevocationGracePeriod() {
        // Both keys have live node references so they land in remainingKids.
        // The revocation grace period then decides which revoked key to drop.
        val nodeStorage = mockk<CustomDataStorage>(relaxed = true) {
            every { values } returns mapOf(
                "k-old" to fixedNow.plusSeconds(3600).epochSecond.toString(),
                "k-recent" to fixedNow.plusSeconds(3600).epochSecond.toString()
            )
        }
        val node = mockNode("node-2", isOnline = true, storage = nodeStorage)
        every { teamCityNodes.nodes } returns listOf(node)
        val oldRevokedAt = fixedNow.minus(20, ChronoUnit.MINUTES).epochSecond
        val recentRevokedAt = fixedNow.minus(5, ChronoUnit.MINUTES).epochSecond
        every { jwkStorage.values } returns mapOf(
            "k-old" to "revoked:$oldRevokedAt",
            "k-recent" to "revoked:$recentRevokedAt"
        )

        createCache().globalCleanup()

        verify { jwkStorage.putValue("k-old", null) }
        verify(exactly = 0) { jwkStorage.putValue("k-recent", null) }
    }

    @Test
    fun globalCleanup_revokedTokenWithInvalidTimestamp_deleted() {
        // A live node reference keeps the key in remainingKids, so deletion is driven
        // purely by the invalid revocation timestamp, not by the key being unreferenced.
        val nodeStorage = mockk<CustomDataStorage>(relaxed = true) {
            every { values } returns mapOf("k-corrupt" to fixedNow.plusSeconds(3600).epochSecond.toString())
        }
        val node = mockNode("node-2", isOnline = true, storage = nodeStorage)
        every { teamCityNodes.nodes } returns listOf(node)
        every { jwkStorage.values } returns mapOf("k-corrupt" to "revoked:whatever")

        createCache().globalCleanup()

        verify { jwkStorage.putValue("k-corrupt", null) }
    }

    @Test
    fun globalCleanup_unreferencedKey_deleted() {
        every { teamCityNodes.nodes } returns emptyList()
        every { jwkStorage.values } returns mapOf("k1" to "jwk-body")

        createCache().globalCleanup()

        verify { jwkStorage.putValue("k1", null) }
    }

    @Test
    fun globalCleanup_keysWithExpiredNodeReferences_deleted() {
        val nodeStorage = mockk<CustomDataStorage>(relaxed = true) {
            every { values } returns mapOf("k1" to fixedNow.minusSeconds(3600).epochSecond.toString())
        }
        val node = mockNode("node-2", isOnline = true, storage = nodeStorage)
        every { teamCityNodes.nodes } returns listOf(node)
        every { jwkStorage.values } returns mapOf("k1" to "jwk-body")

        createCache().globalCleanup()

        verify { jwkStorage.putValue("k1", null) }
    }

    @Test
    fun globalCleanup_jwkStorageWriteConflict_retriesAndSucceeds() {
        every { teamCityNodes.nodes } returns emptyList()
        every { jwkStorage.values } returns mapOf("k1" to "jwk-body")
        var flushCalls = 0
        every { jwkStorage.flush(CustomDataStorage.ConflictResolution.FAIL) } answers {
            if (++flushCalls == 1) throw CustomDataConflictException("conflict")
        }

        createCache().globalCleanup()

        verify(atLeast = 2) { jwkStorage.refresh() }
    }
}
