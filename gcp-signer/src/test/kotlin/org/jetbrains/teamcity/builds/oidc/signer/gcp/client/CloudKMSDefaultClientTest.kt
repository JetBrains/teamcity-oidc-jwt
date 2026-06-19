package org.jetbrains.teamcity.builds.oidc.signer.gcp.client

import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSSettings
import org.jetbrains.teamcity.builds.oidc.signer.gcp.JWTKeyVersion
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSServiceAccountKeyNotProvidedException
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*

class CloudKMSDefaultClientTest : BaseTestCase() {

    private data class FactoryCall(
        val credentials: GCPCredentials,
        val gcpEndpoint: String?,
        val timeoutSeconds: Long,
        val maxAttempts: Int,
    )

    private lateinit var credentials: GCPCredentials
    private lateinit var settings: CloudKMSSettings
    private lateinit var factoryCalls: MutableList<FactoryCall>
    private lateinit var factoryClients: ArrayDeque<CloudKMSClient>
    private lateinit var factory: CloudKMSClientFactory
    private lateinit var defaultClient: CloudKMSDefaultClient
    private lateinit var updateHandler: () -> Unit

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        credentials = GCPCredentials.Environment()
        settings = mockk {
            every { getCredentials() } returns credentials
            every { getGCPEndpoint() } returns "kms.example.com:443"
            every { getKeyResourceName() } returns "projects/p/locations/global/keyRings/r/cryptoKeys/k"
            every { registerUpdateHandler(any()) } just Runs
        }

        factoryCalls = mutableListOf()
        factoryClients = ArrayDeque()
        factoryClients.add(mockk())

        factory = CloudKMSClientFactory { c, endpoint, timeout, attempts ->
            factoryCalls.add(FactoryCall(c, endpoint, timeout, attempts))
            check(factoryClients.isNotEmpty()) { "factory invoked more times than clients enqueued" }
            factoryClients.removeFirst()
        }

        defaultClient = CloudKMSDefaultClient(settings, factory)

        val handlerSlot = slot<() -> Unit>()
        verify { settings.registerUpdateHandler(capture(handlerSlot)) }
        updateHandler = handlerSlot.captured
    }

    @Test
    fun init_registersSettingsUpdateHandler() {
        verify { settings.registerUpdateHandler(any()) }
    }

    @Test
    fun currentClient_emptyCache_buildsClientWithSettingsAndDefaults() {
        val expected = factoryClients.first()

        val actual = defaultClient.currentClient()

        Assertions.assertThat(actual).isSameAs(expected)
        Assertions.assertThat(factoryCalls).hasSize(1)
        val call = factoryCalls.single()
        Assertions.assertThat(call.credentials).isSameAs(credentials)
        Assertions.assertThat(call.gcpEndpoint).isEqualTo("kms.example.com:443")
        Assertions.assertThat(call.timeoutSeconds).isEqualTo(15L)
        Assertions.assertThat(call.maxAttempts).isEqualTo(3)
    }

    @Test
    fun currentClient_secondCall_returnsCachedInstance() {
        val first = defaultClient.currentClient()
        val second = defaultClient.currentClient()

        Assertions.assertThat(first).isSameAs(second)
        Assertions.assertThat(factoryCalls).hasSize(1)
    }

    @Test
    fun settingsUpdate_clearsClientCacheAndClosesOldClient() {
        val clientA = factoryClients.first()
        val clientB: CloudKMSClient = mockk()
        factoryClients.addLast(clientB)

        val firstResult = defaultClient.currentClient()
        Assertions.assertThat(firstResult).isSameAs(clientA)

        every { clientA.close() } just Runs
        updateHandler.invoke()

        verify { clientA.close() }

        val secondResult = defaultClient.currentClient()
        Assertions.assertThat(secondResult).isSameAs(clientB)
        Assertions.assertThat(factoryCalls).hasSize(2)
    }

    @Test
    fun settingsUpdate_clearsKeyCache() {
        val clientA = factoryClients.first()
        val clientB: CloudKMSClient = mockk()
        factoryClients.addLast(clientB)

        val versionA = mockk<JWTKeyVersion>()
        val versionB = mockk<JWTKeyVersion>()
        every { clientA.resolveKeyVersion("k1") } returns versionA
        every { clientB.resolveKeyVersion("k1") } returns versionB
        every { clientA.close() } just Runs

        Assertions.assertThat(defaultClient.getKeyVersion("k1", force = false)).isSameAs(versionA)

        updateHandler.invoke()

        Assertions.assertThat(defaultClient.getKeyVersion("k1", force = false)).isSameAs(versionB)
        verify(exactly = 1) { clientA.resolveKeyVersion("k1") }
        verify(exactly = 1) { clientB.resolveKeyVersion("k1") }
    }

    @Test
    fun getLatestKeyVersion_emptyCache_resolvesFromSettingsResourceName() {
        val client = factoryClients.first()
        val version = mockk<JWTKeyVersion>()
        every { settings.getKeyResourceName() } returns "projects/p/locations/global/keyRings/r/cryptoKeys/configured"
        every { client.resolveKeyVersion("projects/p/locations/global/keyRings/r/cryptoKeys/configured") } returns version

        val result = defaultClient.getLatestKeyVersion(force = false)

        Assertions.assertThat(result).isSameAs(version)
        verify { client.resolveKeyVersion("projects/p/locations/global/keyRings/r/cryptoKeys/configured") }
    }

    @Test
    fun getLatestKeyVersion_settingsReturnsNull_throws() {
        val client = factoryClients.first()
        every { settings.getKeyResourceName() } returns null

        Assertions.assertThatThrownBy {
            defaultClient.getLatestKeyVersion(force = false)
        }.isInstanceOf(CloudKMSServiceAccountKeyNotProvidedException::class.java)

        verify { settings.getKeyResourceName() }
        verify(exactly = 0) { client.resolveKeyVersion(any()) }
    }

    @Test
    fun getLatestKeyVersion_secondCall_returnsCachedValue() {
        val client = factoryClients.first()
        val version = mockk<JWTKeyVersion>()
        every { client.resolveKeyVersion(any()) } returns version

        val first = defaultClient.getLatestKeyVersion(force = false)
        val second = defaultClient.getLatestKeyVersion(force = false)

        Assertions.assertThat(first).isSameAs(second)
        verify(exactly = 1) { client.resolveKeyVersion(any()) }
    }

    @Test
    fun getKeyVersion_sameResourceName_returnsCachedValue() {
        val client = factoryClients.first()
        val version = mockk<JWTKeyVersion>()
        every { client.resolveKeyVersion("k1") } returns version

        val first = defaultClient.getKeyVersion("k1", force = false)
        val second = defaultClient.getKeyVersion("k1", force = false)

        Assertions.assertThat(first).isSameAs(second)
        verify(exactly = 1) { client.resolveKeyVersion("k1") }
    }

    @Test
    fun getKeyVersion_force_bypassesCache() {
        val client = factoryClients.first()
        val v1 = mockk<JWTKeyVersion>()
        val v2 = mockk<JWTKeyVersion>()
        every { client.resolveKeyVersion("k1") } returns v1

        val cached = defaultClient.getKeyVersion("k1", force = false)
        Assertions.assertThat(cached).isSameAs(v1)

        every { client.resolveKeyVersion("k1") } returns v2
        val refreshed = defaultClient.getKeyVersion("k1", force = true)

        Assertions.assertThat(refreshed).isSameAs(v2)
        verify(exactly = 2) { client.resolveKeyVersion("k1") }
    }

    @Test
    fun getKeyVersion_resolvesViaCurrentClient() {
        val client = factoryClients.first()
        val version = mockk<JWTKeyVersion>()
        every { client.resolveKeyVersion("explicit-name") } returns version

        val result = defaultClient.getKeyVersion("explicit-name", force = false)

        Assertions.assertThat(result).isSameAs(version)
        verify(exactly = 1) { client.resolveKeyVersion("explicit-name") }
    }

    @Test
    fun getKeyVersion_force_updatesCacheForSubsequentCalls() {
        val client = factoryClients.first()
        val v1 = mockk<JWTKeyVersion>()
        val v2 = mockk<JWTKeyVersion>()
        val v3 = mockk<JWTKeyVersion>()

        every { client.resolveKeyVersion("k1") } returns v1
        Assertions.assertThat(defaultClient.getKeyVersion("k1", force = false)).isSameAs(v1)

        every { client.resolveKeyVersion("k1") } returns v2
        Assertions.assertThat(defaultClient.getKeyVersion("k1", force = true)).isSameAs(v2)

        every { client.resolveKeyVersion("k1") } returns v3
        Assertions.assertThat(defaultClient.getKeyVersion("k1", force = false)).isSameAs(v2)

        verify(exactly = 2) { client.resolveKeyVersion("k1") }
    }

    @Test
    fun resolve_delegatesToCurrentClient() {
        val client = factoryClients.first()
        val version = mockk<JWTKeyVersion>()
        every { client.resolveKeyVersion("rn") } returns version

        val result = defaultClient.resolve("rn")

        Assertions.assertThat(result).isSameAs(version)
        verify { client.resolveKeyVersion(eq("rn")) }
    }

    @Test
    fun sign_delegatesToCurrentClient() {
        val client = factoryClients.first()
        val version = mockk<JWTKeyVersion>()
        val payload = byteArrayOf(1, 2, 3, 4)
        every { client.sign(version, payload) } returns "sig"

        val result = defaultClient.sign(version, payload)

        Assertions.assertThat(result).isEqualTo("sig")
        verify { client.sign(eq(version), eq(payload)) }
    }

    @Test
    fun destroy_closesCurrentClient() {
        val client = factoryClients.first()
        every { client.close() } returns Unit
        defaultClient.currentClient()
        defaultClient.destroy()
        verify { client.close() }
    }

    @Test
    fun destroy_blocksClientFetching() {
        val client = factoryClients.first()
        every { client.close() } returns Unit
        defaultClient.currentClient()
        defaultClient.destroy()
        Assertions.assertThatThrownBy { defaultClient.currentClient() }.isInstanceOf(IllegalStateException::class.java)
    }
}
