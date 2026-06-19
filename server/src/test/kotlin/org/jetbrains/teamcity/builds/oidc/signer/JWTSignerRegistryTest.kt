package org.jetbrains.teamcity.builds.oidc.signer

import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import jetbrains.buildServer.ExtensionsProvider
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*
import jetbrains.buildServer.plugins.PluginManager
import jetbrains.buildServer.plugins.PluginManagerListener
import jetbrains.buildServer.plugins.bean.PluginInfo
import jetbrains.buildServer.plugins.classLoaders.PluginInfoSearcher
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.util.EventDispatcher
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerUnavailableException
import java.time.Instant

class JWTSignerRegistryTest : BaseTestCase() {
    private abstract class MockSignerClass(val classId: String, val classDisplayName: String): JWTSigner {
        override fun getId(): String = classId
        override fun getDisplayName(): String = classDisplayName
        override fun makeJWT(build: SBuild?, claimsJSON: ByteArray, expiresAt: Instant): String = TODO("Should not be called")
        override fun getCurrentKeyPublicJWK(): String = TODO("Should not be called")
        override fun getJWKS(): String = TODO("Should not be called")
        override fun getSigningAlgorithms(): List<String?> = TODO("Should not be called")
    }

    private fun mockSigner(id: String, displayName: String): JWTSigner = mockk {
        every { getId() } returns id
        every { getDisplayName() } returns displayName
    }

    @Test
    fun init_registersUpdateHandlers() {
        val settings = mockk<OIDCSettings> {
            every { registerUpdateHandler(any()) } just Runs
        }
        val lifecycleEventDispatcher = mockk<EventDispatcher<PluginManagerListener>> {
            every { addListener(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns lifecycleEventDispatcher
        }

        val registry = JWTSignerRegistry(settings, mockk(), pluginManager, mockk())

        verify(exactly = 1) { settings.registerUpdateHandler(any()) }
        verify(exactly = 1) { lifecycleEventDispatcher.addListener(eq(registry)) }
    }

    @Test
    fun getSigners_usesServiceLocatorToLocateSigners() {
        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns emptyList()
        }
        val settings = mockk<OIDCSettings> {
            every { registerUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(any()) } just Runs
            }
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, mockk())

        registry.getSigners()

        verify(exactly = 1) { extensionsProvider.getExtensions(JWTSigner::class.java) }
    }

    @Test
    fun getSigners_returnsSignersSortedByDisplayName() {
        val signerA = mockSigner("id-f", "Alpha")
        val signerB = mockSigner("id-e", "Bravo")
        val signerC = mockSigner("id-d", "Charlie")

        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signerC, signerA, signerB)
        }
        val settings = mockk<OIDCSettings> {
            every { registerUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(any()) } just Runs
            }
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, mockk())

        val result = registry.getSigners()

        Assertions.assertThat(result.values.toList()).isEqualTo(listOf(signerA, signerB, signerC))
    }

    @Test
    fun getActiveSigner_usesCacheWhenActiveSignerUnchanged() {
        val signer = mockSigner("builtin-rsa", "Built-in RSA")
        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signer)
        }
        val settings = mockk<OIDCSettings> {
            every { getActiveSignerId() } returns "builtin-rsa"
            every { registerUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(any()) } just Runs
            }
        }
        val pluginInfoSearcher = mockk<PluginInfoSearcher> {
            every { findPluginInfoByClass(any()) } returns mockk<PluginInfo> {}
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, pluginInfoSearcher)

        val first = registry.getActiveSigner()
        val second = registry.getActiveSigner()

        Assertions.assertThat(first).isSameAs(second)
        verify(exactly = 1) { extensionsProvider.getExtensions(JWTSigner::class.java) }
    }

    @Test
    fun settingsUpdateHandler_invalidatesCacheOnSettingsUpdate() {
        val signerA = mockSigner("a", "Alpha")
        val signerB = mockSigner("b", "Bravo")
        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signerA, signerB)
        }
        val handlerSlot = slot<() -> Unit>()
        val settings = mockk<OIDCSettings> {
            every { getActiveSignerId() } returnsMany listOf("a", "b")
            every { registerUpdateHandler(capture(handlerSlot)) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(any()) } just Runs
            }
        }
        val pluginInfoSearcher = mockk<PluginInfoSearcher> {
            every { findPluginInfoByClass(any()) } returns mockk<PluginInfo> {}
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, pluginInfoSearcher)

        val first = registry.getActiveSigner()
        handlerSlot.captured.invoke()
        val second = registry.getActiveSigner()

        Assertions.assertThat(first).isSameAs(signerA)
        Assertions.assertThat(second).isSameAs(signerB)
        verify(exactly = 2) { extensionsProvider.getExtensions(JWTSigner::class.java) }
    }

    @Test
    fun pluginLifecycleEventHandler_invalidatesCacheWhenActiveSignerPluginResourcesAreFreed() {
        class MockSignerA: MockSignerClass("a", "Alpha")
        class MockSignerB: MockSignerClass("b", "Bravo")
        val signerA = MockSignerA()
        val signerB = MockSignerB()
        val signerAPluginInfo = mockk<PluginInfo> {
            every { uuid } returns "a-uuid"
        }
        val signerBPluginInfo = mockk<PluginInfo> {
            every { uuid } returns "b-uuid"
        }

        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signerA, signerB)
        }
        val handlerSlot = slot<PluginManagerListener>()
        val settings = mockk<OIDCSettings> {
            every { getActiveSignerId() } returnsMany listOf("a", "b")
            every { registerUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(capture(handlerSlot)) } just Runs
            }
        }
        val pluginInfoSearcher = mockk<PluginInfoSearcher> {
            every { findPluginInfoByClass(eq(MockSignerA::class.java)) } returns signerAPluginInfo
            every { findPluginInfoByClass(eq(MockSignerB::class.java)) } returns signerBPluginInfo
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, pluginInfoSearcher)

        val first = registry.getActiveSigner()
        handlerSlot.captured.pluginResourcesCleaned(signerAPluginInfo)
        val second = registry.getActiveSigner()

        Assertions.assertThat(first).isSameAs(signerA)
        Assertions.assertThat(second).isSameAs(signerB)
        verify(exactly = 2) { extensionsProvider.getExtensions(JWTSigner::class.java) }
    }

    @Test
    fun pluginLifecycleEventHandler_doesNotInvalidateCacheWhenOtherPluginResourcesAreFreed() {
        class MockSignerA: MockSignerClass("a", "Alpha")
        class MockSignerB: MockSignerClass("b", "Bravo")
        val signerA = MockSignerA()
        val signerB = MockSignerB()
        val signerAPluginInfo = mockk<PluginInfo> {
            every { uuid } returns "a-uuid"
        }
        val signerBPluginInfo = mockk<PluginInfo> {
            every { uuid } returns "b-uuid"
        }

        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signerA, signerB)
        }
        val handlerSlot = slot<PluginManagerListener>()
        val settings = mockk<OIDCSettings> {
            every { getActiveSignerId() } returns "a"
            every { registerUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(capture(handlerSlot)) } just Runs
            }
        }
        val pluginInfoSearcher = mockk<PluginInfoSearcher> {
            every { findPluginInfoByClass(eq(MockSignerA::class.java)) } returns signerAPluginInfo
            every { findPluginInfoByClass(eq(MockSignerB::class.java)) } returns signerBPluginInfo
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, pluginInfoSearcher)

        val first = registry.getActiveSigner()
        handlerSlot.captured.pluginResourcesCleaned(signerBPluginInfo)
        val second = registry.getActiveSigner()

        Assertions.assertThat(first).isSameAs(signerA)
        Assertions.assertThat(second).isSameAs(signerA)
        verify(exactly = 1) { extensionsProvider.getExtensions(JWTSigner::class.java) }
    }

    @Test
    fun getActiveSigner_throwsWhenActiveSignerNotFound() {
        val signer = mockSigner("a", "Alpha")
        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signer)
        }
        val settings = mockk<OIDCSettings> {
            every { getActiveSignerId() } returns "nonexistent"
            every { registerUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(any()) } just Runs
            }
        }
        val pluginInfoSearcher = mockk<PluginInfoSearcher> {
            every { findPluginInfoByClass(any()) } returns mockk<PluginInfo> {}
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, pluginInfoSearcher)

        Assertions.assertThatThrownBy {
            registry.getActiveSigner()
        }.isInstanceOf(JWTSignerUnavailableException::class.java)
    }

    @Test
    fun getActiveSigner_throwsWhenPluginInfoNotFound() {
        val signer = mockSigner("a", "Alpha")
        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signer)
        }
        val settings = mockk<OIDCSettings> {
            every { getActiveSignerId() } returns "a"
            every { registerUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(any()) } just Runs
            }
        }
        val pluginInfoSearcher = mockk<PluginInfoSearcher> {
            every { findPluginInfoByClass(any()) } returns null
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, pluginInfoSearcher)

        Assertions.assertThatThrownBy {
            registry.getActiveSigner()
        }.isInstanceOf(JWTSignerUnavailableException::class.java)
    }

    @Test
    fun destroy_invalidatesCacheSoGetActiveSignerThrows() {
        val signer = mockSigner("builtin-rsa", "Built-in RSA")
        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signer)
        }
        val lifecycleEventDispatcher = mockk<EventDispatcher<PluginManagerListener>> {
            every { addListener(any()) } just Runs
            every { removeListener(any()) } just Runs
        }
        val settings = mockk<OIDCSettings> {
            every { getActiveSignerId() } returns "builtin-rsa"
            every { registerUpdateHandler(any()) } just Runs
            every { unregisterUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns lifecycleEventDispatcher
        }
        val pluginInfoSearcher = mockk<PluginInfoSearcher> {
            every { findPluginInfoByClass(any()) } returns mockk<PluginInfo> {}
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, pluginInfoSearcher)

        registry.getActiveSigner()
        registry.destroy()

        Assertions.assertThatThrownBy {
            registry.getActiveSigner()
        }.isInstanceOf(JWTSignerException::class.java)
    }

    @Test
    fun destroy_deregistersHandlersRegisteredOnInit() {
        val handlerSlot = slot<() -> Unit>()
        val listenerSlot = slot<PluginManagerListener>()
        val lifecycleEventDispatcher = mockk<EventDispatcher<PluginManagerListener>> {
            every { addListener(capture(listenerSlot)) } just Runs
            every { removeListener(any()) } just Runs
        }
        val settings = mockk<OIDCSettings> {
            every { registerUpdateHandler(capture(handlerSlot)) } just Runs
            every { unregisterUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns lifecycleEventDispatcher
        }
        val registry = JWTSignerRegistry(settings, mockk(), pluginManager, mockk())

        registry.destroy()

        verify(exactly = 1) { settings.unregisterUpdateHandler(handlerSlot.captured) }
        verify(exactly = 1) { lifecycleEventDispatcher.removeListener(listenerSlot.captured) }
    }

    @Test
    fun pluginResourcesCleaned_invalidatesCacheWhenActiveSignerPluginMatches() {
        class MockSignerA: MockSignerClass("a", "Alpha")
        class MockSignerB: MockSignerClass("b", "Bravo")
        val signerA = MockSignerA()
        val signerB = MockSignerB()
        val signerAPluginInfo = mockk<PluginInfo> {
            every { uuid } returns "a-uuid"
        }
        val signerBPluginInfo = mockk<PluginInfo> {
            every { uuid } returns "b-uuid"
        }

        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signerA, signerB)
        }
        val settings = mockk<OIDCSettings> {
            every { getActiveSignerId() } returnsMany listOf("a", "b")
            every { registerUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(any()) } just Runs
            }
        }
        val pluginInfoSearcher = mockk<PluginInfoSearcher> {
            every { findPluginInfoByClass(eq(MockSignerA::class.java)) } returns signerAPluginInfo
            every { findPluginInfoByClass(eq(MockSignerB::class.java)) } returns signerBPluginInfo
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, pluginInfoSearcher)

        val first = registry.getActiveSigner()
        registry.pluginResourcesCleaned(signerAPluginInfo)
        val second = registry.getActiveSigner()

        Assertions.assertThat(first).isSameAs(signerA)
        Assertions.assertThat(second).isSameAs(signerB)
        verify(exactly = 2) { extensionsProvider.getExtensions(JWTSigner::class.java) }
    }

    @Test
    fun pluginResourcesCleaned_leavesCacheIntactWhenOtherPluginMatches() {
        class MockSignerA: MockSignerClass("a", "Alpha")
        class MockSignerB: MockSignerClass("b", "Bravo")
        val signerA = MockSignerA()
        val signerB = MockSignerB()
        val signerAPluginInfo = mockk<PluginInfo> {
            every { uuid } returns "a-uuid"
        }
        val signerBPluginInfo = mockk<PluginInfo> {
            every { uuid } returns "b-uuid"
        }

        val extensionsProvider = mockk<ExtensionsProvider> {
            every { getExtensions(JWTSigner::class.java) } returns listOf(signerA, signerB)
        }
        val settings = mockk<OIDCSettings> {
            every { getActiveSignerId() } returns "a"
            every { registerUpdateHandler(any()) } just Runs
        }
        val pluginManager = mockk<PluginManager> {
            every { pluginLifecycleEventDispatcher } returns mockk {
                every { addListener(any()) } just Runs
            }
        }
        val pluginInfoSearcher = mockk<PluginInfoSearcher> {
            every { findPluginInfoByClass(eq(MockSignerA::class.java)) } returns signerAPluginInfo
            every { findPluginInfoByClass(eq(MockSignerB::class.java)) } returns signerBPluginInfo
        }
        val registry = JWTSignerRegistry(settings, extensionsProvider, pluginManager, pluginInfoSearcher)

        val first = registry.getActiveSigner()
        registry.pluginResourcesCleaned(signerBPluginInfo)
        val second = registry.getActiveSigner()

        Assertions.assertThat(first).isSameAs(signerA)
        Assertions.assertThat(second).isSameAs(signerA)
        verify(exactly = 1) { extensionsProvider.getExtensions(JWTSigner::class.java) }
    }
}
