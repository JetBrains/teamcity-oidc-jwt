package org.jetbrains.teamcity.builds.oidc

import jetbrains.buildServer.serverSide.SBuildServer
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*

class OIDCSettingsTest : BaseTestCase() {
    private lateinit var store: OIDCGlobalSettingsStore
    private lateinit var buildServer: SBuildServer
    private lateinit var settings: OIDCSettings

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        store = mockk()
        every { store.get() } returns OIDCGlobalSettings()
        buildServer = mockk {
            every { rootUrl } returns "https://teamcity.example.com"
        }
        settings = OIDCSettings(store, buildServer)
    }

    @Test
    fun getOverrideIssuer_valuePresent_returnsValue() {
        every { store.get() } returns OIDCGlobalSettings(overrideIssuer = "https://custom.issuer.com")

        Assertions.assertThat(settings.getOverrideIssuer()).isEqualTo("https://custom.issuer.com")
    }

    @Test
    fun getOverrideIssuer_valueAbsent_returnsEmptyString() {
        every { store.get() } returns OIDCGlobalSettings(overrideIssuer = "")

        Assertions.assertThat(settings.getOverrideIssuer()).isEqualTo("")
    }

    @Test
    fun getDefaultIssuer_httpsUrl_appendsOidcPath() {
        Assertions.assertThat(settings.getDefaultIssuer()).isEqualTo("https://teamcity.example.com/app/oidc-jwt")
    }

    @Test
    fun getDefaultIssuer_httpUrl_replacedWithHttps() {
        every { buildServer.rootUrl } returns "http://teamcity.example.com"

        Assertions.assertThat(settings.getDefaultIssuer()).isEqualTo("https://teamcity.example.com/app/oidc-jwt")
    }

    @Test
    fun getDefaultIssuer_trailingSlash_removed() {
        every { buildServer.rootUrl } returns "https://teamcity.example.com/"

        Assertions.assertThat(settings.getDefaultIssuer()).isEqualTo("https://teamcity.example.com/app/oidc-jwt")
    }

    @Test
    fun getEffectiveIssuer_overridePresent_returnsOverride() {
        every { store.get() } returns OIDCGlobalSettings(overrideIssuer = "https://custom.issuer.com")

        Assertions.assertThat(settings.getEffectiveIssuer()).isEqualTo("https://custom.issuer.com")
    }

    @Test
    fun getEffectiveIssuer_overrideBlank_returnsDefault() {
        every { store.get() } returns OIDCGlobalSettings(overrideIssuer = "")

        Assertions.assertThat(settings.getEffectiveIssuer()).isEqualTo("https://teamcity.example.com/app/oidc-jwt")
    }

    @Test
    fun registerUpdateHandler_delegatesToStore() {
        val handler: () -> Unit = {}
        every { store.registerUpdateHandler(handler) } just Runs
        settings.registerUpdateHandler(handler)

        verify { store.registerUpdateHandler(handler) }
    }

    @Test
    fun unregisterUpdateHandler_delegatesToStore() {
        val handler: () -> Unit = {}
        every { store.unregisterUpdateHandler(handler) } just Runs
        settings.unregisterUpdateHandler(handler)

        verify { store.unregisterUpdateHandler(handler) }
    }

    @Test
    fun getActiveSignerId_valuePresent_returnsValue() {
        every { store.get() } returns OIDCGlobalSettings(activeSignerId = "my-signer")

        Assertions.assertThat(settings.getActiveSignerId()).isEqualTo("my-signer")
    }

    @Test
    fun getActiveSignerId_valueAbsent_returnsBuiltinDefault() {
        every { store.get() } returns OIDCGlobalSettings()

        Assertions.assertThat(settings.getActiveSignerId()).isEqualTo("builtin-rsa")
    }

    private fun captureSavedSettings(action: () -> Unit): OIDCGlobalSettings {
        val slot = slot<OIDCGlobalSettings>()
        every { store.save(capture(slot), any()) } just Runs
        action()
        return slot.captured
    }

    @Test
    fun updateSettings_updatesValuesInStore() {
        val saved = captureSavedSettings { settings.updateSettings("my-signer", "https://example.com") }

        Assertions.assertThat(saved).isEqualTo(
            OIDCGlobalSettings(activeSignerId = "my-signer", overrideIssuer = "https://example.com")
        )
    }

    @Test
    fun updateSettings_trimsBlankIssuerToEmpty() {
        val saved = captureSavedSettings { settings.updateSettings("my-signer", "   ") }

        Assertions.assertThat(saved).isEqualTo(
            OIDCGlobalSettings(activeSignerId = "my-signer", overrideIssuer = "")
        )
    }

    @Test
    fun updateSettings_nullIssuer_storesEmpty() {
        val saved = captureSavedSettings { settings.updateSettings("my-signer", null) }

        Assertions.assertThat(saved).isEqualTo(
            OIDCGlobalSettings(activeSignerId = "my-signer", overrideIssuer = "")
        )
    }

    @Test
    fun updateSettings_trimsIssuerWhitespace() {
        val saved = captureSavedSettings { settings.updateSettings("my-signer", "  https://example.com  ") }

        Assertions.assertThat(saved).isEqualTo(
            OIDCGlobalSettings(activeSignerId = "my-signer", overrideIssuer = "https://example.com")
        )
    }
}
