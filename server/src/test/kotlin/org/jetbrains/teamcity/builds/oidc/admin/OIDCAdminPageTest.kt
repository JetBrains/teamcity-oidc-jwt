package org.jetbrains.teamcity.builds.oidc.admin

import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerAdminSettings
import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.serverSide.auth.Permission
import jetbrains.buildServer.users.SUser
import jetbrains.buildServer.web.openapi.PagePlace
import jetbrains.buildServer.web.openapi.PagePlaces
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*
import javax.servlet.http.HttpServletRequest

class OIDCAdminPageTest : BaseTestCase() {
    private lateinit var pagePlaces: PagePlaces
    private lateinit var pluginDescriptor: PluginDescriptor
    private lateinit var registry: JWTSignerRegistry
    private lateinit var settings: OIDCSettings
    private lateinit var request: HttpServletRequest
    private lateinit var page: OIDCAdminPage

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        pagePlaces = mockk {
            every { getPlaceById(any()) } returns mockk<PagePlace>(relaxed = true)
        }
        pluginDescriptor = mockk {
            every { getPluginResourcesPath("oidcSignerSettings.jsp") } returns "/plugins/oidc-jwt/oidcSignerSettings.jsp"
            every { getPluginResourcesPath("signerSettings/missing-signer.jsp") } returns "/plugins/oidc-jwt/signerSettings/missing-signer.jsp"
        }
        registry = mockk {
            every { getSigners() } returns emptyMap()
        }
        settings = mockk {
            every { getDefaultIssuer() } returns "https://teamcity.example.com/app/oidc-jwt"
            every { getEffectiveIssuer() } returns "https://teamcity.example.com/app/oidc-jwt"
            every { getOverrideIssuer() } returns ""
            every { getActiveSignerId() } returns "builtin-rsa"
        }
        request = mockk()

        page = OIDCAdminPage(pagePlaces, pluginDescriptor, registry, settings)
    }

    private fun mockAuthorizedUser(): SUser = mockk {
        every { isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS) } returns true
    }

    private fun mockUnauthorizedUser(): SUser = mockk {
        every { isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS) } returns false
    }

    private fun stubSessionUser(user: SUser?) {
        every { request.getAttribute("USER_KEY") } returns user
    }

    private fun mockSigner(id: String, displayName: String, adminSettings: JWTSignerAdminSettings? = null): JWTSigner = mockk {
        every { getId() } returns id
        every { getDisplayName() } returns displayName
        every { getAdminSettings() } returns adminSettings
    }

    @Test
    fun getGroup_returnsIntegrationsGroup() {
        Assertions.assertThat(page.group).isEqualTo("Integrations")
    }

    @Test
    fun fillModel_populatesIssuerFields() {
        every { settings.getOverrideIssuer() } returns "https://custom.example.com"
        every { settings.getDefaultIssuer() } returns "https://teamcity.example.com/app/oidc-jwt"
        every { settings.getEffectiveIssuer() } returns "https://custom.example.com"

        val model = mutableMapOf<String, Any>()
        page.fillModel(model, request)

        Assertions.assertThat(model["issuer"]).isEqualTo("https://custom.example.com")
        Assertions.assertThat(model["defaultIssuer"]).isEqualTo("https://teamcity.example.com/app/oidc-jwt")
        Assertions.assertThat(model["effectiveIssuer"]).isEqualTo("https://custom.example.com")
    }

    @Test
    fun fillModel_constructsUrlsFromConstants() {
        val model = mutableMapOf<String, Any>()
        page.fillModel(model, request)

        Assertions.assertThat(model["jwksURL"]).isEqualTo("/app/oidc-jwt/.well-known/jwks?currentOnly=true")
        Assertions.assertThat(model["configURL"]).isEqualTo("/app/oidc-jwt/.well-known/openid-configuration.json")
        Assertions.assertThat(model["saveUrl"]).isEqualTo("/admin/oidcSignerSettings/save.html")
    }

    @Test
    fun fillModel_filenamesStripHttpsPrefix() {
        every { settings.getEffectiveIssuer() } returns "https://my.server.com/app/oidc-jwt"

        val model = mutableMapOf<String, Any>()
        page.fillModel(model, request)

        Assertions.assertThat(model["jwksFilename"]).isEqualTo("my.server.com/app/oidc-jwt_jwks.json")
        Assertions.assertThat(model["configFilename"]).isEqualTo("my.server.com/app/oidc-jwt_openid-configuration.json")
    }

    @Test
    fun fillModel_noSigners_onlyMissingActiveSignerView() {
        every { settings.getActiveSignerId() } returns "builtin-rsa"

        val model = mutableMapOf<String, Any>()
        page.fillModel(model, request)

        @Suppress("UNCHECKED_CAST")
        val signers = model["signers"] as List<SignerView>
        Assertions.assertThat(signers).hasSize(1)
        Assertions.assertThat(signers[0].id).isEqualTo("builtin-rsa")
        Assertions.assertThat(signers[0].displayName).isEqualTo("builtin-rsa (missing)")
    }

    @Test
    fun fillModel_signerWithoutAdminSettings_nullSettingsPathAndEmptySettings() {
        val signer = mockSigner("testId", "Test Signer")
        every { registry.getSigners() } returns mapOf("testId" to signer)
        every { settings.getActiveSignerId() } returns "testId"

        val model = mutableMapOf<String, Any>()
        page.fillModel(model, request)

        @Suppress("UNCHECKED_CAST")
        val signers = model["signers"] as List<SignerView>
        Assertions.assertThat(signers).hasSize(1)

        val view = signers[0]
        Assertions.assertThat(view.id).isEqualTo("testId")
        Assertions.assertThat(view.displayName).isEqualTo("Test Signer")
        Assertions.assertThat(view.paramPrefix).isEqualTo("testId.")
        Assertions.assertThat(view.errorPrefix).isEqualTo("signerError_testId_")
        Assertions.assertThat(view.settingsPagePath).isNull()
        Assertions.assertThat(view.settings).isEmpty()
    }

    @Test
    fun fillModel_signerWithAdminSettings_populatesSettingsAndPath() {
        val adminSettings = mockk<JWTSignerAdminSettings> {
            every { settingsPagePath } returns "signerSettings/test.jsp"
            every { fillSettingsModel(any()) } answers { invocation ->
                @Suppress("UNCHECKED_CAST")
                val settingsModel = invocation.invocation.args[0] as MutableMap<String, Any>
                settingsModel["keySize"] = 2048
                null
            }
        }
        val signer = mockSigner("test", "Test Signer", adminSettings)
        every { registry.getSigners() } returns mapOf("test" to signer)
        every { settings.getActiveSignerId() } returns "test"

        val model = mutableMapOf<String, Any>()
        page.fillModel(model, request)

        @Suppress("UNCHECKED_CAST")
        val signers = model["signers"] as List<SignerView>
        val view = signers[0]
        Assertions.assertThat(view.settingsPagePath).isEqualTo("signerSettings/test.jsp")
        Assertions.assertThat(view.settings).isEqualTo(mapOf("keySize" to 2048))
    }

    @Test
    fun fillModel_multipleSigners_allMappedInOrder() {
        val signer1 = mockSigner("first", "First Signer")
        val signer2 = mockSigner("second", "Second Signer")
        every { registry.getSigners() } returns linkedMapOf("first" to signer1, "second" to signer2)
        every { settings.getActiveSignerId() } returns "second"

        val model = mutableMapOf<String, Any>()
        page.fillModel(model, request)

        @Suppress("UNCHECKED_CAST")
        val signers = model["signers"] as List<SignerView>
        Assertions.assertThat(signers).hasSize(2)
        Assertions.assertThat(signers[0].id).isEqualTo("first")
        Assertions.assertThat(signers[1].id).isEqualTo("second")
        Assertions.assertThat(model["activeSignerId"]).isEqualTo("second")
    }

    @Test
    fun fillModel_activeSignerMissing_prependsMissingSignerView() {
        val signer1 = mockSigner("first", "First Signer")
        every { registry.getSigners() } returns linkedMapOf("first" to signer1)
        every { settings.getActiveSignerId() } returns "builtin-rsa"

        val model = mutableMapOf<String, Any>()
        page.fillModel(model, request)

        @Suppress("UNCHECKED_CAST")
        val signers = model["signers"] as List<SignerView>
        Assertions.assertThat(signers).hasSize(2)

        val missing = signers[0]
        Assertions.assertThat(missing.id).isEqualTo("builtin-rsa")
        Assertions.assertThat(missing.displayName).isEqualTo("builtin-rsa (missing)")
        Assertions.assertThat(missing.paramPrefix).isEqualTo("builtin-rsa.")
        Assertions.assertThat(missing.errorPrefix).isEqualTo("signerError_builtin-rsa_")
        Assertions.assertThat(missing.settingsPagePath).isEqualTo("/plugins/oidc-jwt/signerSettings/missing-signer.jsp")
        Assertions.assertThat(missing.settings).isEmpty()

        Assertions.assertThat(signers[1].id).isEqualTo("first")
        Assertions.assertThat(model["activeSignerId"]).isEqualTo("builtin-rsa")
    }

    @Test
    fun isAvailable_authorizedUser_returnsTrue() {
        stubSessionUser(mockAuthorizedUser())
        Assertions.assertThat(page.isAvailable(request)).isTrue()
    }

    @Test
    fun isAvailable_unauthorizedUser_returnsFalse() {
        stubSessionUser(mockUnauthorizedUser())
        Assertions.assertThat(page.isAvailable(request)).isFalse()
    }

    @Test
    fun isAvailable_noUser_returnsFalse() {
        stubSessionUser(null)
        Assertions.assertThat(page.isAvailable(request)).isFalse()
    }
}
