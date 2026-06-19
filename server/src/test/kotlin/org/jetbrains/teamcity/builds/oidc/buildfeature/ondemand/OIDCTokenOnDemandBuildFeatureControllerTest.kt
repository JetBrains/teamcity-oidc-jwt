package org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand

import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import jetbrains.buildServer.controllers.MockRequest
import jetbrains.buildServer.controllers.MockResponse
import jetbrains.buildServer.controllers.admin.projects.EditBuildTypeForm
import jetbrains.buildServer.serverSide.SBuildType
import jetbrains.buildServer.serverSide.SProject
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.web.openapi.WebControllerManager
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*
import org.springframework.web.servlet.ModelAndView

class OIDCTokenOnDemandBuildFeatureControllerTest : BaseTestCase() {

    private val pluginResourcesPrefix = "/plugins/oidc-jwt/resources/"

    private lateinit var descriptor: PluginDescriptor
    private lateinit var web: WebControllerManager
    private lateinit var settings: OIDCSettings
    private lateinit var controller: OIDCTokenOnDemandBuildFeatureController
    private lateinit var request: MockRequest
    private lateinit var response: MockResponse

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        descriptor = mockk {
            every { getPluginResourcesPath(any()) } answers { invocation ->
                pluginResourcesPrefix + invocation.invocation.args[0]
            }
        }
        web = mockk(relaxed = true)
        settings = mockk {
            every { getEffectiveIssuer() } returns "https://issuer.example.com"
        }
        request = MockRequest()
        response = MockResponse()

        controller = OIDCTokenOnDemandBuildFeatureController(descriptor, web, settings)
    }

    private fun handleRequest(): ModelAndView =
        controller.handleRequestInternal(request, response) ?: error("Controller returned null ModelAndView")

    @Test
    fun init_registersControllerAtCorrectPath() {
        verify { web.registerController(
            eq("${pluginResourcesPrefix}oidcTokenOnDemandBuildFeature.html"),
            eq(controller)
        ) }
    }

    @Test
    fun doHandle_usesCorrectJspView() {
        val mv = handleRequest()

        Assertions.assertThat(mv.viewName).isEqualTo("${pluginResourcesPrefix}oidcTokenOnDemandBuildFeature.jsp")
    }

    @Test
    fun doHandle_happyPath_populatesAllModelValues() {
        val rootProject = mockk<SProject> {
            every { projectId } returns "_Root"
            every { parentProject } returns null
        }
        val project = mockk<SProject> {
            every { projectId } returns "MyProject"
            every { parentProject } returns rootProject
        }
        val buildType = mockk<SBuildType> {
            every { this@mockk.project } returns project
            every { buildTypeId } returns "bt1"
        }
        val buildForm = mockk<EditBuildTypeForm> {
            every { settingsBuildType } returns buildType
        }
        request.setAttribute("buildForm", buildForm)

        val mv = handleRequest()

        Assertions.assertThat(mv.model["issuer"]).isEqualTo("https://issuer.example.com")
        Assertions.assertThat(mv.model["sub"]).isEqualTo("_Root:MyProject:bt1")
        Assertions.assertThat(mv.model["jwksURL"]).isEqualTo("/app/oidc-jwt/.well-known/jwks?currentOnly=true")
        Assertions.assertThat(mv.model["jwksFilename"]).isEqualTo("issuer.example.com_jwks.json")
        Assertions.assertThat(mv.model["onDemandUrlParam"]).isEqualTo("teamcity.build.oidc.endpoint")
    }

    @Test
    fun doHandle_noBuildForm_subIsNull() {
        val mv = handleRequest()

        Assertions.assertThat(mv.model["sub"]).isNull()
        Assertions.assertThat(mv.model["issuer"]).isEqualTo("https://issuer.example.com")
        Assertions.assertThat(mv.model["jwksURL"]).isEqualTo("/app/oidc-jwt/.well-known/jwks?currentOnly=true")
        Assertions.assertThat(mv.model["jwksFilename"]).isEqualTo("issuer.example.com_jwks.json")
        Assertions.assertThat(mv.model["onDemandUrlParam"]).isEqualTo("teamcity.build.oidc.endpoint")
    }

    @Test
    fun doHandle_buildFormIsWrongType_subIsNull() {
        request.setAttribute("buildForm", Any())

        val mv = handleRequest()

        Assertions.assertThat(mv.model["sub"]).isNull()
        Assertions.assertThat(mv.model["issuer"]).isEqualTo("https://issuer.example.com")
        Assertions.assertThat(mv.model["jwksURL"]).isEqualTo("/app/oidc-jwt/.well-known/jwks?currentOnly=true")
        Assertions.assertThat(mv.model["jwksFilename"]).isEqualTo("issuer.example.com_jwks.json")
        Assertions.assertThat(mv.model["onDemandUrlParam"]).isEqualTo("teamcity.build.oidc.endpoint")
    }

    @Test
    fun doHandle_buildFormHasNullBuildType_subIsNull() {
        val buildForm = mockk<EditBuildTypeForm> {
            every { settingsBuildType } returns null
        }
        request.setAttribute("buildForm", buildForm)

        val mv = handleRequest()

        Assertions.assertThat(mv.model["sub"]).isNull()
        Assertions.assertThat(mv.model["issuer"]).isEqualTo("https://issuer.example.com")
        Assertions.assertThat(mv.model["jwksURL"]).isEqualTo("/app/oidc-jwt/.well-known/jwks?currentOnly=true")
        Assertions.assertThat(mv.model["jwksFilename"]).isEqualTo("issuer.example.com_jwks.json")
        Assertions.assertThat(mv.model["onDemandUrlParam"]).isEqualTo("teamcity.build.oidc.endpoint")
    }
}
