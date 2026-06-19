package org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.serverSide.*
import jetbrains.buildServer.serverSide.agentPools.AgentPool
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*
import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import javax.servlet.http.HttpServletRequest

class OIDCOnDemandTokenIssuerControllerTest : BaseTestCase() {

    private val fixedInstant = Instant.parse("2026-01-01T00:00:00Z")
    private val fixedClock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
    private val objectMapper = ObjectMapper()

    private fun mockRequest(buildId: Long? = 1L): HttpServletRequest {
        return mockk<HttpServletRequest> {
            every { getAttribute("TeamCityAuthenticatedBuild") } returns buildId
        }
    }

    private fun createOnDemandDescriptor(audiences: String? = null): SBuildFeatureDescriptor {
        val params = mutableMapOf<String, String>()
        if (audiences != null) params["audiences"] = audiences
        return mockk<SBuildFeatureDescriptor> {
            every { parameters } returns params
        }
    }

    private fun mockBuild(
        buildId: Long = 1L,
        projectId: String = "project1",
        buildTypeId: String = "bt1",
        buildTypeExternalId: String = "BuildType1",
        projectExternalId: String = "Project1",
        buildNumber: String = "42",
        onDemandFeatures: List<SBuildFeatureDescriptor> = emptyList(),
    ): SRunningBuild {
        val build = mockk<SRunningBuild>()
        val triggeredBy = mockk<TriggeredBy>()
        every { triggeredBy.user } returns null
        every { triggeredBy.isTriggeredBySnapshotDependency } returns false

        val agent = mockk<SBuildAgent>()
        val pool = mockk<AgentPool>()
        every { pool.name } returns "Default"
        every { agent.id } returns 1
        every { agent.name } returns "agent-1"
        every { agent.hostName } returns "agent1.example.com"
        every { agent.agentPool } returns pool
        every { agent.isCloudAgent } returns false
        every { agent.version } returns "2024.12"

        every { build.buildId } returns buildId
        every { build.buildTypeId } returns buildTypeId
        every { build.buildTypeExternalId } returns buildTypeExternalId
        every { build.projectId } returns projectId
        every { build.projectExternalId } returns projectExternalId
        every { build.buildNumber } returns buildNumber
        every { build.triggeredBy } returns triggeredBy
        every { build.branch } returns null
        every { build.agent } returns agent
        every { build.vcsRootEntries } returns emptyList()
        every { build.isAgentLessBuild } returns false
        every { build.isPersonal } returns false
        every { build.getBuildFeaturesOfType("oidcTokenOnDemand") } returns onDemandFeatures

        return build
    }

    private fun mockProject(projectId: String = "project1"): SProject {
        val project = mockk<SProject>()
        every { project.projectId } returns projectId
        every { project.parentProject } returns null
        return project
    }

    private fun parseClaims(claimsBytes: ByteArray): Map<String, Any?> {
        return objectMapper.readValue(claimsBytes, object : TypeReference<Map<String, Any?>>() {})
    }

    private data class ControllerSetup(
        val controller: OIDCOnDemandTokenIssuerController,
        val registry: JWTSignerRegistry,
        val settings: OIDCSettings,
        val projectManager: ProjectManager,
        val buildsManager: BuildsManager,
        val securityContextEx: SecurityContextEx,
        val signer: JWTSigner,
        val build: SBuild,
    )

    private fun createControllerSetup(
        buildId: Long = 1L,
        projectId: String = "project1",
        effectiveIssuer: String = "https://issuer.example.com",
        onDemandFeatures: List<SBuildFeatureDescriptor> = listOf(createOnDemandDescriptor()),
        signer: JWTSigner = mockk<JWTSigner> { every { makeJWT(any(), any(), any()) } returns "signed-jwt" },
    ): ControllerSetup {
        val project = mockProject(projectId)
        val projectManager = mockk<ProjectManager>()
        every { projectManager.findProjectById(projectId) } returns project

        val build = mockBuild(buildId = buildId, projectId = projectId, onDemandFeatures = onDemandFeatures)
        val buildsManager = mockk<BuildsManager>()
        every { buildsManager.findRunningBuildById(buildId) } returns build

        val registry = mockk<JWTSignerRegistry> {
            every { getActiveSigner() } returns signer
        }
        val settings = mockk<OIDCSettings> {
            every { getEffectiveIssuer() } returns effectiveIssuer
        }
        val securityContextEx = mockk<SecurityContextEx>()
        every { securityContextEx.runAsSystem(any<SecurityContextEx.RunAsActionWithResult<*>>()) } answers { invocation ->
            @Suppress("UNCHECKED_CAST")
            (invocation.invocation.args[0] as SecurityContextEx.RunAsActionWithResult<*>).run()
        }

        val controller = OIDCOnDemandTokenIssuerController(
            registry, settings, projectManager, buildsManager, securityContextEx, fixedClock
        )
        return ControllerSetup(controller, registry, settings, projectManager, buildsManager, securityContextEx, signer, build)
    }

    @Test
    fun issue_requestNotFromBuild_returnsUnauthorized() {
        val buildsManager = mockk<BuildsManager>()
        val controller = OIDCOnDemandTokenIssuerController(
            mockk(), mockk(), mockk(), buildsManager, mockk(), fixedClock
        )
        val request = mockRequest(buildId = null)

        val exception = Assertions.catchThrowableOfType(
            { controller.issue(listOf("aud"), request) },
            ResponseStatusException::class.java
        )

        Assertions.assertThat(exception.status).isEqualTo(HttpStatus.UNAUTHORIZED)
        verify(exactly = 0) { buildsManager.findRunningBuildById(any()) }
    }

    @Test
    fun issue_buildNotCurrentlyRunning_returnsNotFound() {
        val buildsManager = mockk<BuildsManager>()
        every { buildsManager.findRunningBuildById(42) } returns null
        val controller = OIDCOnDemandTokenIssuerController(
            mockk(), mockk(), mockk(), buildsManager, mockk(), fixedClock
        )

        val exception = Assertions.catchThrowableOfType(
            { controller.issue(listOf("aud"), mockRequest(buildId = 42)) },
            ResponseStatusException::class.java
        )

        Assertions.assertThat(exception.status).isEqualTo(HttpStatus.NOT_FOUND)
    }

    @Test
    fun issue_projectNotAccessible_returnsNotFound() {
        val build = mockBuild(projectId = "project1")
        val buildsManager = mockk<BuildsManager>()
        every { buildsManager.findRunningBuildById(1) } returns build
        val projectManager = mockk<ProjectManager>()
        every { projectManager.findProjectById("project1") } returns null
        val controller = OIDCOnDemandTokenIssuerController(
            mockk(), mockk(), projectManager, buildsManager, mockk(), fixedClock
        )

        val exception = Assertions.catchThrowableOfType(
            { controller.issue(listOf("aud"), mockRequest()) },
            ResponseStatusException::class.java
        )

        Assertions.assertThat(exception.status).isEqualTo(HttpStatus.NOT_FOUND)
    }

    @Test
    fun issue_noOnDemandFeaturesPresent_returnsForbidden() {
        val setup = createControllerSetup(onDemandFeatures = emptyList())

        val exception = Assertions.catchThrowableOfType(
            { setup.controller.issue(listOf("aud"), mockRequest()) },
            ResponseStatusException::class.java
        )

        Assertions.assertThat(exception.status).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @Test
    fun issue_requestedAudienceNotAllowed_returnsBadRequest() {
        val setup = createControllerSetup(
            onDemandFeatures = listOf(createOnDemandDescriptor("aud-1\naud-2"))
        )

        val exception = Assertions.catchThrowableOfType(
            { setup.controller.issue(listOf("aud-1", "disallowed"), mockRequest()) },
            ResponseStatusException::class.java
        )

        Assertions.assertThat(exception.status).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    @Test
    fun issue_allAllowedAudiencesRequested_allEndUpInToken() {
        val setup = createControllerSetup(
            onDemandFeatures = listOf(createOnDemandDescriptor("aud-1\naud-2"))
        )

        setup.controller.issue(listOf("aud-1", "aud-2"), mockRequest())

        val claimsSlot = slot<ByteArray>()
        verify { setup.signer.makeJWT(eq(setup.build), capture(claimsSlot), any()) }
        val claims = parseClaims(claimsSlot.captured)
        @Suppress("UNCHECKED_CAST")
        Assertions.assertThat(claims["aud"] as List<String>).isEqualTo(listOf("aud-1", "aud-2"))
    }

    @Test
    fun issue_singleAudienceFromMultipleAllowed_onlyRequestedOneInClaims() {
        val setup = createControllerSetup(
            onDemandFeatures = listOf(createOnDemandDescriptor("aud-1\naud-2\naud-3"))
        )

        setup.controller.issue(listOf("aud-2"), mockRequest())

        val claimsSlot = slot<ByteArray>()
        verify { setup.signer.makeJWT(eq(setup.build), capture(claimsSlot), any()) }
        val claims = parseClaims(claimsSlot.captured)
        Assertions.assertThat(claims["aud"]).isEqualTo("aud-2")
    }

    @Test
    fun issue_subsetOfAllowedAudiences_onlySubsetInClaims() {
        val setup = createControllerSetup(
            onDemandFeatures = listOf(createOnDemandDescriptor("aud-1\naud-2\naud-3\naud-4"))
        )

        setup.controller.issue(listOf("aud-1", "aud-3"), mockRequest())

        val claimsSlot = slot<ByteArray>()
        verify { setup.signer.makeJWT(eq(setup.build), capture(claimsSlot), any()) }
        val claims = parseClaims(claimsSlot.captured)
        @Suppress("UNCHECKED_CAST")
        Assertions.assertThat(claims["aud"] as List<String>).isEqualTo(listOf("aud-1", "aud-3"))
    }

    @Test
    fun issue_multipleFeatures_onlyRequestedAudiencesInToken() {
        val setup = createControllerSetup(
            onDemandFeatures = listOf(
                createOnDemandDescriptor("aud-A\naud-B"),
                createOnDemandDescriptor("aud-C\naud-D"),
            )
        )

        setup.controller.issue(listOf("aud-A", "aud-C"), mockRequest())

        val claimsSlot = slot<ByteArray>()
        verify { setup.signer.makeJWT(eq(setup.build), capture(claimsSlot), any()) }
        val claims = parseClaims(claimsSlot.captured)
        @Suppress("UNCHECKED_CAST")
        Assertions.assertThat(claims["aud"] as List<String>).isEqualTo(listOf("aud-A", "aud-C"))
    }

    @Test
    fun issue_tokenLifetime_usesConstant300Seconds() {
        val setup = createControllerSetup(
            onDemandFeatures = listOf(createOnDemandDescriptor("aud-1"))
        )

        setup.controller.issue(listOf("aud-1"), mockRequest())

        val lifetimeSlot = slot<Instant>()
        verify { setup.signer.makeJWT(eq(setup.build), any(), capture(lifetimeSlot)) }
        Assertions.assertThat(lifetimeSlot.captured).isEqualTo(fixedInstant.plusSeconds(300))
    }

    @Test
    fun issue_happyPath_returnsSignerOutput() {
        val signer = mockk<JWTSigner> { every { makeJWT(any(), any(), any()) } returns "signed-jwt-token-xyz" }
        val setup = createControllerSetup(
            onDemandFeatures = listOf(createOnDemandDescriptor("aud-1")),
            signer = signer,
        )

        val result = setup.controller.issue(listOf("aud-1"), mockRequest())

        Assertions.assertThat(result).isEqualTo("signed-jwt-token-xyz")
    }

    @Test
    fun issue_claimsGenerationThrows_returnsInternalServerError() {
        val setup = createControllerSetup(
            onDemandFeatures = listOf(createOnDemandDescriptor("aud-1"))
        )
        every { setup.securityContextEx.runAsSystem(any<SecurityContextEx.RunAsActionWithResult<*>>()) } throws
            RuntimeException("claims generation failed")

        val exception = Assertions.catchThrowableOfType(
            { setup.controller.issue(listOf("aud-1"), mockRequest()) },
            ResponseStatusException::class.java
        )

        Assertions.assertThat(exception.status).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR)
        clearFailure()
    }

    @Test
    fun issue_signerMakeJWTThrows_returnsInternalServerError() {
        val signer = mockk<JWTSigner>()
        every { signer.makeJWT(any(), any(), any()) } throws RuntimeException("signing failed")
        val setup = createControllerSetup(
            onDemandFeatures = listOf(createOnDemandDescriptor("aud-1")),
            signer = signer,
        )

        val exception = Assertions.catchThrowableOfType(
            { setup.controller.issue(listOf("aud-1"), mockRequest()) },
            ResponseStatusException::class.java
        )

        Assertions.assertThat(exception.status).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR)
        clearFailure()
    }

    @Test
    fun issue_claimsGeneration_callsRunAsSystemExactlyOnce() {
        val setup = createControllerSetup(
            onDemandFeatures = listOf(createOnDemandDescriptor("aud-1"))
        )

        setup.controller.issue(listOf("aud-1"), mockRequest())

        verify(exactly = 1) { setup.securityContextEx.runAsSystem(any<SecurityContextEx.RunAsActionWithResult<*>>()) }
    }
}
