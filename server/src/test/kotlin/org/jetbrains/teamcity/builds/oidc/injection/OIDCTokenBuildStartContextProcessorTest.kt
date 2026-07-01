package org.jetbrains.teamcity.builds.oidc.injection

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.BuildProblemData
import jetbrains.buildServer.serverSide.*
import jetbrains.buildServer.serverSide.agentPools.AgentPool
import jetbrains.buildServer.parameters.ParametersProvider
import jetbrains.buildServer.serverSide.parameters.ParameterFactory
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class OIDCTokenBuildStartContextProcessorTest : BaseTestCase() {

    private val fixedInstant = Instant.parse("2026-01-01T00:00:00Z")
    private val fixedClock = Clock.fixed(fixedInstant, ZoneOffset.UTC)
    private val objectMapper = ObjectMapper()

    private fun createInParamsDescriptor(
        buildParam: String? = null,
        audiences: String? = null,
        tokenLifetimeSeconds: String? = null,
    ): SBuildFeatureDescriptor {
        val params = mutableMapOf<String, String>()
        if (buildParam != null) params["buildParam"] = buildParam
        if (audiences != null) params["audiences"] = audiences
        if (tokenLifetimeSeconds != null) params["tokenLifetimeSeconds"] = tokenLifetimeSeconds
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
        inParamsFeatures: List<SBuildFeatureDescriptor> = emptyList(),
        executionTimeoutMin: Int? = 30,
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
        every { build.buildPromotion } returns mockk<BuildPromotion>()
        val parametersProvider = mockk<ParametersProvider>()
        every { parametersProvider.get("teamcity.serverUrl") } returns null
        every { build.parametersProvider } returns parametersProvider
        every { build.addBuildProblem(any()) } just Runs
        every { build.vcsRootEntries } returns emptyList()
        every { build.isAgentLessBuild } returns false
        every { build.isPersonal } returns false
        every { build.getBuildFeaturesOfType("oidcTokenOnDemand") } returns onDemandFeatures
        every { build.getBuildFeaturesOfType("oidcTokenInParams") } returns inParamsFeatures

        if (executionTimeoutMin != null) {
            val buildType = mockk<SBuildType>()
            every { buildType.executionTimeoutMin } returns executionTimeoutMin
            every { build.buildType } returns buildType
        } else {
            every { build.buildType } returns null
        }

        return build
    }

    private fun mockContext(build: SRunningBuild): BuildStartContext {
        return mockk<BuildStartContext> {
            every { getBuild() } returns build
            every { addSharedParameter(any(), any()) } just Runs
        }
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

    private data class TokenIssuingSetup(
        val processor: OIDCTokenBuildStartContextProcessor,
        val projectManager: ProjectManager,
        val registry: JWTSignerRegistry,
        val settings: OIDCSettings,
        val paramFactory: ParameterFactory,
        val buildServer: SBuildServer,
        val signer: JWTSigner,
    )

    private fun createTokenIssuingSetup(
        effectiveIssuer: String = "https://issuer.example.com",
        projectId: String = "project1",
        signer: JWTSigner = mockk<JWTSigner> { every { makeJWT(any(), any(), any()) } returns "signed-jwt" },
    ): TokenIssuingSetup {
        val project = mockProject(projectId)
        val projectManager = mockk<ProjectManager>()
        every { projectManager.findProjectById(projectId) } returns project

        val registry = mockk<JWTSignerRegistry> {
            every { getActiveSigner() } returns signer
        }
        val settings = mockk<OIDCSettings> {
            every { getEffectiveIssuer() } returns effectiveIssuer
        }
        val paramFactory = mockk<ParameterFactory>()
        val buildServer = mockk<SBuildServer> {
            every { rootUrl } returns "https://teamcity.example.com"
        }
        val processor = OIDCTokenBuildStartContextProcessor(
            projectManager, registry, settings, paramFactory, buildServer, fixedClock
        )
        return TokenIssuingSetup(processor, projectManager, registry, settings, paramFactory, buildServer, signer)
    }

    @Test
    fun updateParameters_noInParamsFeatures_doesNotCallSignerOrProjectManager() {
        val projectManager = mockk<ProjectManager>()
        val registry = mockk<JWTSignerRegistry>()
        val processor = OIDCTokenBuildStartContextProcessor(
            projectManager, registry, mockk(), mockk(), mockk(), fixedClock
        )
        val build = mockBuild(inParamsFeatures = emptyList())
        val context = mockContext(build)

        processor.updateParameters(context)

        verify(exactly = 0) { registry.getActiveSigner() }
        verify(exactly = 0) { projectManager.findProjectById(any()) }
    }

    @Test
    fun updateParameters_projectNotFound_doesNotGenerateTokens() {
        val projectManager = mockk<ProjectManager>()
        every { projectManager.findProjectById(any()) } returns null
        val registry = mockk<JWTSignerRegistry>()
        val processor = OIDCTokenBuildStartContextProcessor(
            projectManager, registry, mockk(), mockk(), mockk(), fixedClock
        )
        val build = mockBuild(
            inParamsFeatures = listOf(createInParamsDescriptor(buildParam = "my.param"))
        )
        val context = mockContext(build)

        processor.updateParameters(context)

        verify(exactly = 0) { registry.getActiveSigner() }
    }

    @Test
    fun updateParameters_multipleFeatures_usesSameSignerForAll() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "param1"),
            createInParamsDescriptor(buildParam = "param2"),
        ))
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        verify(exactly = 1) { setup.registry.getActiveSigner() }
        verify(exactly = 2) { setup.signer.makeJWT(eq(build), any(), any()) }
    }

    @Test
    fun updateParameters_featureWithEmptyParam_IssuesDefaultTokenName() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = ""),
            createInParamsDescriptor(buildParam = "valid.param"),
        ))
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        verify(exactly = 2) { setup.signer.makeJWT(eq(build), any(), any()) }
        verify(exactly = 1) { context.addSharedParameter("env.TEAMCITY_BUILD_OIDC_TOKEN", "signed-jwt") }
        verify(exactly = 1) { context.addSharedParameter("valid.param", "signed-jwt") }
    }

    @Test
    fun updateParameters_customAudiences_appearsInSignedClaims() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "my.param", audiences = "aud1\naud2"),
        ))
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        val claimsSlot = slot<ByteArray>()
        verify { setup.signer.makeJWT(eq(build), capture(claimsSlot), any()) }
        val claims = parseClaims(claimsSlot.captured)
        @Suppress("UNCHECKED_CAST")
        Assertions.assertThat(claims["aud"] as List<String>).isEqualTo(listOf("aud1", "aud2"))
    }

    @Test
    fun updateParameters_noAudiences_usesEffectiveIssuerAsDefault() {
        val setup = createTokenIssuingSetup(effectiveIssuer = "https://default-issuer.example.com")
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "my.param"),
        ))
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        val claimsSlot = slot<ByteArray>()
        verify { setup.signer.makeJWT(eq(build), capture(claimsSlot), any()) }
        val claims = parseClaims(claimsSlot.captured)
        Assertions.assertThat(claims["aud"]).isEqualTo("https://default-issuer.example.com")
    }

    @Test
    fun updateParameters_customTokenLifetime_expiresAtMatchesFeatureValue() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "my.param", tokenLifetimeSeconds = "600"),
        ))
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        val expirationSlot = slot<Instant>()
        verify { setup.signer.makeJWT(eq(build), any(), capture(expirationSlot)) }
        Assertions.assertThat(expirationSlot.captured).isEqualTo(fixedInstant.plusSeconds(600))
    }

    @Test
    fun updateParameters_noTokenLifetime_expiresAtEqualsBuildTimeoutPlusBuffer() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(
            executionTimeoutMin = 30,
            inParamsFeatures = listOf(createInParamsDescriptor(buildParam = "my.param")),
        )
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        val expirationSlot = slot<Instant>()
        verify { setup.signer.makeJWT(eq(build), any(), capture(expirationSlot)) }
        Assertions.assertThat(expirationSlot.captured).isEqualTo(fixedInstant.plusSeconds((30 + 10) * 60L))
    }

    @Test
    fun updateParameters_nullBuildType_expiresAtIsAZeroTimeout() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(
            executionTimeoutMin = null,
            inParamsFeatures = listOf(createInParamsDescriptor(buildParam = "my.param")),
        )
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        val expirationSlot = slot<Instant>()
        verify { setup.signer.makeJWT(eq(build), any(), capture(expirationSlot)) }
        Assertions.assertThat(expirationSlot.captured).isEqualTo(fixedInstant.plusSeconds((0 + 10) * 60L))
    }

    @Test
    fun updateParameters_signerThrows_addsBuildProblemAndStopsProcessing() {
        val signer = mockk<JWTSigner>()
        every { signer.makeJWT(any(), any(), any()) } throws RuntimeException("signing failed")
        val setup = createTokenIssuingSetup(signer = signer)

        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "param1"),
            createInParamsDescriptor(buildParam = "param2"),
        ))
        every { build.addBuildProblem(any()) } just Runs
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        val captor = slot<BuildProblemData>()
        verify { build.addBuildProblem(capture(captor)) }
        Assertions.assertThat(captor.captured.identity).isEqualTo(
            "oidc_TokenInjector_TokenGenerationError" + "Failed to sign JWT: signing failed".hashCode()
        )
        Assertions.assertThat(captor.captured.type).isEqualTo("[OIDC JWT] Failed to generate JWT")
        Assertions.assertThat(captor.captured.description).isEqualTo("Failed to sign JWT: signing failed")
        verify(exactly = 1) { signer.makeJWT(eq(build), any(), any()) }
        verify(exactly = 0) { context.addSharedParameter(any(), any()) }
        clearFailure()
    }

    @Test
    fun updateParameters_projectNotFound_addsBuildProblem() {
        val projectManager = mockk<ProjectManager>()
        every { projectManager.findProjectById("project1") } returns null
        val registry = mockk<JWTSignerRegistry>()
        val processor = OIDCTokenBuildStartContextProcessor(
            projectManager, registry, mockk(), mockk(), mockk(), fixedClock
        )
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "my.param"),
        ))
        every { build.addBuildProblem(any()) } just Runs
        val context = mockContext(build)

        processor.updateParameters(context)

        val captor = slot<BuildProblemData>()
        verify { build.addBuildProblem(capture(captor)) }
        Assertions.assertThat(captor.captured.identity).isEqualTo(
            "oidc_TokenInjector_ProjectLookupError" + "project1".hashCode()
        )
        Assertions.assertThat(captor.captured.type).isEqualTo("[OIDC JWT] Failed to look up the build's active project")
        Assertions.assertThat(captor.captured.description).isEqualTo("Project with ID project1 not found")
        verify(exactly = 0) { context.addSharedParameter(any(), any()) }
    }

    @Test
    fun updateParameters_getActiveSignerThrows_addsBuildProblemAndStopsProcessing() {
        val signer = mockk<JWTSigner>()
        val project = mockProject()
        val projectManager = mockk<ProjectManager>()
        every { projectManager.findProjectById("project1") } returns project
        val registry = mockk<JWTSignerRegistry>()
        every { registry.getActiveSigner() } throws RuntimeException("registry boom")
        val settings = mockk<OIDCSettings> {
            every { getEffectiveIssuer() } returns "https://issuer.example.com"
        }
        val processor = OIDCTokenBuildStartContextProcessor(
            projectManager, registry, settings, mockk(), mockk(), fixedClock
        )
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "my.param"),
        ))
        every { build.addBuildProblem(any()) } just Runs
        val context = mockContext(build)

        processor.updateParameters(context)

        val captor = slot<BuildProblemData>()
        verify { build.addBuildProblem(capture(captor)) }
        Assertions.assertThat(captor.captured.identity).isEqualTo(
            "oidc_TokenInjector_SignerLookupError" + "registry boom".hashCode()
        )
        Assertions.assertThat(captor.captured.type).isEqualTo("[OIDC JWT] Failed to look up the active signer")
        Assertions.assertThat(captor.captured.description).isEqualTo("registry boom")
        verify(exactly = 0) { signer.makeJWT(any(), any(), any()) }
        verify(exactly = 0) { context.addSharedParameter(any(), any()) }
        clearFailure()
    }

    @Test
    fun updateParameters_duplicateBuildParam_addsBuildProblemAndInjectsNothing() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "shared.param"),
            createInParamsDescriptor(buildParam = "shared.param"),
        ))
        every { build.addBuildProblem(any()) } just Runs
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        verify(exactly = 0) { context.addSharedParameter(any(), any()) }
        val captor = slot<BuildProblemData>()
        verify { build.addBuildProblem(capture(captor)) }
        Assertions.assertThat(captor.captured.identity).isEqualTo(
            "oidc_TokenInjector_DuplicateInjectionParamError" + "shared.param".hashCode()
        )
        Assertions.assertThat(captor.captured.type).isEqualTo("[OIDC JWT] Duplicate injection parameter")
        Assertions.assertThat(captor.captured.description).isEqualTo(
            "The 'shared.param' parameter is already provided by another 'OIDC Token (in build parameters)' build feature"
        )
    }

    @Test
    fun updateParameters_thirdFeatureFollowsDuplicate_injectsNothing() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "a"),
            createInParamsDescriptor(buildParam = "a"),
            createInParamsDescriptor(buildParam = "b"),
        ))
        every { build.addBuildProblem(any()) } just Runs
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        verify(exactly = 1) { setup.signer.makeJWT(eq(build), any(), any()) }
        verify(exactly = 0) { context.addSharedParameter(any(), any()) }
    }

    @Test
    fun updateParameters_makeJWTThrowsOnLaterFeature_injectsNoneOfTheEarlierTokens() {
        val signer = mockk<JWTSigner>()
        every { signer.makeJWT(any(), any(), any()) } returnsMany listOf("jwt-1") andThenThrows RuntimeException("signing failed")
        val setup = createTokenIssuingSetup(signer = signer)

        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "first.param"),
            createInParamsDescriptor(buildParam = "second.param"),
        ))
        every { build.addBuildProblem(any()) } just Runs
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        verify(exactly = 2) { signer.makeJWT(eq(build), any(), any()) }
        verify(exactly = 0) { context.addSharedParameter(any(), any()) }
        verify(exactly = 1) { build.addBuildProblem(any()) }
        clearFailure()
    }

    @Test
    fun getPasswordParameters_afterDuplicateError_returnsEmpty() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "shared.param"),
            createInParamsDescriptor(buildParam = "shared.param"),
        ))
        every { build.addBuildProblem(any()) } just Runs
        val context = mockContext(build)

        setup.processor.updateParameters(context)
        val result = setup.processor.getPasswordParameters(build)

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun updateParameters_sameNameUsedAcrossDifferentBuilds_doesNotConflict() {
        val setup = createTokenIssuingSetup()
        val build1 = mockBuild(buildId = 1L, inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "shared.param"),
        ))
        val build2 = mockBuild(buildId = 2L, inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "shared.param"),
        ))
        val context1 = mockContext(build1)
        val context2 = mockContext(build2)

        setup.processor.updateParameters(context1)
        setup.processor.updateParameters(context2)

        verify(exactly = 2) { setup.signer.makeJWT(any(), any(), any()) }
        verify(exactly = 1) { context1.addSharedParameter("shared.param", "signed-jwt") }
        verify(exactly = 1) { context2.addSharedParameter("shared.param", "signed-jwt") }
        verify(exactly = 0) { build1.addBuildProblem(any()) }
        verify(exactly = 0) { build2.addBuildProblem(any()) }
    }

    @Test
    fun updateParameters_buildParamOnly_addsBuildParam() {
        val setup = createTokenIssuingSetup()
        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "my.param"),
        ))
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        verify(exactly = 1) { context.addSharedParameter("my.param", "signed-jwt") }
        verify(exactly = 1) { context.addSharedParameter(any(), any()) }
    }

    @Test
    fun updateParameters_multipleFeatures_eachGetsOwnSignedToken() {
        val signer = mockk<JWTSigner>()
        every { signer.makeJWT(any(), any(), any()) } returnsMany listOf("jwt-1", "jwt-2")
        val setup = createTokenIssuingSetup(signer = signer)

        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "param1"),
            createInParamsDescriptor(buildParam = "param2"),
        ))
        val context = mockContext(build)

        setup.processor.updateParameters(context)

        verify(exactly = 1) { context.addSharedParameter("param1", "jwt-1") }
        verify(exactly = 1) { context.addSharedParameter("param2", "jwt-2") }
    }

    @Test
    fun getConstraint_returnsBeforePasswordsBuildStartContextProcessor() {
        val processor = OIDCTokenBuildStartContextProcessor(
            mockk(), mockk(), mockk(), mockk(), mockk(), fixedClock
        )

        val constraint = processor.constraint

        Assertions.assertThat(constraint.getBefore()).contains(
            "jetbrains.buildServer.serverSide.parameters.types.PasswordsBuildStartContextProcessor"
        )
    }

    @Test
    fun getOrderId_returnsClassName() {
        val processor = OIDCTokenBuildStartContextProcessor(
            mockk(), mockk(), mockk(), mockk(), mockk(), fixedClock
        )

        Assertions.assertThat(processor.orderId).isEqualTo(
            "org.jetbrains.teamcity.builds.oidc.injection.OIDCTokenBuildStartContextProcessor"
        )
    }

    @Test
    fun getPasswordParameters_afterUpdateParameters_returnsIssuedTokensAsPasswords() {
        val setup = createTokenIssuingSetup()
        val mockParam1 = mockk<Parameter>()
        every { setup.paramFactory.createTypedParameter(eq("my.param"), eq("signed-jwt"), eq("password")) } returns mockParam1

        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "my.param"),
        ))
        val context = mockContext(build)

        setup.processor.updateParameters(context)
        val result = setup.processor.getPasswordParameters(build)

        Assertions.assertThat(result).hasSize(1)
        Assertions.assertThat(result).contains(mockParam1)
    }

    @Test
    fun getPasswordParameters_calledTwice_returnsEmptyOnSecondCall() {
        val setup = createTokenIssuingSetup()
        every { setup.paramFactory.createTypedParameter(any(), any(), any()) } returns mockk()

        val build = mockBuild(inParamsFeatures = listOf(
            createInParamsDescriptor(buildParam = "my.param"),
        ))
        val context = mockContext(build)

        setup.processor.updateParameters(context)
        val first = setup.processor.getPasswordParameters(build)
        val second = setup.processor.getPasswordParameters(build)

        Assertions.assertThat(first).hasSize(1)
        Assertions.assertThat(second).isEmpty()
    }

    @Test
    fun getPasswordParameters_noTokensIssued_returnsEmptyList() {
        val processor = OIDCTokenBuildStartContextProcessor(
            mockk(), mockk(), mockk(), mockk(), mockk(), fixedClock
        )
        val build = mockk<SRunningBuild> {
            every { buildId } returns 999L
        }

        val result = processor.getPasswordParameters(build)

        Assertions.assertThat(result).isEmpty()
    }

    private fun mockOwnerNode(url: String, canAcceptHTTP: Boolean): TeamCityNode {
        return mockk<TeamCityNode> {
            every { getUrl() } returns url
            every { canAcceptHTTPRequests() } returns canAcceptHTTP
        }
    }

    private fun mockBuildWithOwnerNode(
        ownerNode: TeamCityNode?,
        serverUrlParam: String? = null,
    ): SRunningBuild {
        val parametersProvider = mockk<ParametersProvider>()
        every { parametersProvider.get("teamcity.serverUrl") } returns serverUrlParam

        val buildPromotion = mockk<BuildPromotionEx>()
        every { buildPromotion.ownerNode } returns ownerNode

        val build = mockk<SRunningBuild>()
        every { build.buildId } returns 1L
        every { build.parametersProvider } returns parametersProvider
        every { build.getBuildFeaturesOfType("oidcTokenOnDemand") } returns listOf(mockk())
        every { build.getBuildFeaturesOfType("oidcTokenInParams") } returns emptyList()
        every { build.buildPromotion } returns buildPromotion

        return build
    }
}
