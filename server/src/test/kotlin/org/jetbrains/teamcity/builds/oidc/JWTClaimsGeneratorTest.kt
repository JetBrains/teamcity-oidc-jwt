package org.jetbrains.teamcity.builds.oidc

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.core.type.TypeReference
import jetbrains.buildServer.serverSide.*
import jetbrains.buildServer.serverSide.agentPools.AgentPool
import jetbrains.buildServer.users.SUser
import jetbrains.buildServer.vcs.CheckoutRules
import jetbrains.buildServer.vcs.VcsRootInstance
import jetbrains.buildServer.vcs.VcsRootInstanceEntry
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*
import jetbrains.buildServer.BaseTestCase
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID

class JWTClaimsGeneratorTest : BaseTestCase() {

    private val objectMapper = ObjectMapper()

    private fun parseClaimsJson(result: JWTClaimsGenerator.GeneratedClaims): Map<String, Any?> {
        return objectMapper.readValue(result.claims, object : TypeReference<Map<String, Any?>>() {})
    }

    private fun createMockProject(vararg projectIds: String): SProject {
        var parent: SProject? = null
        var current: SProject? = null
        for (id in projectIds) {
            current = mockk<SProject>()
            every { current.projectId } returns id
            every { current.parentProject } returns parent
            parent = current
        }
        return current!!
    }

    private fun mockUser(id: Long = 42, username: String = "testuser"): SUser {
        val user = mockk<SUser>()
        every { user.id } returns id
        every { user.username } returns username
        return user
    }

    private fun stubBranch(
        name: String = "refs/heads/main",
        displayName: String = "main",
        isDefault: Boolean = true
    ): Branch = object : Branch {
        override fun getName() = name
        override fun getDisplayName() = displayName
        override fun isDefaultBranch() = isDefault
    }

    private fun mockAgent(
        id: Int = 1,
        name: String = "agent-1",
        hostName: String = "agent1.example.com",
        poolName: String = "Default",
        isCloud: Boolean = false,
        version: String = "2024.12"
    ): SBuildAgent {
        val agent = mockk<SBuildAgent>()
        val pool = mockk<AgentPool>()
        every { pool.name } returns poolName
        every { agent.id } returns id
        every { agent.name } returns name
        every { agent.hostName } returns hostName
        every { agent.agentPool } returns pool
        every { agent.isCloudAgent } returns isCloud
        every { agent.version } returns version
        return agent
    }

    private fun stubVcsRootEntry(
        id: Long = 1,
        name: String = "vcs-root-1",
        revisionVersion: String = "abc123"
    ): VcsRootInstanceEntry {
        val vcsRoot = mockk<VcsRootInstance>()
        every { vcsRoot.id } returns id
        every { vcsRoot.name } returns name
        every { vcsRoot.currentRevision } returns RepositoryVersion(revisionVersion, revisionVersion)
        return VcsRootInstanceEntry(vcsRoot, CheckoutRules.DEFAULT)
    }

    private fun createMockBuild(
        buildTypeId: String = "bt123",
        buildTypeExternalId: String = "MyBuildType",
        projectId: String = "_Root",
        projectExternalId: String = "Root",
        buildId: Long = 1234L,
        buildNumber: String = "42",
        user: SUser? = mockUser(),
        branch: Branch? = stubBranch(),
        agent: SBuildAgent = mockAgent(),
        vcsRootEntries: List<VcsRootInstanceEntry> = listOf(stubVcsRootEntry()),
        isTriggeredBySnapshot: Boolean = false,
        isAgentLess: Boolean = false,
        isPersonal: Boolean = false,
        executionTimeoutMin: Int? = 30,
    ): SBuild {
        val build = mockk<SBuild>()
        val triggeredBy = mockk<TriggeredBy>()

        every { triggeredBy.user } returns user
        every { triggeredBy.isTriggeredBySnapshotDependency } returns isTriggeredBySnapshot

        every { build.buildTypeId } returns buildTypeId
        every { build.buildTypeExternalId } returns buildTypeExternalId
        every { build.projectId } returns projectId
        every { build.projectExternalId } returns projectExternalId
        every { build.buildId } returns buildId
        every { build.buildNumber } returns buildNumber
        every { build.triggeredBy } returns triggeredBy
        every { build.branch } returns branch
        every { build.agent } returns agent
        every { build.vcsRootEntries } returns vcsRootEntries
        every { build.isAgentLessBuild } returns isAgentLess
        every { build.isPersonal } returns isPersonal

        if (executionTimeoutMin != null) {
            val buildType = mockk<SBuildType>()
            every { buildType.executionTimeoutMin } returns executionTimeoutMin
            every { build.buildType } returns buildType
        } else {
            every { build.buildType } returns null
        }

        return build
    }

    @Test
    fun happyPath_allClaimsPresent() {
        val project = createMockProject("_Root")
        val build = createMockBuild()

        val now = Instant.parse("2026-01-01T00:00:00Z")
        val clock = mockk<Clock> {
            every { instant() } answers { now }
            every { zone } returns ZoneOffset.UTC
        }

        val result = JWTClaimsGenerator.generate(
            "https://issuer.example.com", listOf("api://default"),
            project, build,
            lifetimeSeconds = 300, clock = clock
        )

        val claims = parseClaimsJson(result)

        // Standard JWT claims
        Assertions.assertThat(claims["iss"]).isEqualTo("https://issuer.example.com")
        Assertions.assertThat(claims["sub"]).isEqualTo("_Root:bt123")
        Assertions.assertThat(claims["aud"]).isEqualTo("api://default") // single audience = string
        Assertions.assertThat((claims["iat"] as Number).toLong()).isEqualTo(now.epochSecond)
        Assertions.assertThat((claims["nbf"] as Number).toLong()).isEqualTo(now.epochSecond)
        val claimedExp = (claims["exp"] as Number).toLong()
        Assertions.assertThat(claimedExp).isEqualTo(now.plusSeconds(300).epochSecond)

        // jti is a valid UUID
        Assertions.assertThatCode { UUID.fromString(claims["jti"] as String) }.doesNotThrowAnyException()

        // result.expiresAt matches exp
        Assertions.assertThat(result.expiresAt.epochSecond).isEqualTo(claimedExp)

        // Build info
        Assertions.assertThat(claims["build_type_id"]).isEqualTo("bt123")
        Assertions.assertThat(claims["build_type_external_id"]).isEqualTo("MyBuildType")
        Assertions.assertThat(claims["project_id"]).isEqualTo("_Root")
        Assertions.assertThat(claims["project_external_id"]).isEqualTo("Root")
        Assertions.assertThat((claims["build_id"] as Number).toLong()).isEqualTo(1234L)
        Assertions.assertThat(claims["build_number"]).isEqualTo("42")

        // VCS roots
        @Suppress("UNCHECKED_CAST")
        val vcsRoots = claims["vcs_roots"] as List<Map<String, Any?>>
        Assertions.assertThat(vcsRoots).hasSize(1)
        Assertions.assertThat(vcsRoots[0]["id"]).isEqualTo(1)
        Assertions.assertThat(vcsRoots[0]["name"]).isEqualTo("vcs-root-1")
        Assertions.assertThat(vcsRoots[0]["revision"]).isEqualTo("abc123")

        // Triggered by
        Assertions.assertThat(claims["triggered_by_user_id"]).isEqualTo(42)
        Assertions.assertThat(claims["triggered_by_user_name"]).isEqualTo("testuser")
        Assertions.assertThat(claims["triggered_by_snapshot"]).isEqualTo(false)

        // Branch
        Assertions.assertThat(claims["branch_name"]).isEqualTo("refs/heads/main")
        Assertions.assertThat(claims["branch_display_name"]).isEqualTo("main")
        Assertions.assertThat(claims["branch_is_default"]).isEqualTo(true)

        // Agent
        Assertions.assertThat(claims["agent_id"]).isEqualTo(1)
        Assertions.assertThat(claims["agent_name"]).isEqualTo("agent-1")
        Assertions.assertThat(claims["agent_hostname"]).isEqualTo("agent1.example.com")
        Assertions.assertThat(claims["agent_pool"]).isEqualTo("Default")
        Assertions.assertThat(claims["agent_is_cloud"]).isEqualTo(false)
        Assertions.assertThat(claims["agent_version"]).isEqualTo("2024.12")
        Assertions.assertThat(claims["agentless"]).isEqualTo(false)

        // Build flags
        Assertions.assertThat(claims["is_personal"]).isEqualTo(false)
    }

    @Test
    fun emptyAudience_throwsIllegalArgumentException() {
        val project = createMockProject("_Root")
        val build = createMockBuild()

        val ex = Assertions.catchThrowableOfType({
            JWTClaimsGenerator.generate("https://issuer.example.com", emptyList(), project, build, lifetimeSeconds = 60)
        }, IllegalArgumentException::class.java)
        Assertions.assertThat(ex.message).isEqualTo("Audience must not be empty")
    }

    @Test
    fun multipleAudiences_audIsStringOrList() {
        val project = createMockProject("_Root")
        val build = createMockBuild()
        val audiences = listOf("aud1", "aud2", "aud3")

        val resultList = JWTClaimsGenerator.generate("https://issuer.example.com", audiences, project, build, lifetimeSeconds = 60)
        val claimsList = parseClaimsJson(resultList)

        @Suppress("UNCHECKED_CAST")
        val aud = claimsList["aud"] as List<String>
        Assertions.assertThat(aud).isEqualTo(audiences)

        val resultString = JWTClaimsGenerator.generate("https://issuer.example.com", listOf(audiences.first()), project, build, lifetimeSeconds = 60)
        val claimsString = parseClaimsJson(resultString)
        val audStr = claimsString["aud"] as String
        Assertions.assertThat(audStr).isEqualTo(audiences.first())
    }

    @Test
    fun nestedProjects_subClaimIncludesFullPath() {
        val project = createMockProject("_Root", "groupA", "groupB", "leaf")
        val build = createMockBuild(buildTypeId = "bt1")

        val result = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("aud"), project, build, lifetimeSeconds = 60)
        val claims = parseClaimsJson(result)

        Assertions.assertThat(claims["sub"]).isEqualTo("_Root:groupA:groupB:leaf:bt1")
    }

    @Test
    fun triggeredByUserNull_userFieldsAreNull() {
        val project = createMockProject("_Root")
        val build = createMockBuild(user = null)

        val result = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("aud"), project, build, lifetimeSeconds = 60)
        val claims = parseClaimsJson(result)

        Assertions.assertThat(claims["triggered_by_user_id"]).isNull()
        Assertions.assertThat(claims["triggered_by_user_name"]).isNull()
    }

    @Test
    fun branchNull_branchFieldsAreNull() {
        val project = createMockProject("_Root")
        val build = createMockBuild(branch = null)

        val result = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("aud"), project, build, lifetimeSeconds = 60)
        val claims = parseClaimsJson(result)

        Assertions.assertThat(claims["branch_name"]).isNull()
        Assertions.assertThat(claims["branch_display_name"]).isNull()
        Assertions.assertThat(claims["branch_is_default"]).isNull()
    }

    @Test
    fun jtiIsUniqueAcrossCalls() {
        val project = createMockProject("_Root")
        val build = createMockBuild()

        val result1 = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("aud"), project, build, lifetimeSeconds = 60)
        val result2 = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("aud"), project, build, lifetimeSeconds = 60)

        val jti1 = parseClaimsJson(result1)["jti"] as String
        val jti2 = parseClaimsJson(result2)["jti"] as String

        Assertions.assertThatCode { UUID.fromString(jti1) }.doesNotThrowAnyException()
        Assertions.assertThatCode { UUID.fromString(jti2) }.doesNotThrowAnyException()
        Assertions.assertThat(jti1).isNotEqualTo(jti2)
    }

    @Test
    fun multipleVcsRoots_allIncludedInClaims() {
        val project = createMockProject("_Root")
        val vcsEntries = listOf(
            stubVcsRootEntry(id = 1, name = "repo-a", revisionVersion = "aaa111"),
            stubVcsRootEntry(id = 2, name = "repo-b", revisionVersion = "bbb222"),
        )
        val build = createMockBuild(vcsRootEntries = vcsEntries)

        val result = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("aud"), project, build, lifetimeSeconds = 60)
        val claims = parseClaimsJson(result)

        @Suppress("UNCHECKED_CAST")
        val vcsRoots = claims["vcs_roots"] as List<Map<String, Any?>>
        Assertions.assertThat(vcsRoots).hasSize(2)
        Assertions.assertThat(vcsRoots[0]["id"]).isEqualTo(1)
        Assertions.assertThat(vcsRoots[0]["name"]).isEqualTo("repo-a")
        Assertions.assertThat(vcsRoots[0]["revision"]).isEqualTo("aaa111")
        Assertions.assertThat(vcsRoots[1]["id"]).isEqualTo(2)
        Assertions.assertThat(vcsRoots[1]["name"]).isEqualTo("repo-b")
        Assertions.assertThat(vcsRoots[1]["revision"]).isEqualTo("bbb222")
    }

    @Test
    fun emptyVcsRoots_vcsRootsIsEmptyList() {
        val project = createMockProject("_Root")
        val build = createMockBuild(vcsRootEntries = emptyList())

        val result = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("aud"), project, build, lifetimeSeconds = 60)
        val claims = parseClaimsJson(result)

        @Suppress("UNCHECKED_CAST")
        val vcsRoots = claims["vcs_roots"] as List<Map<String, Any?>>
        Assertions.assertThat(vcsRoots).isEmpty()
    }

    @Test
    fun supportedClaims_allPresent() {
        val project = createMockProject("_Root")
        val build = createMockBuild()

        val result = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("api://default"), project, build, lifetimeSeconds = 300)
        val claims = parseClaimsJson(result)

        val supportedClaims = JWTClaimsGenerator.getSupportedClaims()
        Assertions.assertThat(supportedClaims).containsAll(claims.keys)
        Assertions.assertThat(supportedClaims).hasSize(claims.size)
    }

    @Test
    fun sub_includesPersonalPrefix() {
        val project = createMockProject("_Root")
        val build = createMockBuild(isPersonal = true)

        val result = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("api://default"), project, build, lifetimeSeconds = 300)
        val claims = parseClaimsJson(result)
        val expectedUserPrefix = "user${build.triggeredBy.user?.id ?: -1}_"
        Assertions.assertThat(claims["sub"]).isEqualTo("${expectedUserPrefix}_Root:${expectedUserPrefix}bt123")
    }

    @Test
    fun sub_allLevelsIncludePersonalPrefix() {
        val project = createMockProject("_Root", "groupA", "groupB", "leaf")
        val build = createMockBuild(isPersonal = true)

        val result = JWTClaimsGenerator.generate("https://issuer.example.com", listOf("api://default"), project, build, lifetimeSeconds = 300)
        val claims = parseClaimsJson(result)
        val expectedUserPrefix = "user${build.triggeredBy.user?.id ?: -1}_"
        Assertions.assertThat(claims["sub"]).isEqualTo("${expectedUserPrefix}_Root:${expectedUserPrefix}groupA:${expectedUserPrefix}groupB:${expectedUserPrefix}leaf:${expectedUserPrefix}bt123")
    }
}
