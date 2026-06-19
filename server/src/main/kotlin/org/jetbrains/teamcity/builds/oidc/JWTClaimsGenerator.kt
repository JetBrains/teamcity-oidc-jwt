package org.jetbrains.teamcity.builds.oidc

import com.fasterxml.jackson.databind.ObjectMapper
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.SProject
import java.time.Clock
import java.time.Instant
import java.util.UUID

object JWTClaimsGenerator {
    data class GeneratedClaims(val claims: ByteArray, val expiresAt: Instant) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as GeneratedClaims

            if (!claims.contentEquals(other.claims)) return false
            if (expiresAt != other.expiresAt) return false

            return true
        }

        override fun hashCode(): Int {
            var result = claims.contentHashCode()
            result = 31 * result + expiresAt.hashCode()
            return result
        }
    }

    private val objectMapper = ObjectMapper()

    /**
     * Generates a `sub` claim for the given build.
     *
     * For non-personal builds, the format is `_Root:project123:project456:bt123`.
     *
     * For personal builds, the format is `user123__Root:user123_project123:user123_project456:user123_bt123`.
     */
    fun sub(project: SProject, buildTypeID: String, personalBuildOf: Long? = null): String {
        val isPersonal = personalBuildOf != null
        var path = if (isPersonal) "user${personalBuildOf}_" else ""
        var currentProject: SProject? = project
        while (currentProject != null) {
            path = "${currentProject.projectId}:$path"
            if (isPersonal) {
                path = "user${personalBuildOf}_$path"
            }
            currentProject = currentProject.parentProject
        }

        return "$path$buildTypeID"
    }

    fun generate(
        issuer: String,
        audience: Collection<String>,
        project: SProject,
        build: SBuild,
        lifetimeSeconds: Long,
        clock: Clock = Clock.systemUTC()
    ): GeneratedClaims {
        val now = Instant.now(clock)
        if (audience.isEmpty()) {
            throw IllegalArgumentException("Audience must not be empty")
        }

        val sub = sub(project, build.buildTypeId, if (build.isPersonal) build.triggeredBy.user?.id ?: -1 else null)

        val expiresAt = now.plusSeconds(lifetimeSeconds)

        val claims = mapOf(
            "iss" to issuer,
            "sub" to sub,
            "aud" to if (audience.size == 1) audience.first() else audience,
            "exp" to expiresAt.epochSecond,

            // `nbf` (Not Before) and `iat` (Issued At) claims should be equal for our use case:
            //  the token must be processable the moment it was issued.
            "nbf" to now.epochSecond,
            "iat" to now.epochSecond,

            "jti" to UUID.randomUUID().toString(),

            "build_type_id" to build.buildTypeId,
            "build_type_external_id" to build.buildTypeExternalId,

            "project_id" to build.projectId,
            "project_external_id" to build.projectExternalId,

            "build_id" to build.buildId,
            "build_number" to build.buildNumber,

            // TODO More specific info about VCS roots, at least for git
            "vcs_roots" to build.vcsRootEntries.map { mapOf(
                "id" to it.vcsRoot.id,
                "name" to it.vcsRoot.name,
                "revision" to it.vcsRoot.currentRevision.version
            ) },

            "triggered_by_user_id" to build.triggeredBy.user?.id,
            "triggered_by_user_name" to build.triggeredBy.user?.username,
            "triggered_by_snapshot" to build.triggeredBy.isTriggeredBySnapshotDependency,

            "branch_name" to build.branch?.name,
            "branch_display_name" to build.branch?.displayName,
            "branch_is_default" to build.branch?.isDefaultBranch,

            "agent_id" to build.agent.id,
            "agent_name" to build.agent.name,
            "agent_hostname" to build.agent.hostName,
            "agent_pool" to build.agent.agentPool.name,
            "agent_is_cloud" to build.agent.isCloudAgent,
            "agent_version" to build.agent.version,
            "agentless" to build.isAgentLessBuild,

            "is_personal" to build.isPersonal,
        )

        return GeneratedClaims(objectMapper.writeValueAsBytes(claims), expiresAt)
    }

    fun getSupportedClaims(): List<String> {
        return listOf(
            "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
            "build_type_id", "build_type_external_id",
            "project_id", "project_external_id",
            "build_id", "build_number",
            "vcs_roots",
            "triggered_by_user_id", "triggered_by_user_name", "triggered_by_snapshot",
            "branch_name", "branch_display_name", "branch_is_default",
            "agent_id", "agent_name", "agent_hostname", "agent_pool", "agent_is_cloud", "agent_version", "agentless",
            "is_personal",
        )
    }
}
