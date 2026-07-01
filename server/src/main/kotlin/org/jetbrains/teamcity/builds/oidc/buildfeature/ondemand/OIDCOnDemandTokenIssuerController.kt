package org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand

import org.jetbrains.teamcity.builds.oidc.JWTClaimsGenerator
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand.OIDCTokenOnDemandBuildFeature.Companion.oidcOnDemandAudiences
import org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand.OIDCTokenOnDemandBuildFeature.Companion.oidcOnDemandBuildFeatures
import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.serverSide.BuildsManager
import jetbrains.buildServer.serverSide.ProjectManager
import jetbrains.buildServer.serverSide.SecurityContextEx
import jetbrains.buildServer.web.util.WebAuthUtil
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException
import java.time.Clock
import javax.servlet.http.HttpServletRequest

@RestController
@RequestMapping("/${OIDCConstants.PLUGIN_ID}/${OIDCConstants.BuildFeatureOnDemand.CONTROLLER_ROOT}")
class OIDCOnDemandTokenIssuerController @JvmOverloads constructor(
    private val registry: JWTSignerRegistry,
    private val settings: OIDCSettings,
    private val projectManager: ProjectManager,
    private val buildsManager: BuildsManager,
    private val securityContextEx: SecurityContextEx,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val LOG = com.intellij.openapi.diagnostic.Logger.getInstance(this.javaClass.name)

    @RequestMapping("",
        method = [RequestMethod.GET], produces = ["text/plain"])
    fun issue(@RequestParam("aud", required = false) requestedAud: List<String>? = emptyList(), request: HttpServletRequest): String {
        val buildId = WebAuthUtil.getAuthenticatedBuildId(request) ?: throw ResponseStatusException(
            HttpStatus.UNAUTHORIZED,
            "No authenticated build was found. Access to build tokens is denied."
        )
        val build = buildsManager.findRunningBuildById(buildId)
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "Running build with ID $buildId not found")

        val project = projectManager.findProjectById(build.projectId)
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "Project with ID ${build.projectId} not found")

        val onDemandFeatures = build.oidcOnDemandBuildFeatures().sortedBy { it.id }
        if (onDemandFeatures.isEmpty()) {
            throw ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "No '${OIDCConstants.BuildFeatureOnDemand.DISPLAY_NAME}' build features were found for this build."
            )
        }

        val issuer = settings.getEffectiveIssuer()
        val audience = requestedAud?.map { it.trim() } ?: emptyList()

        val allowedAudiences = onDemandFeatures.flatMap { it.oidcOnDemandAudiences(issuer) }.toSet()
        audience.filter { it !in allowedAudiences }.takeIf { it.isNotEmpty() }?.let {
            throw ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                """
                    The following requested audiences are not specified in on-demand build features: ${it.joinToString(", ")}. 
                    Allowed audiences: ${allowedAudiences.joinToString(", ")}
                """.trimIndent()
            )
        }

        // If no audience was provided, combine all on-demand audiences to a single token.
        val resultingAudience = if (audience.isEmpty()) {
            allowedAudiences
        } else {
            audience
        }

        val generatedClaims: JWTClaimsGenerator.GeneratedClaims = try {
            // The request is tainted with credentials from the build user.
            securityContextEx.runAsSystem<JWTClaimsGenerator.GeneratedClaims> {
                JWTClaimsGenerator.generate(issuer, resultingAudience, project, build,
                    OIDCConstants.BuildFeatureOnDemand.TOKEN_LIFETIME_SECONDS, clock)
            }
        } catch (e: Exception) {
            LOG.error("Could not generate JWT claims", e)
            throw ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Could not generate JWT claims: ${e.message}",
                e
            )
        }

        val signer = registry.getActiveSigner()
        val signed = try {
            signer.makeJWT(build, generatedClaims.claims, generatedClaims.expiresAt)
        } catch (e: Exception) {
            LOG.error("Could not sign JWT", e)
            throw ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Could not sign JWT: ${e.message}",
                e
            )
        }

        return signed
    }
}
