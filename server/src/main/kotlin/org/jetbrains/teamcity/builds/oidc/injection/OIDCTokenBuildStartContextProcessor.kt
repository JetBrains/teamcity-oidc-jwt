package org.jetbrains.teamcity.builds.oidc.injection

import com.intellij.openapi.diagnostic.Logger
import org.jetbrains.teamcity.builds.oidc.JWTClaimsGenerator
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcInParamsAudiences
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcInParamsBuildFeatures
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcBuildParameter
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcTokenLifetime
import org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand.OIDCTokenOnDemandBuildFeature.Companion.oidcOnDemandBuildFeatures
import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.BuildProblemData
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.serverSide.BuildPromotionEx
import jetbrains.buildServer.serverSide.BuildStartContext
import jetbrains.buildServer.serverSide.BuildStartContextProcessor
import jetbrains.buildServer.serverSide.Parameter
import jetbrains.buildServer.serverSide.ProjectManager
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.SBuildServer
import jetbrains.buildServer.serverSide.parameters.ParameterFactory
import jetbrains.buildServer.serverSide.parameters.types.PasswordsProvider
import jetbrains.buildServer.util.positioning.PositionAware
import jetbrains.buildServer.util.positioning.PositionConstraint
import java.time.Clock
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * OIDCTokenBuildStartContextProcessor provides the build parameters. It generates JWTs for each in-param build feature
 * and signs them using the signer that was active at the build start time. When there are on-demand JWT build features
 * in the build configuration, it also adds the endpoint URL parameter.
 *
 * In TeamCity, builds have a certain lifecycle: when the build is started, the agents will not pick it up immediately.
 * There's a queue they need to go through first to be assigned to an agent. Once this happens, TeamCity will call
 * [jetbrains.buildServer.serverSide.BuildStartContextProcessor]s that can, among other things, inject parameters
 * to the build that's about to run. Because we issue JWTs with limited lifespan, it's necessary for us to do it
 * as close to the start of the build as possible. [jetbrains.buildServer.serverSide.BuildStartContextProcessor] is
 * the most suitable extension point for this case.
 *
 * Since JWTs are effectively credentials, it's important to mask their values in the UI. The only way to do so is to
 * implement [jetbrains.buildServer.serverSide.parameters.types.PasswordsProvider], which this class does as well.
 * When [getPasswordParameters] is called, the parameters provided by [updateParameters] are inaccessible,
 * so we use a map to store issued tokens.
 *
 * Internally, [jetbrains.buildServer.serverSide.parameters.types.PasswordsProvider] instances are collected and called by
 * [PasswordsBuildStartContextProcessor](https://javadoc.jetbrains.net/teamcity/openapi/current/jetbrains/buildServer/serverSide/parameters/types/PasswordsBuildStartContextProcessor.html),
 * which is also a [jetbrains.buildServer.serverSide.BuildStartContextProcessor]. To make the processors call sequence
 * reasonable (we can't return token values from [getPasswordParameters] if tokens are yet to be issued), this class
 * implements [jetbrains.buildServer.util.positioning.PositionAware].
 *
 * At the time of writing (2026.1 EAP), BuildStartContextProcessors are called on the main node only.
 */
class OIDCTokenBuildStartContextProcessor @JvmOverloads constructor(
    private val projectManager: ProjectManager,
    private val registry: JWTSignerRegistry,
    private val settings: OIDCSettings,
    private val paramFactory: ParameterFactory,
    private val buildServer: SBuildServer,
    private val clock: Clock = Clock.systemUTC(),
) : BuildStartContextProcessor, PasswordsProvider, PositionAware {
    private val LOG = Logger.getInstance(Loggers.SERVER_CATEGORY + "." + this.javaClass.name)

    private data class IssuedToken(val param: String, val token: String, val expiresAt: Instant)
    // We need to store issued token bodies between `updateParameters` and `getPasswordParameters` to mask their values.
    // Unfortunately, there seems to be no better way to do that.
    //
    // The calls of context processors seemingly happen within the same node, so we store them in a hashmap.
    private val issuedTokens = ConcurrentHashMap<Long, List<IssuedToken>>()

    private fun getOwnerNodeRootUrl(build: SBuild): String {
        val result = build.buildPromotion.let {
            if (it is BuildPromotionEx && it.ownerNode?.canAcceptHTTPRequests() == true) {
                it.ownerNode?.url
            } else {
                build.parametersProvider.get("teamcity.serverUrl")?.ifBlank { null }
            }
        } ?: buildServer.rootUrl
        return result.removeSuffix("/")
    }

    override fun updateParameters(context: BuildStartContext) {
        val build = context.build

        // Provide on-demand endpoint URL via parameter if any on-demand build features are present
        val onDemandTokens = build.oidcOnDemandBuildFeatures().isNotEmpty()
        if (onDemandTokens) {
            val rootUrl = getOwnerNodeRootUrl(build)
            val endpointUrl =
                "${rootUrl}${OIDCConstants.OIDC_ROOT_URL}/${OIDCConstants.BuildFeatureOnDemand.CONTROLLER_ROOT}"
            context.addSharedParameter(OIDCConstants.BuildFeatureOnDemand.ENDPOINT_URL_PARAM, endpointUrl)
        }

        // Exit early if no in-param build features are present
        val features = build.oidcInParamsBuildFeatures()
        if (features.isEmpty()) return

        // Pre-fetch JWT parameters outside the loop to prevent unnecessary lookups and drift
        val project = projectManager.findProjectById(build.projectId)
        if (project == null) {
            context.build.addBuildProblem(
                BuildProblemData.createBuildProblem(
                    OIDCConstants.Injection.PROJECT_LOOKUP_ERROR_IDENTITY + build.projectId.hashCode(),
                    OIDCConstants.Injection.PROJECT_LOOKUP_ERROR_MESSAGE,
                    "Project with ID ${build.projectId} not found"
                )
            )
            return
        }
        val signer = try {
            registry.getActiveSigner()
        } catch (e: Exception) {
            LOG.error("Failed to get active signer", e)
            context.build.addBuildProblem(
                BuildProblemData.createBuildProblem(
                    OIDCConstants.Injection.SIGNER_LOOKUP_ERROR_IDENTITY + e.message.hashCode(),
                    OIDCConstants.Injection.SIGNER_LOOKUP_ERROR_MESSAGE,
                    e.message
                )
            )
            return
        }
        val effectiveIssuer = settings.getEffectiveIssuer()

        val usedParams = mutableSetOf<String>()

        // Issue JWTs for each in-param build feature
        val tokens = mutableListOf<IssuedToken>()
        for (feature in features) {
            val param = feature.oidcBuildParameter()
            // Add a problem for duplicated parameter names and stop
            if (param in usedParams) {
                context.build.addBuildProblem(
                    BuildProblemData.createBuildProblem(
                        OIDCConstants.Injection.DUPLICATE_INJECTION_PARAM_ERROR_IDENTITY + param.hashCode(),
                        OIDCConstants.Injection.DUPLICATE_INJECTION_PARAM_ERROR_MESSAGE,
                        "The '$param' parameter is already provided by another '${OIDCConstants.BuildFeatureInParams.DISPLAY_NAME}' build feature"
                    )
                )
                return
            }

            // Generate JWT claims
            val audiences = feature.oidcInParamsAudiences(effectiveIssuer)
            val lifetime = feature.oidcTokenLifetime(build.buildType?.executionTimeoutMin ?: 0)
            val generatedClaim =
                JWTClaimsGenerator.generate(effectiveIssuer, audiences, project, build, lifetime, clock)

            // Sign the claims
            val signed = try {
                signer.makeJWT(build, generatedClaim.claims, generatedClaim.expiresAt)
            } catch (e: Exception) {
                LOG.error("Failed to sign JWT", e)
                val description = "Failed to sign JWT: " + e.message
                context.build.addBuildProblem(
                    // TODO Add info about the particular build feature that failed
                    BuildProblemData.createBuildProblem(
                        OIDCConstants.Injection.TOKEN_GENERATION_ERROR_IDENTITY + description.hashCode(),
                        OIDCConstants.Injection.TOKEN_GENERATION_ERROR_MESSAGE,
                        description
                    )
                )
                return
            }

            usedParams.add(param)
            tokens.add(IssuedToken(param, signed, generatedClaim.expiresAt))
        }

        // Inject the tokens into the build parameters in a separate loop to prevent leaking tokens on duplicate errors.
        // It's all or nothing, because the build will most likely fail without all the tokens anyway. This, and we need
        // to mask the token values, which might or might not happen if we fail the build from our processor.
        for (token in tokens) {
            context.addSharedParameter(token.param, token.token)
        }

        // A little housekeeping here: because the order of context processors might differ from instance to instance,
        // there could be faulty processors between us and `PasswordsBuildStartContextProcessor` (which calls
        // `getPasswordParameters` that removes tokens from the map), failures in which will lead to a memory leak.
        //
        // So, clean up the expired tokens whenever we issue a new one. I wish there could be a better solution,
        // but I'm yet to discover it.
        //
        // Please note that we drop the token records as soon as at least one of the tokens expires since the build
        // will probably fail at some point anyway.
        val now = Instant.now(clock)
        issuedTokens.filter { (_, tokens) -> tokens.any { it.expiresAt.isBefore(now) } }
            .forEach { (buildId, _) -> issuedTokens.remove(buildId) }
        issuedTokens[context.build.buildId] = tokens
    }

    override fun getOrderId(): String {
        return this.javaClass.name
    }

    override fun getConstraint(): PositionConstraint {
        // This processor calls the `getPasswordParameters` method, so it MUST go after we've stored the token
        return PositionConstraint.before(
            "jetbrains.buildServer.serverSide.parameters.types.PasswordsBuildStartContextProcessor")
    }

    override fun getPasswordParameters(build: SBuild): Collection<Parameter> {
        val tokens = issuedTokens.remove(build.buildId) ?: return emptyList()
        // Mark each issued token parameter as a password.
        return tokens.map {
            paramFactory.createTypedParameter(it.param, it.token, "password")
        }
    }
}
