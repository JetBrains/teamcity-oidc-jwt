package org.jetbrains.teamcity.builds.oidc.injection

import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcInParamsBuildFeatures
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcBuildParameter
import org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand.OIDCTokenOnDemandBuildFeature.Companion.oidcOnDemandBuildFeatures
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.parameters.BuildParametersProvider

/**
 * OIDCTokenBuildParametersProvider allows the builds using OIDC parameters
 * to start without "No compatible agents" errors.
 *
 * It notifies TeamCity that the parameters will be available on the agent.
 * The actual injection happens in [OIDCTokenBuildStartContextProcessor] because
 * unlike [BuildParametersProvider]s, context processors are called right before
 * the build starts, which is critical for JWTs since they have a limited lifetime.
 */
class OIDCTokenBuildParametersProvider: BuildParametersProvider {
    override fun getParameters(
        build: SBuild,
        emulationMode: Boolean
    ): Map<String?, String?> {
        return emptyMap()
    }

    override fun getParametersAvailableOnAgent(build: SBuild): Collection<String?> {
        val result = mutableListOf<String>()

        val onDemandFeatures = build.oidcOnDemandBuildFeatures()
        if (onDemandFeatures.isNotEmpty()) {
            result.add(OIDCConstants.BuildFeatureOnDemand.ENDPOINT_URL_PARAM)
        }

        val inParamsFeatures = build.oidcInParamsBuildFeatures()
        inParamsFeatures.forEach { feature ->
            feature.oidcBuildParameter().let { result.add(it) }
        }

        return result
    }
}
