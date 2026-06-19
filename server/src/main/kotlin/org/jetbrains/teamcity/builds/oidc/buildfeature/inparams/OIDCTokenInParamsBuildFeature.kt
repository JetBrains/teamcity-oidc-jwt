package org.jetbrains.teamcity.builds.oidc.buildfeature.inparams

import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import jetbrains.buildServer.serverSide.BuildFeature
import jetbrains.buildServer.serverSide.BuildTypeIdentity
import jetbrains.buildServer.serverSide.InvalidProperty
import jetbrains.buildServer.serverSide.PropertiesProcessor
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor
import jetbrains.buildServer.web.openapi.PluginDescriptor

class OIDCTokenInParamsBuildFeature(
    private val pluginDescriptor: PluginDescriptor,
    private val settings: OIDCSettings
) : BuildFeature() {

    override fun getType(): String = OIDCConstants.BuildFeatureInParams.FEATURE_TYPE

    override fun getDisplayName(): String = OIDCConstants.BuildFeatureInParams.DISPLAY_NAME

    override fun isRequiresAgent(): Boolean = false

    override fun isMultipleFeaturesPerBuildTypeAllowed(): Boolean = true

    override fun getPlaceToShow(): PlaceToShow = PlaceToShow.GENERAL

    private val propertiesProcessor: PropertiesProcessor = InParamsPropertiesProcessor()

    override fun getParametersProcessor(buildTypeOrTemplate: BuildTypeIdentity): PropertiesProcessor {
        return propertiesProcessor
    }

    // Return HTML path as it gets handled by OIDCTokenBuildFeatureController.
    // This way we can add OIDC config URL to the view.
    override fun getEditParametersUrl(): String =
        pluginDescriptor.getPluginResourcesPath(OIDCConstants.BuildFeatureInParams.BUILD_FEATURE_PATH_HTML)

    override fun getDefaultParameters(): Map<String, String> = mapOf(
        OIDCConstants.BuildFeatureInParams.AUDIENCES_PARAM to settings.getEffectiveIssuer(),
        OIDCConstants.BuildFeatureInParams.BUILDPARAM_PARAM to OIDCConstants.BuildFeatureInParams.DEFAULT_BUILDPARAM,
        OIDCConstants.BuildFeatureInParams.TOKEN_LIFETIME_SECONDS_PARAM to "",
    )

    override fun describeParameters(params: Map<String, String>): String {
        val result = StringBuilder()
        result.append("Audiences: ")
        val audiences = parseAudiences(params)
        result.append(
            if (audiences.isNotEmpty()) audiences.joinToString("\n* ", prefix = "\n* ")
            else "\n* ${settings.getEffectiveIssuer()} (default)"
        )
        result.append("\n\n")

        val buildParam = getOidcBuildParameter(params)
        result.append("Pass JWT via the '$buildParam' build parameter.")

        val tokenLifetime = getTokenLifetimeOrMarker(params)
        result.append("\n\nToken will expire ")
        result.append(if (tokenLifetime == DEFAULT_TOKEN_LIFETIME_MARKER) {
            "${OIDCConstants.BuildFeatureInParams.JWT_LIFETIME_BUFFER_MINUTES * 60} seconds after the build timeout."
        } else {
            "in $tokenLifetime seconds."
        })
        return result.toString()
    }

    /*
     * InParamsPropertiesProcessor validates the properties of the build feature.
     */
    internal class InParamsPropertiesProcessor: PropertiesProcessor {
        override fun process(params: Map<String?, String?>?): Collection<InvalidProperty?> {
            val tokenLifetime = params?.get(OIDCConstants.BuildFeatureInParams.TOKEN_LIFETIME_SECONDS_PARAM)
            // If there's a token lifetime value, it must be a number
            if (tokenLifetime?.isBlank() == false && tokenLifetime.toLongOrNull() == null) {
                return listOf(
                    InvalidProperty(
                        OIDCConstants.BuildFeatureInParams.TOKEN_LIFETIME_SECONDS_PARAM,
                        "Invalid token lifetime"
                    )
                )
            }
            return emptyList()
        }
    }

    companion object {
        private fun parseAudiences(params: Map<String, String>): List<String> =
            params[OIDCConstants.BuildFeatureInParams.AUDIENCES_PARAM]
                ?.lines()
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                ?: emptyList()

        private const val DEFAULT_TOKEN_LIFETIME_MARKER = -1L

        private fun getTokenLifetimeOrMarker(params: Map<String, String>): Long =
            params[OIDCConstants.BuildFeatureInParams.TOKEN_LIFETIME_SECONDS_PARAM]?.toLongOrNull()?.let {
                if (it > 0) it else null
            } ?: DEFAULT_TOKEN_LIFETIME_MARKER

        private fun getOidcBuildParameter(params: Map<String, String>): String =
            params[OIDCConstants.BuildFeatureInParams.BUILDPARAM_PARAM]?.ifBlank { null }
                ?: OIDCConstants.BuildFeatureInParams.DEFAULT_BUILDPARAM

        fun SBuildFeatureDescriptor.oidcTokenLifetime(buildTimeoutMins: Int): Long {
            val lifetime = getTokenLifetimeOrMarker(this.parameters)
            return if (lifetime != DEFAULT_TOKEN_LIFETIME_MARKER) lifetime
                else (buildTimeoutMins + OIDCConstants.BuildFeatureInParams.JWT_LIFETIME_BUFFER_MINUTES) * 60L
        }

        fun SBuildFeatureDescriptor.oidcInParamsAudiences(default: String): Set<String> =
            parseAudiences(this.parameters).ifEmpty { listOf(default) }.toSet()

        fun SBuildFeatureDescriptor.oidcBuildParameter(): String =
            getOidcBuildParameter(this.parameters)

        fun SBuild.oidcInParamsBuildFeatures(): Collection<SBuildFeatureDescriptor> =
            this.getBuildFeaturesOfType(OIDCConstants.BuildFeatureInParams.FEATURE_TYPE)
    }
}
