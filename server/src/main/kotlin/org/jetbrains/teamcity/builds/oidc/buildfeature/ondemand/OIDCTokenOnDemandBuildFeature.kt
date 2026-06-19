package org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand

import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuildFeatureOnDemand.AUDIENCES_PARAM
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuildFeatureOnDemand.DISPLAY_NAME
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuildFeatureOnDemand.FEATURE_TYPE
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import jetbrains.buildServer.serverSide.BuildFeature
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor
import jetbrains.buildServer.web.openapi.PluginDescriptor

class OIDCTokenOnDemandBuildFeature(
    private val pluginDescriptor: PluginDescriptor,
    private val settings: OIDCSettings
) : BuildFeature() {

    override fun getType(): String = FEATURE_TYPE

    override fun getDisplayName(): String = DISPLAY_NAME

    override fun isRequiresAgent(): Boolean = false

    override fun isMultipleFeaturesPerBuildTypeAllowed(): Boolean = true

    override fun getPlaceToShow(): PlaceToShow = PlaceToShow.GENERAL

    // Return HTML path as it gets handled by OIDCTokenBuildFeatureController.
    // This way we can add OIDC config URL to the view.
    override fun getEditParametersUrl(): String =
        pluginDescriptor.getPluginResourcesPath(OIDCConstants.BuildFeatureOnDemand.BUILD_FEATURE_PATH_HTML)

    override fun getDefaultParameters(): Map<String, String> = mapOf(
        AUDIENCES_PARAM to settings.getEffectiveIssuer(),
    )

    override fun describeParameters(params: Map<String, String>): String {
        val result = StringBuilder()
        result.append("Allowed audiences: ")
        val audiences = parseAudiences(params)
        result.append(
            if (audiences.isNotEmpty()) audiences.joinToString("\n* ", prefix = "\n* ")
            else "\n* ${settings.getEffectiveIssuer()} (default)"
        )
        return result.toString()
    }

    companion object {
        private fun parseAudiences(params: Map<String, String>): List<String> =
            params[AUDIENCES_PARAM]
                ?.lines()
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                ?: emptyList()

        fun SBuildFeatureDescriptor.oidcOnDemandAudiences(default: String): Set<String> =
            parseAudiences(this.parameters).ifEmpty { listOf(default) }.toSet()

        fun SBuild.oidcOnDemandBuildFeatures(): Collection<SBuildFeatureDescriptor> =
            this.getBuildFeaturesOfType(FEATURE_TYPE)
    }
}
