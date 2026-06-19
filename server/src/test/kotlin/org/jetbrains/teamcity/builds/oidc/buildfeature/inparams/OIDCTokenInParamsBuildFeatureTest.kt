package org.jetbrains.teamcity.builds.oidc.buildfeature.inparams

import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcBuildParameter
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcInParamsAudiences
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcInParamsBuildFeatures
import org.jetbrains.teamcity.builds.oidc.buildfeature.inparams.OIDCTokenInParamsBuildFeature.Companion.oidcTokenLifetime
import jetbrains.buildServer.serverSide.BuildFeature
import jetbrains.buildServer.serverSide.BuildTypeIdentity
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*

class OIDCTokenInParamsBuildFeatureTest : BaseTestCase() {

    private val pluginDescriptor = mockk<PluginDescriptor>()
    private val settings = mockk<OIDCSettings> {
        every { getEffectiveIssuer() } returns "https://issuer.example.com"
    }
    private val feature = OIDCTokenInParamsBuildFeature(pluginDescriptor, settings)

    private fun descriptorWith(params: Map<String, String>): SBuildFeatureDescriptor =
        mockk<SBuildFeatureDescriptor> { every { parameters } returns params }

    private fun defaultParams(vararg overrides: Pair<String, String>): Map<String, String> {
        val base = mutableMapOf(
            "audiences" to "https://issuer.example.com",
            "buildParam" to "teamcity.build.oidc.token",
            "tokenLifetimeSeconds" to ""
        )
        overrides.forEach { (k, v) -> base[k] = v }
        return base
    }

    @Test
    fun getType_returnsOidcTokenInParameters() {
        Assertions.assertThat(feature.type).isEqualTo("oidcTokenInParams")
    }

    @Test
    fun getDisplayName_returnsOIDCToken() {
        Assertions.assertThat(feature.displayName).isEqualTo("OIDC Token (in build parameters)")
    }

    @Test
    fun isRequiresAgent_returnsFalse() {
        Assertions.assertThat(feature.isRequiresAgent).isFalse()
    }

    @Test
    fun isMultipleFeaturesPerBuildTypeAllowed_returnsTrue() {
        Assertions.assertThat(feature.isMultipleFeaturesPerBuildTypeAllowed).isTrue()
    }

    @Test
    fun getPlaceToShow_returnsGeneral() {
        Assertions.assertThat(feature.placeToShow).isEqualTo(BuildFeature.PlaceToShow.GENERAL)
    }

    @Test
    fun getEditParametersUrl_delegatesToPluginDescriptor() {
        every { pluginDescriptor.getPluginResourcesPath("oidcTokenInParamsBuildFeature.html") } returns
            "/plugins/oidc/oidcTokenInParamsBuildFeature.html"

        Assertions.assertThat(feature.editParametersUrl).isEqualTo("/plugins/oidc/oidcTokenInParamsBuildFeature.html")
    }

    @Test
    fun getParametersProcessor_returnsPropertiesProcessor() {
        val processor = feature.getParametersProcessor(mockk<BuildTypeIdentity>())

        Assertions.assertThat(processor).isInstanceOf(OIDCTokenInParamsBuildFeature.InParamsPropertiesProcessor::class.java)
    }

    @Test
    fun getParametersProcessor_returnsSameInstance() {
        val first = feature.getParametersProcessor(mockk<BuildTypeIdentity>())
        val second = feature.getParametersProcessor(mockk<BuildTypeIdentity>())

        Assertions.assertThat(first).isSameAs(second)
    }

    @Test
    fun getDefaultParameters_returnsExpectedDefaults() {
        val defaults = feature.defaultParameters

        Assertions.assertThat(defaults).hasSize(3)
        Assertions.assertThat(defaults["audiences"]).isEqualTo("https://issuer.example.com")
        Assertions.assertThat(defaults["buildParam"]).isEqualTo("env.TEAMCITY_BUILD_OIDC_TOKEN")
        Assertions.assertThat(defaults["tokenLifetimeSeconds"]).isEqualTo("")
    }

    @Test
    fun describeParameters_withSingleAudience_showsAudienceInList() {
        val result = feature.describeParameters(defaultParams("audiences" to "https://my-audience"))

        Assertions.assertThat(result).contains("* https://my-audience")
        Assertions.assertThat(result).doesNotContain("(default)")
    }

    @Test
    fun describeParameters_withMultipleAudiences_showsAllAudiences() {
        val result = feature.describeParameters(defaultParams("audiences" to "aud1\naud2\naud3"))

        Assertions.assertThat(result).contains("* aud1")
        Assertions.assertThat(result).contains("* aud2")
        Assertions.assertThat(result).contains("* aud3")
        Assertions.assertThat(result).doesNotContain("(default)")
    }

    @Test
    fun describeParameters_withEmptyAudiences_showsDefaultIssuer() {
        val result = feature.describeParameters(defaultParams("audiences" to ""))

        Assertions.assertThat(result).contains("* https://issuer.example.com (default)")
    }

    @Test
    fun describeParameters_withWhitespaceAudiences_trimsAndFilters() {
        val result = feature.describeParameters(defaultParams("audiences" to "  aud1  \n  \n  aud2  "))

        Assertions.assertThat(result).contains("* aud1")
        Assertions.assertThat(result).contains("* aud2")
        Assertions.assertThat(result).doesNotContain("(default)")
    }

    @Test
    fun describeParameters_showsBuildParam() {
        val result = feature.describeParameters(
            defaultParams("buildParam" to "my.param")
        )

        Assertions.assertThat(result).contains("Pass JWT via the 'my.param' build parameter.")
    }

    @Test
    fun describeParameters_showsDefaultBuildParam_whenBuildParamIsNull() {
        val result = feature.describeParameters(
            mapOf()
        )

        Assertions.assertThat(result).contains("Pass JWT via the 'env.TEAMCITY_BUILD_OIDC_TOKEN' build parameter.")
    }

    @Test
    fun describeParameters_showsDefaultBuildParam_whenBuildParamIsEmpty() {
        val result = feature.describeParameters(
            defaultParams("buildParam" to "")
        )

        Assertions.assertThat(result).contains("Pass JWT via the 'env.TEAMCITY_BUILD_OIDC_TOKEN' build parameter.")
    }

    @Test
    fun describeParameters_withNoTokenLifetime_showsBuildTimeoutBased() {
        val result = feature.describeParameters(defaultParams("tokenLifetimeSeconds" to ""))

        Assertions.assertThat(result).contains("600 seconds after the build timeout.")
    }

    @Test
    fun describeParameters_withCustomTokenLifetime_showsCustomValue() {
        val result = feature.describeParameters(defaultParams("tokenLifetimeSeconds" to "3600"))

        Assertions.assertThat(result).contains("3600 seconds.")
        Assertions.assertThat(result).doesNotContain("after the build timeout")
    }

    @Test
    fun describeParameters_withZeroTokenLifetime_showsBuildTimeoutBased() {
        val result = feature.describeParameters(defaultParams("tokenLifetimeSeconds" to "0"))

        Assertions.assertThat(result).contains("600 seconds after the build timeout.")
    }

    @Test
    fun describeParameters_withNegativeTokenLifetime_showsBuildTimeoutBased() {
        val result = feature.describeParameters(defaultParams("tokenLifetimeSeconds" to "-5"))

        Assertions.assertThat(result).contains("600 seconds after the build timeout.")
    }

    @Test
    fun describeParameters_withNonNumericTokenLifetime_showsBuildTimeoutBased() {
        val result = feature.describeParameters(defaultParams("tokenLifetimeSeconds" to "abc"))

        Assertions.assertThat(result).contains("600 seconds after the build timeout.")
    }

    @Test
    fun oidcAudiences_withMultipleAudiences_returnsAll() {
        val descriptor = descriptorWith(mapOf("audiences" to "aud1\naud2"))

        Assertions.assertThat(descriptor.oidcInParamsAudiences("fallback")).isEqualTo(setOf("aud1", "aud2"))
    }

    @Test
    fun oidcAudiences_withEmptyAudiences_returnsDefault() {
        val descriptor = descriptorWith(mapOf("audiences" to ""))

        Assertions.assertThat(descriptor.oidcInParamsAudiences("https://default.example.com"))
            .isEqualTo(setOf("https://default.example.com"))
    }

    @Test
    fun oidcAudiences_withMissingKey_returnsDefault() {
        val descriptor = descriptorWith(emptyMap())

        Assertions.assertThat(descriptor.oidcInParamsAudiences("https://default.example.com"))
            .isEqualTo(setOf("https://default.example.com"))
    }

    @Test
    fun oidcAudiences_withBlankLines_filtersOut() {
        val descriptor = descriptorWith(mapOf("audiences" to "aud1\n\n  \naud2"))

        Assertions.assertThat(descriptor.oidcInParamsAudiences("fallback")).isEqualTo(setOf("aud1", "aud2"))
    }

    @Test
    fun oidcAudiences_withDuplicates_deduplicates() {
        val descriptor = descriptorWith(mapOf("audiences" to "aud1\naud1\naud2"))

        Assertions.assertThat(descriptor.oidcInParamsAudiences("fallback")).isEqualTo(setOf("aud1", "aud2"))
    }

    @Test
    fun oidcTokenLifetime_withCustomLifetime_returnsExactValue() {
        val descriptor = descriptorWith(mapOf("tokenLifetimeSeconds" to "3600"))

        Assertions.assertThat(descriptor.oidcTokenLifetime(30)).isEqualTo(3600L)
    }

    @Test
    fun oidcTokenLifetime_withNoLifetime_returnsBuildTimeoutPlusBuffer() {
        val descriptor = descriptorWith(mapOf("tokenLifetimeSeconds" to ""))

        Assertions.assertThat(descriptor.oidcTokenLifetime(30)).isEqualTo((30 + 10) * 60L)
    }

    @Test
    fun oidcTokenLifetime_withZeroLifetime_returnsBuildTimeoutPlusBuffer() {
        val descriptor = descriptorWith(mapOf("tokenLifetimeSeconds" to "0"))

        Assertions.assertThat(descriptor.oidcTokenLifetime(60)).isEqualTo((60 + 10) * 60L)
    }

    @Test
    fun oidcBuildParameter_withValue_returnsValue() {
        val descriptor = descriptorWith(mapOf("buildParam" to "my.custom.param"))

        Assertions.assertThat(descriptor.oidcBuildParameter()).isEqualTo("my.custom.param")
    }

    @Test
    fun oidcBuildParameter_withBlank_returnsDefault() {
        val descriptor = descriptorWith(mapOf("buildParam" to ""))

        Assertions.assertThat(descriptor.oidcBuildParameter()).isEqualTo("env.TEAMCITY_BUILD_OIDC_TOKEN")
    }

    @Test
    fun oidcBuildParameter_withMissingKey_returnsDefault() {
        val descriptor = descriptorWith(emptyMap())

        Assertions.assertThat(descriptor.oidcBuildParameter()).isEqualTo("env.TEAMCITY_BUILD_OIDC_TOKEN")
    }

    @Test
    fun oidcBuildFeatures_delegatesToGetBuildFeaturesOfType() {
        val descriptor = mockk<SBuildFeatureDescriptor>()
        val build = mockk<SBuild>()
        every { build.getBuildFeaturesOfType("oidcTokenInParams") } returns listOf(descriptor)

        val result = build.oidcInParamsBuildFeatures()

        Assertions.assertThat(result.toList()).isEqualTo(listOf(descriptor))
    }
}
