package org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand

import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand.OIDCTokenOnDemandBuildFeature.Companion.oidcOnDemandAudiences
import org.jetbrains.teamcity.builds.oidc.buildfeature.ondemand.OIDCTokenOnDemandBuildFeature.Companion.oidcOnDemandBuildFeatures
import jetbrains.buildServer.serverSide.BuildFeature
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*

class OIDCTokenOnDemandBuildFeatureTest : BaseTestCase() {

    private val pluginDescriptor = mockk<PluginDescriptor>()
    private val settings = mockk<OIDCSettings> {
        every { getEffectiveIssuer() } returns "https://issuer.example.com"
    }
    private val feature = OIDCTokenOnDemandBuildFeature(pluginDescriptor, settings)

    private fun descriptorWith(params: Map<String, String>): SBuildFeatureDescriptor =
        mockk<SBuildFeatureDescriptor> { every { parameters } returns params }

    @Test
    fun getType_returnsOidcTokenOnDemand() {
        Assertions.assertThat(feature.type).isEqualTo("oidcTokenOnDemand")
    }

    @Test
    fun getDisplayName_returnsOIDCTokenOnDemand() {
        Assertions.assertThat(feature.displayName).isEqualTo("OIDC Token (on demand via HTTP request)")
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
        every { pluginDescriptor.getPluginResourcesPath("oidcTokenOnDemandBuildFeature.html") } returns
            "/plugins/oidc/oidcTokenOnDemandBuildFeature.html"

        Assertions.assertThat(feature.editParametersUrl).isEqualTo("/plugins/oidc/oidcTokenOnDemandBuildFeature.html")
    }

    @Test
    fun getDefaultParameters_returnsExpectedDefaults() {
        val defaults = feature.defaultParameters

        Assertions.assertThat(defaults).hasSize(1)
        Assertions.assertThat(defaults["audiences"]).isEqualTo("https://issuer.example.com")
    }

    @Test
    fun describeParameters_withSingleAudience_showsAudienceInList() {
        val result = feature.describeParameters(mapOf("audiences" to "https://my-audience"))

        Assertions.assertThat(result).contains("* https://my-audience")
        Assertions.assertThat(result).doesNotContain("(default)")
    }

    @Test
    fun describeParameters_withMultipleAudiences_showsAllAudiences() {
        val result = feature.describeParameters(mapOf("audiences" to "aud1\naud2\naud3"))

        Assertions.assertThat(result).contains("* aud1")
        Assertions.assertThat(result).contains("* aud2")
        Assertions.assertThat(result).contains("* aud3")
        Assertions.assertThat(result).doesNotContain("(default)")
    }

    @Test
    fun describeParameters_withEmptyAudiences_showsDefaultIssuer() {
        val result = feature.describeParameters(mapOf("audiences" to ""))

        Assertions.assertThat(result).contains("* https://issuer.example.com (default)")
    }

    @Test
    fun describeParameters_withWhitespaceAudiences_trimsAndFilters() {
        val result = feature.describeParameters(mapOf("audiences" to "  aud1  \n  \n  aud2  "))

        Assertions.assertThat(result).contains("* aud1")
        Assertions.assertThat(result).contains("* aud2")
        Assertions.assertThat(result).doesNotContain("(default)")
    }

    @Test
    fun describeParameters_withMissingKey_showsDefaultIssuer() {
        val result = feature.describeParameters(emptyMap())

        Assertions.assertThat(result).contains("* https://issuer.example.com (default)")
    }

    @Test
    fun oidcOnDemandAudiences_withMultipleAudiences_returnsAll() {
        val descriptor = descriptorWith(mapOf("audiences" to "aud1\naud2"))

        Assertions.assertThat(descriptor.oidcOnDemandAudiences("fallback")).isEqualTo(setOf("aud1", "aud2"))
    }

    @Test
    fun oidcOnDemandAudiences_withEmptyAudiences_returnsDefault() {
        val descriptor = descriptorWith(mapOf("audiences" to ""))

        Assertions.assertThat(descriptor.oidcOnDemandAudiences("https://default.example.com"))
            .isEqualTo(setOf("https://default.example.com"))
    }

    @Test
    fun oidcOnDemandAudiences_withMissingKey_returnsDefault() {
        val descriptor = descriptorWith(emptyMap())

        Assertions.assertThat(descriptor.oidcOnDemandAudiences("https://default.example.com"))
            .isEqualTo(setOf("https://default.example.com"))
    }

    @Test
    fun oidcOnDemandAudiences_withBlankLines_filtersOut() {
        val descriptor = descriptorWith(mapOf("audiences" to "aud1\n\n  \naud2"))

        Assertions.assertThat(descriptor.oidcOnDemandAudiences("fallback")).isEqualTo(setOf("aud1", "aud2"))
    }

    @Test
    fun oidcOnDemandAudiences_withDuplicates_deduplicates() {
        val descriptor = descriptorWith(mapOf("audiences" to "aud1\naud1\naud2"))

        Assertions.assertThat(descriptor.oidcOnDemandAudiences("fallback")).isEqualTo(setOf("aud1", "aud2"))
    }

    @Test
    fun oidcOnDemandBuildFeatures_delegatesToGetBuildFeaturesOfType() {
        val descriptor = mockk<SBuildFeatureDescriptor>()
        val build = mockk<SBuild>()
        every { build.getBuildFeaturesOfType("oidcTokenOnDemand") } returns listOf(descriptor)

        val result = build.oidcOnDemandBuildFeatures()

        Assertions.assertThat(result.toList()).isEqualTo(listOf(descriptor))
    }
}
