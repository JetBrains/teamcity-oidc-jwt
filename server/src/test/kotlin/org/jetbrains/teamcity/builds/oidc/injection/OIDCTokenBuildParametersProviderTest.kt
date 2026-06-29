package org.jetbrains.teamcity.builds.oidc.injection

import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*

class OIDCTokenBuildParametersProviderTest : BaseTestCase() {

    private val provider = OIDCTokenBuildParametersProvider()

    private fun createInParamsDescriptor(
        buildParam: String? = null,
    ): SBuildFeatureDescriptor {
        val params = mutableMapOf<String, String>()
        if (buildParam != null) params["buildParam"] = buildParam
        return mockk<SBuildFeatureDescriptor> {
            every { parameters } returns params
        }
    }

    private fun mockBuild(
        inParamsFeatures: List<SBuildFeatureDescriptor> = emptyList()
    ): SBuild {
        val build = mockk<SBuild>()
        every { build.getBuildFeaturesOfType("oidcTokenOnDemand") } throws Exception("Should not be called")
        every { build.getBuildFeaturesOfType("oidcTokenInParams") } returns inParamsFeatures
        return build
    }

    @Test
    fun getParameters_returnsEmptyMap() {
        val build = mockBuild()

        val result = provider.getParameters(build, false)

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun getParametersAvailableOnAgent_noFeatures_returnsEmpty() {
        val build = mockBuild()

        val result = provider.getParametersAvailableOnAgent(build)

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun getParametersAvailableOnAgent_oneInParamsFeature_addsBuildParam() {
        val descriptor = createInParamsDescriptor(buildParam = "my.param")
        val build = mockBuild(inParamsFeatures = listOf(descriptor))

        val result = provider.getParametersAvailableOnAgent(build)

        Assertions.assertThat(result.toList()).isEqualTo(listOf("my.param"))
    }

    @Test
    fun getParametersAvailableOnAgent_multipleInParamsFeatures_addsAllParams() {
        val descriptor1 = createInParamsDescriptor(buildParam = "param.one")
        val descriptor2 = createInParamsDescriptor(buildParam = "param.two")
        val build = mockBuild(inParamsFeatures = listOf(descriptor1, descriptor2))

        val result = provider.getParametersAvailableOnAgent(build)

        Assertions.assertThat(result.toList()).isEqualTo(listOf("param.one", "param.two"))
    }
}
