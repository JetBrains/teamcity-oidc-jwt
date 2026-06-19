package org.jetbrains.teamcity.builds.oidc.buildfeature.inparams

import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test

class InParamsPropertiesProcessorTest : BaseTestCase() {

    private val processor = OIDCTokenInParamsBuildFeature.InParamsPropertiesProcessor()

    @Test
    fun nullParams_returnsNoErrors() {
        val result = processor.process(null)

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun missingTokenLifetime_returnsNoErrors() {
        val result = processor.process(emptyMap())

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun emptyTokenLifetime_returnsNoErrors() {
        val result = processor.process(mapOf("tokenLifetimeSeconds" to ""))

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun blankTokenLifetime_returnsNoErrors() {
        val result = processor.process(mapOf("tokenLifetimeSeconds" to "   "))

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun validNumericTokenLifetime_returnsNoErrors() {
        val result = processor.process(mapOf("tokenLifetimeSeconds" to "600"))

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun nonNumericTokenLifetime_returnsInvalidProperty() {
        val result = processor.process(mapOf("tokenLifetimeSeconds" to "notANumber"))

        Assertions.assertThat(result).hasSize(1)
        val error = result.first()
        Assertions.assertThat(error!!.propertyName).isEqualTo("tokenLifetimeSeconds")
        Assertions.assertThat(error.invalidReason).isEqualTo("Invalid token lifetime")
    }
}
