package org.jetbrains.teamcity.builds.oidc.signer.gcp.client.util

import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSInvalidResourceNameException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSNoResourceNameException
import org.testng.annotations.Test

class ResourceNameValidationTest: BaseTestCase() {
    private val VALID_KEY = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
    private val VALID_KEY_VERSION_1 = "$VALID_KEY/cryptoKeyVersions/1"
    private val VALID_KEY_VERSION_3 = "$VALID_KEY/cryptoKeyVersions/3"

    @Test
    fun validateKeyResourceNameBlank_throwsNoResourceName() {
        Assertions.assertThatThrownBy {
            validateKeyResourceName("")
        }.isInstanceOf(CloudKMSNoResourceNameException::class.java)
        Assertions.assertThatThrownBy {
            validateKeyResourceName("   ")
        }.isInstanceOf(CloudKMSNoResourceNameException::class.java)
    }

    @Test
    fun validateKeyResourceNameInvalid_throwsInvalidResourceName() {
        Assertions.assertThatThrownBy {
            validateKeyResourceName("projects/p/locations/global/keyRings/r")
        }.isInstanceOf(CloudKMSInvalidResourceNameException::class.java)
        Assertions.assertThatThrownBy {
            validateKeyResourceName("projects//locations/global/keyRings/r/cryptoKeys/k")
        }.isInstanceOf(CloudKMSInvalidResourceNameException::class.java)
        Assertions.assertThatThrownBy {
            validateKeyResourceName("$VALID_KEY/cryptoKeyVersions/1/extra")
        }.isInstanceOf(CloudKMSInvalidResourceNameException::class.java)
    }

    @Test
    fun validateKeyResourceNameCryptoKeyForm_doesNotThrow() {
        Assertions.assertThatCode { validateKeyResourceName(VALID_KEY) }.doesNotThrowAnyException()
    }

    @Test
    fun validateKeyResourceNameCryptoKeyVersionForm_doesNotThrow() {
        Assertions.assertThatCode { validateKeyResourceName(VALID_KEY_VERSION_1) }.doesNotThrowAnyException()
    }
}
