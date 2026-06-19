package org.jetbrains.teamcity.builds.oidc.signer.gcp.admin

import com.google.cloud.kms.v1.CryptoKeyVersion
import com.google.cloud.kms.v1.CryptoKeyVersionName
import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSSettings
import org.jetbrains.teamcity.builds.oidc.signer.gcp.JWTKeyVersion
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.CloudKMSDefaultClient
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.GCPCredentials
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*

class CloudKMSAdminSettingsTest : BaseTestCase() {
    private lateinit var pluginDescriptor: PluginDescriptor
    private lateinit var settings: CloudKMSSettings
    private lateinit var defaultClient: CloudKMSDefaultClient
    private lateinit var connectionChecker: CloudKMSConnectionChecker
    private lateinit var adminSettings: CloudKMSAdminSettings

    private val validResourceName = "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        pluginDescriptor = mockk {
            every { getPluginResourcesPath("gcp-kms.jsp") } returns "/plugins/gcp-kms/gcp-kms.jsp"
        }
        settings = mockk {
            every { getCredentials() } returns GCPCredentials.Environment(null)
        }
        defaultClient = mockk()
        connectionChecker = mockk {
            every { check(any(), anyNullable(), anyNullable(), anyNullable(), any()) } returns CloudKMSConnectionChecker.Result(success = true)
        }
        adminSettings = CloudKMSAdminSettings(pluginDescriptor, settings, defaultClient, connectionChecker)
    }

    private fun createKeyVersion(
        name: CryptoKeyVersionName = CryptoKeyVersionName.of("p", "global", "r", "k", "1"),
        gcpAlg: CryptoKeyVersion.CryptoKeyVersionAlgorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256,
        jwsAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256,
    ): JWTKeyVersion {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val jwk: JWK = RSAKey.Builder(keyPair.public as RSAPublicKey)
            .algorithm(jwsAlgorithm)
            .keyID("test")
            .build()
        return JWTKeyVersion(
            name = name,
            gcpAlg = gcpAlg,
            publicJwk = jwk,
            jwsHeaderStr = "header",
            resolvedFromKey = false,
        )
    }

    private fun captureCheckEndpoint(): String? {
        val slot = slot<String?>()
        verify { connectionChecker.check(any(), anyNullable(), anyNullable(), captureNullable(slot), any()) }
        return slot.captured
    }

    @Test
    fun getSettingsPagePath_returnsPathFromPluginDescriptor() {
        Assertions.assertThat(adminSettings.getSettingsPagePath()).isEqualTo("/plugins/gcp-kms/gcp-kms.jsp")
        verify { pluginDescriptor.getPluginResourcesPath("gcp-kms.jsp") }
    }

    @Test
    fun fillSettingsModel_happyPath_populatesAllFields() {
        every { settings.getCredentials() } returns GCPCredentials.ServiceAccount("{json}", "sa@example.com")
        every { settings.getGCPEndpoint() } returns "kms.example.com:443"
        every { settings.getKeyResourceName() } returns validResourceName
        val keyVersionName = CryptoKeyVersionName.of("p", "global", "r", "k", "1")
        every { defaultClient.getKeyVersion(validResourceName, false) } returns createKeyVersion(name = keyVersionName)

        val model = mutableMapOf<String, Any>()
        adminSettings.fillSettingsModel(model)

        Assertions.assertThat(model["credentialsType"]).isEqualTo("SERVICE_ACCOUNT_KEY")
        Assertions.assertThat(model["impersonationChain"]).isEqualTo("sa@example.com")
        Assertions.assertThat(model["hasServiceAccountKey"]).isEqualTo(true)
        Assertions.assertThat(model["gcpEndpoint"]).isEqualTo("kms.example.com:443")
        Assertions.assertThat(model["kmsResourceName"]).isEqualTo(validResourceName)
        Assertions.assertThat(model["currentKeyVersionName"]).isEqualTo(keyVersionName.toString())
        Assertions.assertThat(model["currentKeyVersionGCPAlgorithm"]).isEqualTo("2048 bit RSA - PKCS#1 v1.5 padding - SHA256 Digest")
        Assertions.assertThat(model["currentKeyVersionJWSAlgorithm"]).isEqualTo("RS256")
    }

    @Test
    fun fillSettingsModel_environmentCredentialsWithoutKey_setsHasServiceAccountKeyFalse() {
        every { settings.getCredentials() } returns GCPCredentials.Environment(null)
        every { settings.getGCPEndpoint() } returns null
        every { settings.getKeyResourceName() } returns null

        val model = mutableMapOf<String, Any>()
        adminSettings.fillSettingsModel(model)

        Assertions.assertThat(model["credentialsType"]).isEqualTo("ENVIRONMENT")
        Assertions.assertThat(model["impersonationChain"]).isEqualTo("")
        Assertions.assertThat(model["hasServiceAccountKey"]).isEqualTo(false)
    }

    @Test
    fun fillSettingsModel_serviceAccountWithBlankKey_setsHasServiceAccountKeyFalse() {
        every { settings.getCredentials() } returns GCPCredentials.ServiceAccount("   ", null)
        every { settings.getGCPEndpoint() } returns null
        every { settings.getKeyResourceName() } returns null

        val model = mutableMapOf<String, Any>()
        adminSettings.fillSettingsModel(model)

        Assertions.assertThat(model["hasServiceAccountKey"]).isEqualTo(false)
    }

    @Test
    fun fillSettingsModel_nullEndpointAndNullResourceName_usesEmptyStringsAndSkipsKeyVersion() {
        every { settings.getGCPEndpoint() } returns null
        every { settings.getKeyResourceName() } returns null

        val model = mutableMapOf<String, Any>()
        adminSettings.fillSettingsModel(model)

        Assertions.assertThat(model["gcpEndpoint"]).isEqualTo("")
        Assertions.assertThat(model["kmsResourceName"]).isEqualTo("")
        Assertions.assertThat(model).doesNotContainKey("currentKeyVersionName")
        Assertions.assertThat(model).doesNotContainKey("currentKeyVersionGCPAlgorithm")
        Assertions.assertThat(model).doesNotContainKey("currentKeyVersionJWSAlgorithm")
        verify(exactly = 0) { defaultClient.getKeyVersion(any(), any()) }
    }

    @Test
    fun fillSettingsModel_resourceNameNull_doesNotInvokeDefaultClient() {
        every { settings.getGCPEndpoint() } returns "kms.example.com:443"
        every { settings.getKeyResourceName() } returns null

        val model = mutableMapOf<String, Any>()
        adminSettings.fillSettingsModel(model)

        verify(exactly = 0) { defaultClient.getKeyVersion(any(), any()) }
    }

    @Test
    fun fillSettingsModel_getKeyVersionThrows_swallowsAndOmitsKeyVersionFields() {
        every { settings.getGCPEndpoint() } returns "kms.example.com:443"
        every { settings.getKeyResourceName() } returns validResourceName
        every { defaultClient.getKeyVersion(validResourceName, false) } throws RuntimeException("boom")

        val model = mutableMapOf<String, Any>()
        adminSettings.fillSettingsModel(model)

        Assertions.assertThat(model["kmsResourceName"]).isEqualTo(validResourceName)
        Assertions.assertThat(model).doesNotContainKey("currentKeyVersionName")
        Assertions.assertThat(model).doesNotContainKey("currentKeyVersionGCPAlgorithm")
        Assertions.assertThat(model).doesNotContainKey("currentKeyVersionJWSAlgorithm")
    }

    @Test
    fun validateSettings_blankKmsResourceName_returnsKmsResourceNameError() {
        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to "",
        ))

        Assertions.assertThat(result).hasSize(1)
        Assertions.assertThat(result).containsKey("kmsResourceName")
        Assertions.assertThat(result["kmsResourceName"]).isNotBlank()
        verify(exactly = 0) { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) }
    }

    @Test
    fun validateSettings_malformedKmsResourceName_returnsKmsResourceNameError() {
        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to "not-a-valid-name",
        ))

        Assertions.assertThat(result).hasSize(1)
        Assertions.assertThat(result).containsKey("kmsResourceName")
        verify(exactly = 0) { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) }
    }

    @Test
    fun validateSettings_unknownCredentialsType_returnsCredentialsError() {
        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "FOO",
            "kmsResourceName" to validResourceName,
        ))

        Assertions.assertThat(result).isEqualTo(mapOf("credentialsError" to "Invalid credentials type 'FOO'."))
        verify(exactly = 0) { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) }
    }

    @Test
    fun validateSettings_serviceAccountTypeWithBlankKeyAndNoStoredKey_returnsServiceAccountKeyError() {
        every { settings.getCredentials() } returns GCPCredentials.Environment(null)

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "SERVICE_ACCOUNT_KEY",
            "kmsResourceName" to validResourceName,
            "serviceAccountKey" to "",
        ))

        Assertions.assertThat(result).isEqualTo(
            mapOf("serviceAccountKey" to "A service account JSON key is required when using service account credentials.")
        )
        verify(exactly = 0) { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) }
    }

    @Test
    fun validateSettings_serviceAccountTypeWithBlankKeyButStoredKeyExists_continuesValidation() {
        every { settings.getCredentials() } returns GCPCredentials.ServiceAccount("stored", null)

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "SERVICE_ACCOUNT_KEY",
            "kmsResourceName" to validResourceName,
            "serviceAccountKey" to "",
        ))

        Assertions.assertThat(result).isEmpty()
        verify { connectionChecker.check(eq("SERVICE_ACCOUNT_KEY"), eq(""), eq(""), anyNullable(), eq(validResourceName)) }
    }

    @Test
    fun validateSettings_impersonationChainWithBlankEntry_returnsImpersonationChainError() {
        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "impersonationChain" to "a@x.com||b@x.com",
        ))

        Assertions.assertThat(result).hasSize(1)
        Assertions.assertThat(result).containsKey("impersonationChain")
        Assertions.assertThat(result["impersonationChain"]).contains("blank entries")
        verify(exactly = 0) { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) }
    }

    @Test
    fun validateSettings_emptyGcpEndpoint_passesNullToConnectionChecker() {
        adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "",
        ))

        Assertions.assertThat(captureCheckEndpoint()).isNull()
    }

    @Test
    fun validateSettings_blankGcpEndpoint_passesNullToConnectionChecker() {
        adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "   ",
        ))

        Assertions.assertThat(captureCheckEndpoint()).isNull()
    }

    @Test
    fun validateSettings_hostOnlyEndpoint_normalizesToHostColon443() {
        adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "kms.example.com",
        ))

        Assertions.assertThat(captureCheckEndpoint()).isEqualTo("kms.example.com:443")
    }

    @Test
    fun validateSettings_hostWithExplicitPort_keepsPort() {
        adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "kms.example.com:8443",
        ))

        Assertions.assertThat(captureCheckEndpoint()).isEqualTo("kms.example.com:8443")
    }

    @Test
    fun validateSettings_httpsEndpoint_extractsHostColon443() {
        adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "https://kms.example.com",
        ))

        Assertions.assertThat(captureCheckEndpoint()).isEqualTo("kms.example.com:443")
    }

    @Test
    fun validateSettings_httpEndpoint_extractsHostColon80() {
        adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "http://kms.example.com",
        ))

        Assertions.assertThat(captureCheckEndpoint()).isEqualTo("kms.example.com:80")
    }

    @Test
    fun validateSettings_httpsEndpointWithExplicitPort_keepsPort() {
        adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "https://kms.example.com:9090",
        ))

        Assertions.assertThat(captureCheckEndpoint()).isEqualTo("kms.example.com:9090")
    }

    @Test
    fun validateSettings_endpointWithUppercaseHttpScheme_handledCaseInsensitive() {
        adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "HTTP://kms.example.com",
        ))

        Assertions.assertThat(captureCheckEndpoint()).isEqualTo("kms.example.com:80")
    }

    @Test
    fun validateSettings_endpointSchemeOnly_returnsGcpEndpointError() {
        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "https://",
        ))

        Assertions.assertThat(result).hasSize(1)
        Assertions.assertThat(result).containsKey("gcpEndpointError")
        verify(exactly = 0) { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) }
    }

    @Test
    fun validateSettings_malformedGcpEndpoint_returnsGcpEndpointError() {
        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "http://[",
        ))

        Assertions.assertThat(result).hasSize(1)
        Assertions.assertThat(result).containsKey("gcpEndpointError")
        Assertions.assertThat(result["gcpEndpointError"]).isNotBlank()
        verify(exactly = 0) { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) }
    }

    @Test
    fun validateSettings_callsConnectionCheckerWithExpectedArguments() {
        adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "serviceAccountKey" to "the-key",
            "impersonationChain" to "sa@example.com",
            "gcpEndpoint" to "kms.example.com",
        ))

        val credTypeSlot = slot<String>()
        val saKeySlot = slot<String?>()
        val chainSlot = slot<String?>()
        val endpointSlot = slot<String?>()
        val resourceSlot = slot<String>()
        verify {
            connectionChecker.check(
                capture(credTypeSlot),
                captureNullable(saKeySlot),
                captureNullable(chainSlot),
                captureNullable(endpointSlot),
                capture(resourceSlot),
            )
        }

        Assertions.assertThat(credTypeSlot.captured).isEqualTo("ENVIRONMENT")
        Assertions.assertThat(saKeySlot.captured).isEqualTo("the-key")
        Assertions.assertThat(chainSlot.captured).isEqualTo("sa@example.com")
        Assertions.assertThat(endpointSlot.captured).isEqualTo("kms.example.com:443")
        Assertions.assertThat(resourceSlot.captured).isEqualTo(validResourceName)
    }

    @Test
    fun validateSettings_authenticatingFailureWithMessage_returnsCredentialsError() {
        every { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) } returns
            CloudKMSConnectionChecker.Result(false, CloudKMSConnectionChecker.Step.AUTHENTICATING, "auth failed")

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
        ))

        Assertions.assertThat(result).isEqualTo(mapOf("credentialsError" to "Credential validation failed. auth failed"))
    }

    @Test
    fun validateSettings_authenticatingFailureWithNullError_usesUnknownPlaceholder() {
        every { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) } returns
            CloudKMSConnectionChecker.Result(false, CloudKMSConnectionChecker.Step.AUTHENTICATING, null)

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
        ))

        Assertions.assertThat(result).isEqualTo(mapOf("credentialsError" to "Credential validation failed. Unknown credentials error"))
    }

    @Test
    fun validateSettings_fetchingPublicKeyFailure_returnsTestConnectionKeyError() {
        every { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) } returns
            CloudKMSConnectionChecker.Result(false, CloudKMSConnectionChecker.Step.FETCHING_PUBLIC_KEY, "denied")

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
        ))

        Assertions.assertThat(result).isEqualTo(mapOf("testConnectionKey" to "Failed to fetch the public key. denied"))
    }

    @Test
    fun validateSettings_fetchingPublicKeyFailureNullError_usesPlaceholder() {
        every { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) } returns
            CloudKMSConnectionChecker.Result(false, CloudKMSConnectionChecker.Step.FETCHING_PUBLIC_KEY, null)

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
        ))

        Assertions.assertThat(result).isEqualTo(mapOf("testConnectionKey" to "Failed to fetch the public key. Unknown public key fetching error"))
    }

    @Test
    fun validateSettings_signingTestPayloadFailure_returnsTestConnectionKeyError() {
        every { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) } returns
            CloudKMSConnectionChecker.Result(false, CloudKMSConnectionChecker.Step.SIGNING_TEST_PAYLOAD, "boom")

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
        ))

        Assertions.assertThat(result).isEqualTo(mapOf("testConnectionKey" to "Failed to sign a test token. boom"))
    }

    @Test
    fun validateSettings_signingTestPayloadFailureNullError_usesPlaceholder() {
        every { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) } returns
            CloudKMSConnectionChecker.Result(false, CloudKMSConnectionChecker.Step.SIGNING_TEST_PAYLOAD, null)

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
        ))

        Assertions.assertThat(result).isEqualTo(mapOf("testConnectionKey" to "Failed to sign a test token. Unknown signing error"))
    }

    @Test
    fun validateSettings_unknownStepFailure_returnsTestConnectionKeyUnknownError() {
        every { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) } returns
            CloudKMSConnectionChecker.Result(false, null, "weird")

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
        ))

        Assertions.assertThat(result).isEqualTo(mapOf("testConnectionKey" to "Unknown error: weird"))
    }

    @Test
    fun validateSettings_unknownStepFailureNullError_usesPlaceholder() {
        every { connectionChecker.check(any(), anyNullable(), anyNullable(), anyNullable(), any()) } returns
            CloudKMSConnectionChecker.Result(false, null, null)

        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
        ))

        Assertions.assertThat(result).isEqualTo(mapOf("testConnectionKey" to "Unknown error: Unknown error"))
    }

    @Test
    fun validateSettings_allValidWithSuccessfulCheck_returnsEmptyMap() {
        val result = adminSettings.validateSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "gcpEndpoint" to "kms.example.com",
        ))

        Assertions.assertThat(result).isEmpty()
    }

    @Test
    fun saveSettings_malformedGcpEndpoint_returnsGcpEndpointErrorAndDoesNotPersist() {
        val result = adminSettings.saveSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "serviceAccountKey" to "",
            "impersonationChain" to "",
            "gcpEndpoint" to "http://[",
        ))

        Assertions.assertThat(result).hasSize(1)
        Assertions.assertThat(result).containsKey("gcpEndpointError")
        verify(exactly = 0) { settings.update(any(), any(), any(), anyNullable(), anyNullable()) }
    }

    @Test
    fun saveSettings_validInputs_callsSettingsUpdateWithPreparedEndpoint() {
        every { settings.update(any(), any(), any(), anyNullable(), anyNullable()) } just Runs

        val result = adminSettings.saveSettings(mapOf(
            "credentialsType" to "SERVICE_ACCOUNT_KEY",
            "kmsResourceName" to validResourceName,
            "serviceAccountKey" to "{json}",
            "impersonationChain" to "sa@example.com",
            "gcpEndpoint" to "kms.example.com",
        ))

        Assertions.assertThat(result).isEmpty()
        verify {
            settings.update(
                eq("SERVICE_ACCOUNT_KEY"),
                eq(validResourceName),
                eq("{json}"),
                eq("sa@example.com"),
                eq("kms.example.com:443"),
            )
        }
    }

    @Test
    fun saveSettings_blankImpersonationChainAndEmptyEndpoint_passesEmptyAndNull() {
        every { settings.update(any(), any(), any(), anyNullable(), anyNullable()) } just Runs

        val result = adminSettings.saveSettings(mapOf(
            "credentialsType" to "ENVIRONMENT",
            "kmsResourceName" to validResourceName,
            "serviceAccountKey" to "",
            "impersonationChain" to "",
            "gcpEndpoint" to "",
        ))

        Assertions.assertThat(result).isEmpty()

        val endpointSlot = slot<String?>()
        verify {
            settings.update(any(), any(), any(), any(), captureNullable(endpointSlot))
        }
        Assertions.assertThat(endpointSlot.captured).isNull()
    }
}
