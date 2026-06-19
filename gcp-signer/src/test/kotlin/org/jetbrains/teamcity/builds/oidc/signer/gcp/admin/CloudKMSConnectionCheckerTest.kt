package org.jetbrains.teamcity.builds.oidc.signer.gcp.admin

import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSSettings
import org.jetbrains.teamcity.builds.oidc.signer.gcp.JWTKeyVersion
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.CloudKMSClient
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.CloudKMSClientFactory
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.GCPCredentials
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSAccessDeniedException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyNotFoundException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyVersionNotEnabledException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSUnauthenticatedException
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*

class CloudKMSConnectionCheckerTest : BaseTestCase() {
    private lateinit var settings: CloudKMSSettings
    private lateinit var client: CloudKMSClient
    private lateinit var factory: CloudKMSClientFactory
    private lateinit var connectionTest: CloudKMSConnectionChecker

    private val validResourceName = "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        settings = mockk()
        client = mockk {
            every { resolveKeyVersion(any()) } returns mockk<JWTKeyVersion>()
            every { sign(any(), any()) } returns "signature"
            every { checkAuthentication() } just Runs
            every { close() } just Runs
        }
        factory = mockk {
            every { create(any(), anyNullable(), any(), any()) } returns client
        }
        connectionTest = CloudKMSConnectionChecker(settings, factory)
    }

    private fun captureFactoryCall(): FactoryArgs {
        val credentialsSlot = slot<GCPCredentials>()
        val endpointSlot = slot<String?>()
        val timeoutSlot = slot<Long>()
        val attemptsSlot = slot<Int>()
        verify {
            factory.create(
                capture(credentialsSlot),
                captureNullable(endpointSlot),
                capture(timeoutSlot),
                capture(attemptsSlot),
            )
        }
        return FactoryArgs(credentialsSlot.captured, endpointSlot.captured, timeoutSlot.captured, attemptsSlot.captured)
    }

    private data class FactoryArgs(
        val credentials: GCPCredentials,
        val endpoint: String?,
        val timeoutSeconds: Long,
        val maxAttempts: Int,
    )

    @Test
    fun serviceAccountKeyTypeWithProvidedKey_passesServiceAccountCredentialsToFactory() {
        connectionTest.check(
            credentialsType = "SERVICE_ACCOUNT_KEY",
            serviceAccountKey = "provided-key",
            impersonationChain = "sa@example.com",
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        val args = captureFactoryCall()
        Assertions.assertThat(args.credentials).isEqualTo(GCPCredentials.ServiceAccount("provided-key", "sa@example.com"))
    }

    @Test
    fun serviceAccountKeyTypeWithBlankKey_fallsBackToCurrentSettingsServiceAccount() {
        every { settings.getCredentials() } returns GCPCredentials.ServiceAccount("stored-key", "old-chain")

        connectionTest.check(
            credentialsType = "SERVICE_ACCOUNT_KEY",
            serviceAccountKey = "",
            impersonationChain = "new-chain",
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        val args = captureFactoryCall()
        Assertions.assertThat(args.credentials).isEqualTo(GCPCredentials.ServiceAccount("stored-key", "new-chain"))
    }

    @Test
    fun serviceAccountKeyTypeWithNullKey_fallsBackToCurrentSettingsServiceAccount() {
        every { settings.getCredentials() } returns GCPCredentials.ServiceAccount("stored-key", "old-chain")

        connectionTest.check(
            credentialsType = "SERVICE_ACCOUNT_KEY",
            serviceAccountKey = null,
            impersonationChain = "new-chain",
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        val args = captureFactoryCall()
        Assertions.assertThat(args.credentials).isEqualTo(GCPCredentials.ServiceAccount("stored-key", "new-chain"))
    }

    @Test
    fun fallbackServiceAccount_overridesImpersonationChainWithProvidedOne() {
        every { settings.getCredentials() } returns GCPCredentials.ServiceAccount("stored-key", "old-chain")

        connectionTest.check(
            credentialsType = "SERVICE_ACCOUNT_KEY",
            serviceAccountKey = null,
            impersonationChain = "new-chain",
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        val args = captureFactoryCall()
        Assertions.assertThat((args.credentials as GCPCredentials.ServiceAccount).impersonationChain).isEqualTo("new-chain")
    }

    @Test
    fun fallbackServiceAccount_blankImpersonationChainIsNormalizedToNull() {
        every { settings.getCredentials() } returns GCPCredentials.ServiceAccount("stored-key", "old-chain")

        connectionTest.check(
            credentialsType = "SERVICE_ACCOUNT_KEY",
            serviceAccountKey = null,
            impersonationChain = "   ",
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        val args = captureFactoryCall()
        Assertions.assertThat((args.credentials as GCPCredentials.ServiceAccount).impersonationChain).isNull()
    }

    @Test
    fun serviceAccountKeyTypeWithBlankKeyAndNoStoredServiceAccount_returnsAuthenticatingFailure() {
        every { settings.getCredentials() } returns GCPCredentials.Environment(null)

        val result = connectionTest.check(
            credentialsType = "SERVICE_ACCOUNT_KEY",
            serviceAccountKey = "",
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.success).isEqualTo(false)
        Assertions.assertThat(result.failedStep).isEqualTo(CloudKMSConnectionChecker.Step.AUTHENTICATING)
        Assertions.assertThat(result.error).isEqualTo("A service account JSON key is required when using service account credentials.")
        verify(exactly = 0) { factory.create(any(), anyNullable(), any(), any()) }
    }

    @Test
    fun nonServiceAccountKeyType_passesEnvironmentCredentialsToFactory() {
        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = "ignored",
            impersonationChain = "sa@example.com",
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        val args = captureFactoryCall()
        Assertions.assertThat(args.credentials).isEqualTo(GCPCredentials.Environment("sa@example.com"))
        verify(exactly = 0) { settings.getCredentials() }
    }

    @Test
    fun passesGcpEndpointToFactory() {
        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = "https://kms.example.com",
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(captureFactoryCall().endpoint).isEqualTo("https://kms.example.com")
    }

    @Test
    fun blankGcpEndpoint_passesNullToFactory() {
        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = "   ",
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(captureFactoryCall().endpoint).isNull()
    }

    @Test
    fun nullGcpEndpoint_passesNullToFactory() {
        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(captureFactoryCall().endpoint).isNull()
    }

    @Test
    fun passesKmsResourceNameToClientResolveKeyVersion() {
        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        verify { client.resolveKeyVersion(eq(validResourceName)) }
    }

    @Test
    fun passesCheckTimeoutAndMaxAttemptsToFactory() {
        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        val args = captureFactoryCall()
        Assertions.assertThat(args.timeoutSeconds).isEqualTo(5L)
        Assertions.assertThat(args.maxAttempts).isEqualTo(1)
    }

    @Test
    fun successfulFlow_returnsSuccessResult() {
        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.success).isEqualTo(true)
        Assertions.assertThat(result.failedStep).isNull()
        Assertions.assertThat(result.error).isNull()
    }

    @Test
    fun successfulFlow_callsClientStepsInOrder() {
        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        verifyOrder {
            client.checkAuthentication()
            client.resolveKeyVersion(eq(validResourceName))
            client.sign(any(), any())
        }
    }

    @Test
    fun successfulFlow_closesClient() {
        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        verify { client.close() }
    }

    @Test
    fun expectedExceptionDuringFlow_closesClient() {
        every { client.resolveKeyVersion(any()) } throws CloudKMSAccessDeniedException("denied")

        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        verify { client.close() }
    }

    @Test
    fun unexpectedExceptionDuringFlow_closesClient() {
        every { client.checkAuthentication() } throws IllegalStateException("boom")

        connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        verify { client.close() }
        clearFailure()
    }

    @Test
    fun checkAuthenticationThrowsJWTSignerException_returnsAuthenticatingFailure() {
        every { client.checkAuthentication() } throws CloudKMSUnauthenticatedException("auth failed")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.success).isEqualTo(false)
        Assertions.assertThat(result.failedStep).isEqualTo(CloudKMSConnectionChecker.Step.AUTHENTICATING)
        Assertions.assertThat(result.error).isEqualTo("auth failed")
        verify(exactly = 0) { client.resolveKeyVersion(any()) }
        verify(exactly = 0) { client.sign(any(), any()) }
    }

    @Test
    fun resolveKeyVersionThrowsJWTSignerException_returnsFetchingPublicKeyFailure() {
        every { client.resolveKeyVersion(any()) } throws CloudKMSAccessDeniedException("denied")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.success).isEqualTo(false)
        Assertions.assertThat(result.failedStep).isEqualTo(CloudKMSConnectionChecker.Step.FETCHING_PUBLIC_KEY)
        Assertions.assertThat(result.error).isEqualTo("denied")
        verify(exactly = 0) { client.sign(any(), any()) }
    }

    @Test
    fun signThrowsJWTSignerException_returnsSigningTestPayloadFailure() {
        every { client.sign(any(), any()) } throws CloudKMSAccessDeniedException("denied")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.success).isEqualTo(false)
        Assertions.assertThat(result.failedStep).isEqualTo(CloudKMSConnectionChecker.Step.SIGNING_TEST_PAYLOAD)
        Assertions.assertThat(result.error).isEqualTo("denied")
    }

    @Test
    fun keyRelatedExceptionDuringResolve_usesMessageWithoutKeyId() {
        every { client.resolveKeyVersion(any()) } throws
            CloudKMSKeyNotFoundException("projects/p/locations/global/keyRings/r/cryptoKeys/k")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.success).isEqualTo(false)
        Assertions.assertThat(result.failedStep).isEqualTo(CloudKMSConnectionChecker.Step.FETCHING_PUBLIC_KEY)
        Assertions.assertThat(result.error).isEqualTo("Key not found")
    }

    @Test
    fun keyRelatedExceptionWithSuffix_usesMessageWithoutKeyIdIncludingSuffix() {
        every { client.resolveKeyVersion(any()) } throws
            CloudKMSKeyVersionNotEnabledException(validResourceName, "DISABLED")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.error).isEqualTo("Key version is not enabled (state: DISABLED)")
    }

    @Test
    fun expectedExceptionMultilineMessage_returnsOnlyFirstLine() {
        every { client.checkAuthentication() } throws
            CloudKMSUnauthenticatedException("first line\nsecond line\nthird")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.error).isEqualTo("first line")
    }

    @Test
    fun expectedExceptionWithNullMessage_returnsUnknownSignerErrorPlaceholder() {
        every { client.checkAuthentication() } throws NullMessageJWTSignerException()

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.error).isNotNull()
        Assertions.assertThat(result.error!!).startsWith("Unknown signer error (")
    }

    @Test
    fun expectedExceptionWithBlankMessage_returnsUnknownErrorPlaceholder() {
        every { client.checkAuthentication() } throws CloudKMSUnauthenticatedException("   ")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.error).isEqualTo(
            "Unknown error (org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSUnauthenticatedException)"
        )
    }

    @Test
    fun unexpectedExceptionWithBlankMessage_returnsUnknownErrorPlaceholder() {
        every { client.checkAuthentication() } throws IllegalStateException("   ")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.error).isEqualTo("Unknown error (java.lang.IllegalStateException)")
        clearFailure()
    }

    @Test
    fun unexpectedException_returnsFailureWithClassNamePrefix() {
        every { client.checkAuthentication() } throws IllegalStateException("boom")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.success).isEqualTo(false)
        Assertions.assertThat(result.failedStep).isEqualTo(CloudKMSConnectionChecker.Step.AUTHENTICATING)
        Assertions.assertThat(result.error).isEqualTo("java.lang.IllegalStateException: boom")
        clearFailure()
    }

    @Test
    fun unexpectedExceptionMultilineMessage_returnsClassNamePlusFirstLine() {
        every { client.checkAuthentication() } throws IllegalStateException("first\nsecond")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.error).isEqualTo("java.lang.IllegalStateException: first")
        clearFailure()
    }

    @Test
    fun unexpectedExceptionDuringSign_carriesSigningTestPayloadStep() {
        every { client.sign(any(), any()) } throws RuntimeException("oops")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.failedStep).isEqualTo(CloudKMSConnectionChecker.Step.SIGNING_TEST_PAYLOAD)
        Assertions.assertThat(result.error).isEqualTo("java.lang.RuntimeException: oops")
        clearFailure()
    }

    @Test
    fun unexpectedExceptionWithNullMessage_returnsUnknownErrorPlaceholder() {
        every { client.checkAuthentication() } throws RuntimeException()

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.error).isEqualTo("Unknown error (java.lang.RuntimeException)")
        clearFailure()
    }

    @Test
    fun factoryThrowsUnexpectedException_returnsAuthenticatingFailure() {
        every { factory.create(any(), anyNullable(), any(), any()) } throws RuntimeException("ctor boom")

        val result = connectionTest.check(
            credentialsType = "ENVIRONMENT",
            serviceAccountKey = null,
            impersonationChain = null,
            gcpEndpoint = null,
            kmsResourceName = validResourceName,
        )

        Assertions.assertThat(result.success).isEqualTo(false)
        Assertions.assertThat(result.failedStep).isEqualTo(CloudKMSConnectionChecker.Step.AUTHENTICATING)
        Assertions.assertThat(result.error).isEqualTo("java.lang.RuntimeException: ctor boom")
        clearFailure()
    }

    private class NullMessageJWTSignerException : JWTSignerException(null as Throwable?)
}
