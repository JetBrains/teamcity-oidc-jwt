package org.jetbrains.teamcity.builds.oidc.signer.gcp.client

import com.google.api.gax.core.FixedCredentialsProvider
import com.google.api.gax.rpc.ApiException
import com.google.api.gax.rpc.FailedPreconditionException
import com.google.api.gax.rpc.InvalidArgumentException
import com.google.api.gax.rpc.NotFoundException
import com.google.api.gax.rpc.PermissionDeniedException
import com.google.api.gax.rpc.UnauthenticatedException
import com.google.auth.oauth2.ServiceAccountCredentials
import com.google.cloud.kms.v1.AsymmetricSignRequest
import com.google.cloud.kms.v1.AsymmetricSignResponse
import com.google.cloud.kms.v1.ChecksummedData
import com.google.cloud.kms.v1.CryptoKeyVersion
import com.google.cloud.kms.v1.CryptoKeyVersionName
import com.google.cloud.kms.v1.GetPublicKeyRequest
import com.google.cloud.kms.v1.KeyManagementServiceClient
import com.google.cloud.kms.v1.KeyManagementServiceSettings
import com.google.cloud.kms.v1.ListCryptoKeyVersionsRequest
import com.google.cloud.kms.v1.PublicKey
import com.google.cloud.location.ListLocationsRequest
import com.google.protobuf.ByteString
import org.jetbrains.teamcity.builds.oidc.signer.gcp.JWTKeyVersion
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSAccessDeniedException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSInvalidResourceNameException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyNotFoundException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyVersionNotEnabledException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSNoEnabledVersionsException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSNoResourceNameException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSUnauthenticatedException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*
import org.jetbrains.teamcity.builds.oidc.signer.gcp.asVersion
import org.threeten.bp.Duration
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.util.Base64

class CloudKMSClientTest : BaseTestCase() {

    companion object {
        private const val SA_CLIENT_EMAIL = "tc-oidc-hsm-test-igor-brov-520@test-sandbox-please-ignore.iam.gserviceaccount.com"
        private const val AUTH_SCOPE = "https://www.googleapis.com/auth/cloudkms"

        private val SA_KEY_JSON = """
        {
          "type": "service_account",
          "project_id": "test-sandbox-please-ignore",
          "private_key_id": "7af98a184f1fe98976b7281cead67a66bf9154c1",
          "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwoqsqo1mQo+Ew\npXR0+KfZpPkBhZnTSPd6ms24ovGsv2GQmtcnERzInUualKqBXrBdkEaeiSapiqc5\nWekIRtsxs/USQAi7ZBN15C1on1Zk6ZBN01Z3ah9dKlu0AHiWEgkjf6XqZckRav5H\n9fqNpJCg3j/myW33nXEnKPelop3vxNv0Oj+H0XSvK6ne8hmtqRwfA6NlnEejKLCg\nOSN25zCMgVNmMjbiKA+UQVwKoVHoJ+3b7p0+lNOhx2sHmYfUfpj4pkpL0SBrwEFk\nj55rWA8fYNBbmpnhYwMitP9xW7H83wGLGQtpYSsJo6jOAuP9odj7jUyrAaBIH5V9\nJt3sbK4XAgMBAAECggEABHx1LXWNoktPPl2NaiUgmjoC6wN6JzAcvPvuiqh0y+bm\ncvZDzaW1HfFEyM3K0NNXVmECMieYmEjBu4apkQC/s3D3IfoHXr8JcX6UmqolVxXJ\niPh7ozfKSSL4xkcWyPT3T3QAAkaIh0043RoFvZA27icG53UpOldA1vZG5+mL6lmC\nQ3cfETDoff4kHIEFq/sulg+bGEhb5xc13T5N20BTHcANuXbTpv2WpyO3Zii5FiyS\ng1r6qr4i+BLFw/CSyLtUTvzY3cSfvPVXgoMrS/OpRyN82QWO4hy8xI3mAX/lqJRi\nSTxI/mIGxiaKsgWwnmgBLKF5QD592A+q4x17s3C+iQKBgQDrFBbx29zKsWt9C3JH\nmbk71Dcl8Ju3mEIJ2yQBSwJMpxyIhRe2/MJzGe+xgoBQSX27g57ABMSRp2Uvuas4\no2eHStSwWT5lBlRzxrnLaYScgSv4+kWguRTJXZksPjg0f7bqroxBLs5qR96pn0pn\npGqnkQSb67TvgA84n7CBE/jAzwKBgQDAWwqwv2pK9UVtPvwkDX/58H0a9x/Ba4v+\nSgRG687+fe/oj1nY5b6P/CVxVlsa29pOp8A2Kjunh9euxojrtpIuAZ2jsjWa7oV+\nH9h33LCTo4xut8gvHXGx63TJ/MkIEPOqB5pdsnULoViXb0HiYUVoOZpRlqi57Kqh\nzQaUEkpAOQKBgQDOZpc2yDp15Y1g/1nZsAlJlKzPLREsBA2HpddZI0jjkJ6m52TJ\nD+iTMySXkOOkmsJAj/Ik2orU8EsRuk2xrxdJXNSd+d2kyggAl22uQfljiK7ZLrVP\nxvGPVBUXGZIz1ib+qz8ORFCMVIoWGHw1v9C9S8DmPfBhkOjMaLmKu8RfVQKBgBXu\nS1m7eTLyo+fAtp6lq2GjuZ/JbSVwTZXAepxbZk49rYymS2gfSYrBBMPXRKvbRRiS\np6eFSSfgpQaYPCQjvKbiKEbxmor/htjKaLPBxaAPlYNKENjOUpgmcDpXR9RTmnRY\nSZFFN3MMAj3BwZE95dvsNVv4AWSxRwMLjSR0sWKBAoGAPcy+mogm4F7xrA7gCPVX\nzQ+gMjJM9lFCLN9WmeuoqisfppI3fkxchE9V16UNB4AyGDLBgFJGchsFmoi6VBXU\nuuGS/Gr0kzqGdyx+vUAhp8P8x7n101v6H6bGHHIFfCytFCkYbkUmC/3BFoZTdkmf\n6LauLe1fBTx5QrBUJ4KOERU=\n-----END PRIVATE KEY-----\n",
          "client_email": "$SA_CLIENT_EMAIL",
          "client_id": "115413607050253529298",
          "auth_uri": "https://accounts.google.com/o/oauth2/auth",
          "token_uri": "https://oauth2.googleapis.com/token",
          "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
          "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/tc-oidc-hsm-test-igor-brov-520%40test-sandbox-please-ignore.iam.gserviceaccount.com",
          "universe_domain": "googleapis.com"
        }
        """.trimIndent()

        private val RSA_KEY_PEM: String by lazy {
            val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            val encoded = Base64.getMimeEncoder().encodeToString(keyPair.public.encoded)
            "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----"
        }

        private const val VALID_KEY = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
        private const val VALID_KEY_VERSION_1 = "$VALID_KEY/cryptoKeyVersions/1"
        private const val VALID_KEY_VERSION_3 = "$VALID_KEY/cryptoKeyVersions/3"
    }

    private data class CapturingProvider(
        val provider: GoogleKMSClientProvider,
        val settings: () -> KeyManagementServiceSettings,
    )

    private fun createCapturingProvider(client: KeyManagementServiceClient): CapturingProvider {
        var captured: KeyManagementServiceSettings? = null
        return CapturingProvider(
            provider = { s ->
                captured = s
                client
            },
            settings = { captured ?: error("provider was not invoked") },
        )
    }

    private fun createCredentials() = GCPCredentials.ServiceAccount(SA_KEY_JSON)

    private fun buildClient(
        client: KeyManagementServiceClient = mockk(relaxed = true),
        gcpEndpoint: String? = null,
        timeoutSeconds: Long? = null,
        maxAttempts: Int? = null,
    ): Pair<CloudKMSClient, CapturingProvider> {
        val cap = createCapturingProvider(client)
        val c = CloudKMSClient(
            credentials = createCredentials(),
            gcpEndpoint = gcpEndpoint,
            timeoutSeconds = timeoutSeconds,
            maxAttempts = maxAttempts,
            provider = cap.provider,
        )
        return c to cap
    }

    private fun createCryptoKeyVersion(name: String): CryptoKeyVersion =
        CryptoKeyVersion.newBuilder().setName(name).build()

    private fun createPublicKey(
        algorithm: CryptoKeyVersion.CryptoKeyVersionAlgorithm,
        pem: String,
    ): PublicKey = PublicKey.newBuilder()
        .setPublicKey(
            ChecksummedData.newBuilder()
                .setData(ByteString.copyFrom(pem.toByteArray(StandardCharsets.UTF_8)))
                .build()
        )
        .setAlgorithm(algorithm)
        .build()

    private fun createPagedResponse(
        pages: List<List<CryptoKeyVersion>>,
    ): KeyManagementServiceClient.ListCryptoKeyVersionsPagedResponse {
        val mockPages = pages.map { values ->
            mockk<KeyManagementServiceClient.ListCryptoKeyVersionsPage> {
                every { getValues() } returns values
            }
        }
        return mockk {
            every { iteratePages() } returns mockPages
        }
    }

    private fun mockNotFound(message: String? = "not found"): NotFoundException =
        mockk { every { this@mockk.message } returns message }

    private fun mockPermissionDenied(
        causeMessage: String? = "perm cause",
        topMessage: String? = "perm top",
    ): PermissionDeniedException = mockk {
        every { this@mockk.message } returns topMessage
        every { this@mockk.cause } returns (causeMessage?.let { RuntimeException(it) })
    }

    private fun mockFailedPrecondition(message: String?): FailedPreconditionException =
        mockk(relaxed = true) { every { this@mockk.message } returns message }

    private fun mockUnauthenticated(message: String?): UnauthenticatedException =
        mockk(relaxed = true) { every { this@mockk.message } returns message }

    private fun mockInvalidArgument(): InvalidArgumentException = mockk(relaxed = true)

    private fun mockOtherApiException(): ApiException = mockk(relaxed = true)

    // ---------- Constructor / settings ----------

    @Test
    fun credentials_passedAsFixedCredentialsProviderWithCloudKmsScope() {
        val (_, cap) = buildClient()

        val provider = cap.settings().credentialsProvider
        Assertions.assertThat(provider).isInstanceOf(FixedCredentialsProvider::class.java)
        val fixedProvider = provider as FixedCredentialsProvider
        val sa = fixedProvider.credentials
        Assertions.assertThat(sa).isInstanceOf(ServiceAccountCredentials::class.java)
        val saCredentials = sa as ServiceAccountCredentials
        Assertions.assertThat(saCredentials.clientEmail).isEqualTo(SA_CLIENT_EMAIL)
        Assertions.assertThat(saCredentials.scopes.toList()).isEqualTo(listOf(AUTH_SCOPE))
    }

    @Test
    fun gcpEndpointSet_overridesDefaultEndpoint() {
        val (_, cap) = buildClient(gcpEndpoint = "kms.override.example:443")

        Assertions.assertThat(cap.settings().endpoint).isEqualTo("kms.override.example:443")
    }

    @Test
    fun gcpEndpointNull_keepsDefaultEndpoint() {
        val defaultEndpoint = KeyManagementServiceSettings.newBuilder().build().endpoint

        val (_, cap) = buildClient(gcpEndpoint = null)

        Assertions.assertThat(cap.settings().endpoint).isEqualTo(defaultEndpoint)
    }

    @Test
    fun gcpEndpointBlank_keepsDefaultEndpoint() {
        val defaultEndpoint = KeyManagementServiceSettings.newBuilder().build().endpoint

        val (_, cap) = buildClient(gcpEndpoint = "   ")

        Assertions.assertThat(cap.settings().endpoint).isEqualTo(defaultEndpoint)
    }

    @Test
    fun timeoutSecondsSet_appliesTotalTimeoutToProductionUnaryMethods() {
        val (_, cap) = buildClient(timeoutSeconds = 42L)

        val s = cap.settings()
        Assertions.assertThat(s.asymmetricSignSettings().retrySettings.totalTimeout).isEqualTo(Duration.ofSeconds(42))
        Assertions.assertThat(s.getPublicKeySettings().retrySettings.totalTimeout).isEqualTo(Duration.ofSeconds(42))
        Assertions.assertThat(s.listCryptoKeyVersionsSettings().retrySettings.totalTimeout).isEqualTo(Duration.ofSeconds(42))
    }

    @Test
    fun maxAttemptsSet_appliesMaxAttemptsToProductionUnaryMethods() {
        val (_, cap) = buildClient(maxAttempts = 7)

        val s = cap.settings()
        Assertions.assertThat(s.asymmetricSignSettings().retrySettings.maxAttempts).isEqualTo(7)
        Assertions.assertThat(s.getPublicKeySettings().retrySettings.maxAttempts).isEqualTo(7)
        Assertions.assertThat(s.listCryptoKeyVersionsSettings().retrySettings.maxAttempts).isEqualTo(7)
    }

    @Test
    fun retrySettingsApplyToAllUnaryMethodsWithSameValues() {
        val (_, cap) = buildClient(timeoutSeconds = 11L, maxAttempts = 4)

        val s = cap.settings()
        val expected = s.asymmetricSignSettings().retrySettings
        Assertions.assertThat(expected.totalTimeout).isEqualTo(Duration.ofSeconds(11))
        Assertions.assertThat(expected.maxAttempts).isEqualTo(4)
        Assertions.assertThat(s.getPublicKeySettings().retrySettings).isEqualTo(expected)
        Assertions.assertThat(s.listCryptoKeyVersionsSettings().retrySettings).isEqualTo(expected)
        Assertions.assertThat(s.listLocationsSettings().retrySettings).isEqualTo(expected)
    }

    @Test
    fun bothTimeoutAndMaxAttemptsNull_leavesRetrySettingsAtDefaults() {
        val defaultRetry = KeyManagementServiceSettings.newBuilder().build().asymmetricSignSettings().retrySettings

        val (_, cap) = buildClient(timeoutSeconds = null, maxAttempts = null)

        Assertions.assertThat(cap.settings().asymmetricSignSettings().retrySettings).isEqualTo(defaultRetry)
    }

    // ---------- wrapExpectedErrors via sign ----------

    private fun signableKeyVersion(): JWTKeyVersion =
        createPublicKey(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256, RSA_KEY_PEM).asVersion(
        CryptoKeyVersionName.parse(VALID_KEY_VERSION_1),
        resolvedFromKey = false,
    )

    @Test
    fun signNotFoundException_throwsCloudKMSKeyNotFoundException() {
        val nf = mockNotFound()
        val kms = mockk<KeyManagementServiceClient> {
            every { asymmetricSign(any<AsymmetricSignRequest>()) } throws nf
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.sign(signableKeyVersion(), byteArrayOf(1, 2, 3)) },
            CloudKMSKeyNotFoundException::class.java
        )
        Assertions.assertThat(ex.message).contains(VALID_KEY_VERSION_1)
    }

    @Test
    fun signPermissionDeniedException_throwsCloudKMSAccessDeniedException() {
        val pd = mockPermissionDenied(causeMessage = "no access for you")
        val kms = mockk<KeyManagementServiceClient> {
            every { asymmetricSign(any<AsymmetricSignRequest>()) } throws pd
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.sign(signableKeyVersion(), byteArrayOf(1, 2, 3)) },
            CloudKMSAccessDeniedException::class.java
        )
        Assertions.assertThat(ex.message).isEqualTo("no access for you")
    }

    @Test
    fun signFailedPreconditionWithIsNotEnabled_throwsKeyVersionNotEnabledWithParsedState() {
        val fp = mockFailedPrecondition(
            "FAILED_PRECONDITION: $VALID_KEY_VERSION_1 is not enabled, current state is: DISABLED."
        )
        val kms = mockk<KeyManagementServiceClient> {
            every { asymmetricSign(any<AsymmetricSignRequest>()) } throws fp
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.sign(signableKeyVersion(), byteArrayOf(1, 2, 3)) },
            CloudKMSKeyVersionNotEnabledException::class.java
        )
        Assertions.assertThat(ex.message).contains("DISABLED")
        Assertions.assertThat(ex.message).contains(VALID_KEY_VERSION_1)
    }

    @Test
    fun signFailedPreconditionWithoutIsNotEnabled_rethrowsAsIs() {
        val original = mockFailedPrecondition("FAILED_PRECONDITION: something else went wrong")
        val kms = mockk<KeyManagementServiceClient> {
            every { asymmetricSign(any<AsymmetricSignRequest>()) } throws original
        }
        val (client, _) = buildClient(client = kms)

        val thrown = Assertions.catchThrowableOfType(
            { client.sign(signableKeyVersion(), byteArrayOf(1, 2, 3)) },
            FailedPreconditionException::class.java
        )
        Assertions.assertThat(thrown).isSameAs(original)
        clearFailure()
    }

    @Test
    fun signUnauthenticatedWithCredentialMetadataMessage_throwsCloudKMSUnauthenticated() {
        val ua = mockUnauthenticated("UNAUTHENTICATED: Failed computing credential metadata: foo")
        val kms = mockk<KeyManagementServiceClient> {
            every { asymmetricSign(any<AsymmetricSignRequest>()) } throws ua
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.sign(signableKeyVersion(), byteArrayOf(1, 2, 3)) },
            CloudKMSUnauthenticatedException::class.java
        )
        Assertions.assertThat(ex.message).contains(AUTH_SCOPE)
    }

    @Test
    fun signUnauthenticatedWithoutCredentialMetadataMessage_rethrowsAsIs() {
        val original = mockUnauthenticated("UNAUTHENTICATED: token expired")
        val kms = mockk<KeyManagementServiceClient> {
            every { asymmetricSign(any<AsymmetricSignRequest>()) } throws original
        }
        val (client, _) = buildClient(client = kms)

        val thrown = Assertions.catchThrowableOfType(
            { client.sign(signableKeyVersion(), byteArrayOf(1, 2, 3)) },
            UnauthenticatedException::class.java
        )
        Assertions.assertThat(thrown).isSameAs(original)
        clearFailure()
    }

    // ---------- resolveKeyVersion / fetchAnyEnabledKeyVersion / publicKey ----------

    @Test
    fun resolveKeyVersionBlankInput_throwsNoResourceName() {
        val (client, _) = buildClient()

        Assertions.assertThatThrownBy {
            client.resolveKeyVersion("")
        }.isInstanceOf(CloudKMSNoResourceNameException::class.java)
    }

    @Test
    fun resolveKeyVersionInvalidInput_throwsInvalidResourceName() {
        val (client, _) = buildClient()

        Assertions.assertThatThrownBy {
            client.resolveKeyVersion("not-a-resource")
        }.isInstanceOf(CloudKMSInvalidResourceNameException::class.java)
    }

    @Test
    fun resolveKeyVersionCryptoKeyForm_callsListCryptoKeyVersionsWithExpectedRequest() {
        val pem = createPublicKey(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256, RSA_KEY_PEM)
        val paged = createPagedResponse(listOf(listOf(createCryptoKeyVersion(VALID_KEY_VERSION_3))))
        val kms = mockk<KeyManagementServiceClient> {
            every { listCryptoKeyVersions(any<ListCryptoKeyVersionsRequest>()) } returns paged
            every { getPublicKey(any<GetPublicKeyRequest>()) } returns pem
        }
        val (client, _) = buildClient(client = kms)

        client.resolveKeyVersion(VALID_KEY)

        val captor = slot<ListCryptoKeyVersionsRequest>()
        verify { kms.listCryptoKeyVersions(capture(captor)) }
        Assertions.assertThat(captor.captured.parent).isEqualTo(VALID_KEY)
        Assertions.assertThat(captor.captured.filter).isEqualTo("state=ENABLED")
        Assertions.assertThat(captor.captured.pageSize).isEqualTo(1)
    }

    @Test
    fun resolveKeyVersionCryptoKeyFormWithEmptyPages_throwsNoEnabledVersions() {
        val paged = createPagedResponse(emptyList())
        val kms = mockk<KeyManagementServiceClient> {
            every { listCryptoKeyVersions(any<ListCryptoKeyVersionsRequest>()) } returns paged
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.resolveKeyVersion(VALID_KEY) },
            CloudKMSNoEnabledVersionsException::class.java
        )
        Assertions.assertThat(ex.message).contains(VALID_KEY)
    }

    @Test
    fun resolveKeyVersionCryptoKeyFormWithEmptyPageValues_throwsNoEnabledVersions() {
        val paged = createPagedResponse(listOf(emptyList()))
        val kms = mockk<KeyManagementServiceClient> {
            every { listCryptoKeyVersions(any<ListCryptoKeyVersionsRequest>()) } returns paged
        }
        val (client, _) = buildClient(client = kms)

        Assertions.assertThatThrownBy {
            client.resolveKeyVersion(VALID_KEY)
        }.isInstanceOf(CloudKMSNoEnabledVersionsException::class.java)
    }

    @Test
    fun resolveKeyVersionCryptoKeyForm_returnsParsedEnabledVersion() {
        val pem = createPublicKey(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256, RSA_KEY_PEM)
        val paged = createPagedResponse(listOf(listOf(createCryptoKeyVersion(VALID_KEY_VERSION_3))))
        val kms = mockk<KeyManagementServiceClient> {
            every { listCryptoKeyVersions(any<ListCryptoKeyVersionsRequest>()) } returns paged
            every { getPublicKey(any<GetPublicKeyRequest>()) } returns pem
        }
        val (client, _) = buildClient(client = kms)

        val result = client.resolveKeyVersion(VALID_KEY)

        Assertions.assertThat(result.name).isEqualTo(CryptoKeyVersionName.parse(VALID_KEY_VERSION_3))
        Assertions.assertThat(result.resolvedFromKey).isTrue()
    }

    @Test
    fun resolveKeyVersionListVersionsPermissionDenied_throwsAccessDenied() {
        val pd = mockPermissionDenied(causeMessage = "list denied")
        val kms = mockk<KeyManagementServiceClient> {
            every { listCryptoKeyVersions(any<ListCryptoKeyVersionsRequest>()) } throws pd
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.resolveKeyVersion(VALID_KEY) },
            CloudKMSAccessDeniedException::class.java
        )
        Assertions.assertThat(ex.message).isEqualTo("list denied")
    }

    @Test
    fun resolveKeyVersionCryptoKeyVersionForm_doesNotCallListCryptoKeyVersions() {
        val pem = createPublicKey(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256, RSA_KEY_PEM)
        val kms = mockk<KeyManagementServiceClient> {
            every { getPublicKey(any<GetPublicKeyRequest>()) } returns pem
        }
        val (client, _) = buildClient(client = kms)

        val result = client.resolveKeyVersion(VALID_KEY_VERSION_1)

        verify(exactly = 0) { kms.listCryptoKeyVersions(any<ListCryptoKeyVersionsRequest>()) }
        Assertions.assertThat(result.name).isEqualTo(CryptoKeyVersionName.parse(VALID_KEY_VERSION_1))
        Assertions.assertThat(result.resolvedFromKey).isEqualTo(false)
    }

    @Test
    fun resolveKeyVersionCallsGetPublicKeyWithParsedNameAndPemFormat() {
        val pem = createPublicKey(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256, RSA_KEY_PEM)
        val kms = mockk<KeyManagementServiceClient> {
            every { getPublicKey(any<GetPublicKeyRequest>()) } returns pem
        }
        val (client, _) = buildClient(client = kms)

        client.resolveKeyVersion(VALID_KEY_VERSION_1)

        val captor = slot<GetPublicKeyRequest>()
        verify { kms.getPublicKey(capture(captor)) }
        Assertions.assertThat(captor.captured.name).isEqualTo(VALID_KEY_VERSION_1)
        Assertions.assertThat(captor.captured.publicKeyFormat).isEqualTo(PublicKey.PublicKeyFormat.PEM)
    }

    @Test
    fun resolveKeyVersionGetPublicKeyPermissionDenied_throwsAccessDenied() {
        val pd = mockPermissionDenied(causeMessage = "pk denied")
        val kms = mockk<KeyManagementServiceClient> {
            every { getPublicKey(any<GetPublicKeyRequest>()) } throws pd
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.resolveKeyVersion(VALID_KEY_VERSION_1) },
            CloudKMSAccessDeniedException::class.java
        )
        Assertions.assertThat(ex.message).isEqualTo("pk denied")
    }

    @Test
    fun resolveKeyVersionReturnsJwtKeyVersionWithExpectedJwk() {
        val pem = createPublicKey(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256, RSA_KEY_PEM)
        val kms = mockk<KeyManagementServiceClient> {
            every { getPublicKey(any<GetPublicKeyRequest>()) } returns pem
        }
        val (client, _) = buildClient(client = kms)

        val result = client.resolveKeyVersion(VALID_KEY_VERSION_1)

        Assertions.assertThat(result.publicJwk).isInstanceOf(RSAKey::class.java)
        val rsa = result.publicJwk as RSAKey
        Assertions.assertThat(rsa.algorithm).isEqualTo(JWSAlgorithm.RS256)
        Assertions.assertThat(rsa.keyID).isNotNull()
        Assertions.assertThat(result.gcpAlg).isEqualTo(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256)
    }

    // ---------- sign ----------

    @Test
    fun signCallsAsymmetricSignWithExpectedRequest() {
        val payload = "hello-payload".toByteArray(StandardCharsets.UTF_8)
        val response = AsymmetricSignResponse.newBuilder()
            .setSignature(ByteString.copyFrom(byteArrayOf(0x10, 0x20)))
            .build()
        val kms = mockk<KeyManagementServiceClient> {
            every { asymmetricSign(any<AsymmetricSignRequest>()) } returns response
        }
        val (client, _) = buildClient(client = kms)

        client.sign(signableKeyVersion(), payload)

        val captor = slot<AsymmetricSignRequest>()
        verify { kms.asymmetricSign(capture(captor)) }
        Assertions.assertThat(captor.captured.name).isEqualTo(VALID_KEY_VERSION_1)
        Assertions.assertThat(payload.contentEquals(captor.captured.data.toByteArray())).isTrue()
    }

    @Test
    fun signReturnsBase64UrlOfSignatureBytes() {
        val signatureBytes = byteArrayOf(0x01, 0x02, 0x03, 0x7f.toByte(), 0x80.toByte(), 0xff.toByte())
        val response = AsymmetricSignResponse.newBuilder()
            .setSignature(ByteString.copyFrom(signatureBytes))
            .build()
        val kms = mockk<KeyManagementServiceClient> {
            every { asymmetricSign(any<AsymmetricSignRequest>()) } returns response
        }
        val (client, _) = buildClient(client = kms)

        val result = client.sign(signableKeyVersion(), byteArrayOf(1))

        Assertions.assertThat(result).isEqualTo(Base64URL.encode(signatureBytes).toString())
    }

    @Test
    fun signPermissionDenied_throwsAccessDenied() {
        val pd = mockPermissionDenied(causeMessage = "sign denied")
        val kms = mockk<KeyManagementServiceClient> {
            every { asymmetricSign(any<AsymmetricSignRequest>()) } throws pd
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.sign(signableKeyVersion(), byteArrayOf(1, 2, 3)) },
            CloudKMSAccessDeniedException::class.java
        )
        Assertions.assertThat(ex.message).isEqualTo("sign denied")
    }

    // ---------- checkAuthentication ----------

    @Test
    fun checkAuthenticationListLocationsReturnsNormally_returnsUnit() {
        val (client, _) = buildClient()

        Assertions.assertThatCode { client.checkAuthentication() }.doesNotThrowAnyException()
    }

    @Test
    fun checkAuthenticationCallsListLocationsWithProjectsQuestionMark() {
        val kms = mockk<KeyManagementServiceClient>(relaxed = true)
        val (client, _) = buildClient(client = kms)

        client.checkAuthentication()

        val captor = slot<ListLocationsRequest>()
        verify { kms.listLocations(capture(captor)) }
        Assertions.assertThat(captor.captured.name).isEqualTo("projects/?")
    }

    @Test
    fun checkAuthenticationInvalidArgument_swallowedAndReturnsNormally() {
        val ia = mockInvalidArgument()
        val kms = mockk<KeyManagementServiceClient> {
            every { listLocations(any<ListLocationsRequest>()) } throws ia
        }
        val (client, _) = buildClient(client = kms)

        Assertions.assertThatCode { client.checkAuthentication() }.doesNotThrowAnyException()
    }

    @Test
    fun checkAuthenticationPermissionDenied_throwsAccessDenied() {
        val pd = mockPermissionDenied(causeMessage = "auth denied")
        val kms = mockk<KeyManagementServiceClient> {
            every { listLocations(any<ListLocationsRequest>()) } throws pd
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.checkAuthentication() },
            CloudKMSAccessDeniedException::class.java
        )
        Assertions.assertThat(ex.message).isEqualTo("auth denied")
    }

    @Test
    fun checkAuthenticationUnauthenticatedWithCredentialMetadataMessage_throwsCloudKMSUnauthenticated() {
        val ua = mockUnauthenticated("UNAUTHENTICATED: Failed computing credential metadata: oh no")
        val kms = mockk<KeyManagementServiceClient> {
            every { listLocations(any<ListLocationsRequest>()) } throws ua
        }
        val (client, _) = buildClient(client = kms)

        val ex = Assertions.catchThrowableOfType(
            { client.checkAuthentication() },
            CloudKMSUnauthenticatedException::class.java
        )
        Assertions.assertThat(ex.message).contains(AUTH_SCOPE)
    }

    @Test
    fun checkAuthenticationUnauthenticatedWithoutCredentialMetadataMessage_rethrowsAsIs() {
        val original = mockUnauthenticated("UNAUTHENTICATED: token expired")
        val kms = mockk<KeyManagementServiceClient> {
            every { listLocations(any<ListLocationsRequest>()) } throws original
        }
        val (client, _) = buildClient(client = kms)

        val thrown = Assertions.catchThrowableOfType(
            { client.checkAuthentication() },
            UnauthenticatedException::class.java
        )
        Assertions.assertThat(thrown).isSameAs(original)
        clearFailure()
    }

    @Test
    fun checkAuthenticationOtherApiException_rethrowsAsIs() {
        val original = mockOtherApiException()
        val kms = mockk<KeyManagementServiceClient> {
            every { listLocations(any<ListLocationsRequest>()) } throws original
        }
        val (client, _) = buildClient(client = kms)

        val thrown = Assertions.catchThrowableOfType(
            { client.checkAuthentication() },
            ApiException::class.java
        )
        Assertions.assertThat(thrown).isSameAs(original)
    }

    // ---------- close ----------

    @Test
    fun closeDelegatesToUnderlyingClient() {
        val kms = mockk<KeyManagementServiceClient>(relaxed = true)
        val (client, _) = buildClient(client = kms)

        client.close()

        verify {
            kms.shutdownNow()
            kms.close()
        }
    }
}
