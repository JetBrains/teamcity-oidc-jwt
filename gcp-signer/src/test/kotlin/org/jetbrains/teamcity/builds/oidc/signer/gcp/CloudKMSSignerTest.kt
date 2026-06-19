package org.jetbrains.teamcity.builds.oidc.signer.gcp

import com.google.cloud.kms.v1.CryptoKeyVersion
import com.google.cloud.kms.v1.CryptoKeyVersionName
import org.jetbrains.teamcity.builds.oidc.signer.gcp.admin.CloudKMSAdminSettings
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.CloudKMSDefaultClient
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSAccessDeniedException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyNotFoundException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyVersionNotEnabledException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSServiceAccountKeyNotProvidedException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSUnauthenticatedException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.BeforeMethod
import org.testng.annotations.DataProvider
import org.testng.annotations.Test
import io.mockk.*
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.time.Instant

class CloudKMSSignerTest : BaseTestCase() {
    private lateinit var adminSettings: CloudKMSAdminSettings
    private lateinit var defaultClient: CloudKMSDefaultClient
    private lateinit var jwkCache: JWKCache
    private lateinit var signer: CloudKMSSigner
    private lateinit var build: SBuild

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        adminSettings = mockk()
        defaultClient = mockk()
        build = mockk()
        jwkCache = mockk<JWKCache> {
            every { fetchCachedJWKs() } returns emptyMap()
            every { trackKey(any(), any(), any()) } returns Unit
            every { purge() } returns Unit
        }
        signer = CloudKMSSigner(adminSettings, defaultClient, jwkCache)
    }

    companion object {
        private val rsaKeyPair: KeyPair by lazy {
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        }
    }

    @DataProvider(name = "recoverableSignExceptions")
    fun recoverableSignExceptions(): Array<Array<Any>> = arrayOf(
        arrayOf(CloudKMSKeyNotFoundException("kid")),
        arrayOf(CloudKMSAccessDeniedException("denied")),
        arrayOf(CloudKMSKeyVersionNotEnabledException("v", "DESTROYED")),
    )

    private fun createKeyVersion(
        keyId: String = "kid-1",
        jwsHeaderStr: String = "HEADER",
        resolvedFromKey: Boolean = true,
        jwsAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256,
        name: CryptoKeyVersionName = CryptoKeyVersionName.of("p", "global", "r", "k", "1"),
        gcpAlg: CryptoKeyVersion.CryptoKeyVersionAlgorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256,
    ): JWTKeyVersion {
        val jwk: JWK = RSAKey.Builder(rsaKeyPair.public as RSAPublicKey)
            .algorithm(jwsAlgorithm)
            .keyID(keyId)
            .build()
        return JWTKeyVersion(
            name = name,
            gcpAlg = gcpAlg,
            publicJwk = jwk,
            jwsHeaderStr = jwsHeaderStr,
            resolvedFromKey = resolvedFromKey,
        )
    }

    @Test
    fun getId_returnsGcpKmsConstant() {
        Assertions.assertThat(signer.getId()).isEqualTo("gcp-kms")
    }

    @Test
    fun getDisplayName_returnsGoogleCloudKMS() {
        Assertions.assertThat(signer.getDisplayName()).isEqualTo("Google Cloud KMS")
    }

    @Test
    fun getAdminSettings_returnsProvidedAdminSettingsInstance() {
        Assertions.assertThat(signer.getAdminSettings()).isSameAs(adminSettings)
    }

    @Test
    fun makeJWT_happyPath_returnsValidJwt() {
        val keyVersion = createKeyVersion(jwsHeaderStr = "HEADER")
        val claimsJson = """{"sub":"x"}""".toByteArray()
        val expiresAt = Instant.parse("2030-01-01T00:00:00Z")
        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion
        every { defaultClient.sign(eq(keyVersion), any()) } returns "SIG"

        val jwt = signer.makeJWT(build, claimsJson, expiresAt)

        val expectedPayload = Base64URL.encode(claimsJson).toString()
        Assertions.assertThat(jwt).isEqualTo("HEADER.$expectedPayload.SIG")

        val parts = jwt.split(".")
        Assertions.assertThat(parts).hasSize(3)
        Assertions.assertThat(parts[0]).isEqualTo("HEADER")
        Assertions.assertThat(Base64URL.from(parts[1]).decode().toList()).isEqualTo(claimsJson.toList())
        Assertions.assertThat(parts[2]).isEqualTo("SIG")

        verify(exactly = 0) { defaultClient.getLatestKeyVersion(true) }
        verify(exactly = 1) {
            jwkCache.trackKey(
                eq(keyVersion.publicJwk.keyID),
                eq(keyVersion.publicJwk.toJSONString()),
                eq(expiresAt)
            )
        }
    }

    @Test
    fun makeJWT_initialKeyResolutionThrows_propagatesException() {
        every { defaultClient.getLatestKeyVersion(false) } throws CloudKMSServiceAccountKeyNotProvidedException()

        Assertions.assertThatThrownBy {
            signer.makeJWT(build, "{}".toByteArray(), Instant.parse("2030-01-01T00:00:00Z"))
        }.isInstanceOf(CloudKMSServiceAccountKeyNotProvidedException::class.java)

        verify(exactly = 0) { defaultClient.sign(any(), any()) }
    }

    @Test
    fun makeJWT_signFails_keyVersionNotResolvedFromKey_doesNotRetry() {
        val keyVersion = createKeyVersion(keyId = "kid-1", resolvedFromKey = false)
        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion
        every { defaultClient.sign(eq(keyVersion), any()) } throws CloudKMSKeyNotFoundException("kid-1")

        Assertions.assertThatThrownBy {
            signer.makeJWT(build, "{}".toByteArray(), Instant.parse("2030-01-01T00:00:00Z"))
        }.isInstanceOf(CloudKMSKeyNotFoundException::class.java)

        verify(exactly = 0) { defaultClient.getLatestKeyVersion(true) }
    }

    @Test
    fun makeJWT_signFailsWithUnrelatedCloudKmsException_doesNotRetry() {
        val keyVersion = createKeyVersion(resolvedFromKey = true)
        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion
        every { defaultClient.sign(eq(keyVersion), any()) } throws CloudKMSUnauthenticatedException("nope")

        Assertions.assertThatThrownBy {
            signer.makeJWT(build, "{}".toByteArray(), Instant.parse("2030-01-01T00:00:00Z"))
        }.isInstanceOf(CloudKMSUnauthenticatedException::class.java)

        verify(exactly = 0) { defaultClient.getLatestKeyVersion(true) }
    }

    @Test(dataProvider = "recoverableSignExceptions")
    fun makeJWT_signFailsWithRecoverableException_reResolvesAndSucceeds(
        recoverableException: CloudKMSException,
    ) {
        val originalKey = createKeyVersion(keyId = "old", jwsHeaderStr = "OLD", resolvedFromKey = true)
        val reResolvedKey = createKeyVersion(keyId = "new", jwsHeaderStr = "NEW", resolvedFromKey = true)
        val claimsJson = """{"sub":"x"}""".toByteArray()

        every { defaultClient.getLatestKeyVersion(false) } returns originalKey
        every { defaultClient.getLatestKeyVersion(true) } returns reResolvedKey
        every { defaultClient.sign(eq(originalKey), any()) } throws recoverableException
        every { defaultClient.sign(eq(reResolvedKey), any()) } returns "SIG2"

        val jwt = signer.makeJWT(build, claimsJson, Instant.parse("2030-01-01T00:00:00Z"))

        val expectedPayload = Base64URL.encode(claimsJson).toString()
        Assertions.assertThat(jwt).isEqualTo("NEW.$expectedPayload.SIG2")

        verify(exactly = 1) { defaultClient.getLatestKeyVersion(true) }
        verify(exactly = 2) { defaultClient.sign(any(), any()) }
        verify(exactly = 1) { jwkCache.trackKey(eq("new"), any(), any()) }
        verify(exactly = 0) { jwkCache.trackKey(eq("old"), any(), any()) }
    }

    @Test
    fun makeJWT_reResolutionReturnsSameKeyId_throwsOriginalException() {
        val keyVersion = createKeyVersion(keyId = "same-kid", resolvedFromKey = true)
        val originalException = CloudKMSKeyNotFoundException("same-kid")

        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion
        every { defaultClient.getLatestKeyVersion(true) } returns keyVersion
        every { defaultClient.sign(eq(keyVersion), any()) } throws originalException

        val caught = Assertions.catchThrowableOfType(
            { signer.makeJWT(build, "{}".toByteArray(), Instant.parse("2030-01-01T00:00:00Z")) },
            CloudKMSKeyNotFoundException::class.java
        )
        Assertions.assertThat(caught).isSameAs(originalException)

        verify(exactly = 1) { defaultClient.sign(any(), any()) }
    }

    @Test
    fun makeJWT_signFailsAfterSuccessfulReResolution_throwsRetrySignFailure() {
        val originalKey = createKeyVersion(keyId = "old", resolvedFromKey = true)
        val reResolvedKey = createKeyVersion(keyId = "new", resolvedFromKey = true)

        every { defaultClient.getLatestKeyVersion(false) } returns originalKey
        every { defaultClient.getLatestKeyVersion(true) } returns reResolvedKey
        every { defaultClient.sign(eq(originalKey), any()) } throws CloudKMSKeyNotFoundException("old")
        every { defaultClient.sign(eq(reResolvedKey), any()) } throws CloudKMSAccessDeniedException("still-bad")

        Assertions.assertThatThrownBy {
            signer.makeJWT(build, "{}".toByteArray(), Instant.parse("2030-01-01T00:00:00Z"))
        }.isInstanceOf(CloudKMSAccessDeniedException::class.java)

        verify(exactly = 2) { defaultClient.sign(any(), any()) }
    }

    @Test
    fun makeJWT_signThrowsJWTSignerException_propagates() {
        val keyVersion = createKeyVersion(resolvedFromKey = true)
        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion
        every { defaultClient.sign(eq(keyVersion), any()) } throws JWTSignerException("boom")

        Assertions.assertThatThrownBy {
            signer.makeJWT(build, "{}".toByteArray(), Instant.parse("2030-01-01T00:00:00Z"))
        }.isInstanceOf(JWTSignerException::class.java)

        verify(exactly = 0) { defaultClient.getLatestKeyVersion(true) }
    }

    @Test
    fun makeJWT_signThrowsNonCloudKmsException_wrapsAndPropagates() {
        val keyVersion = createKeyVersion(resolvedFromKey = true)
        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion
        every { defaultClient.sign(eq(keyVersion), any()) } throws RuntimeException("boom")

        Assertions.assertThatThrownBy {
            signer.makeJWT(build, "{}".toByteArray(), Instant.parse("2030-01-01T00:00:00Z"))
        }.isInstanceOf(JWTSignerException::class.java)

        verify(exactly = 0) { defaultClient.getLatestKeyVersion(true) }
    }

    @Test
    fun getJWKS_emptyCache_returnsOnlyCurrentKey() {
        val keyVersion = createKeyVersion(keyId = "jwks-kid")
        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion
        every { jwkCache.fetchCachedJWKs() } returns emptyMap()

        val jwks = signer.getJWKS()

        val parsed = JWKSet.parse(jwks)
        Assertions.assertThat(parsed.keys).hasSize(1)
        val key = parsed.keys[0]
        Assertions.assertThat(key.keyID).isEqualTo("jwks-kid")
        Assertions.assertThat(key.algorithm).isEqualTo(JWSAlgorithm.RS256)
        Assertions.assertThat(key.toJSONObject()).isEqualTo(keyVersion.publicJwk.toJSONObject())
    }

    @Test
    fun getJWKS_cachedKeys_returnsCurrentPlusCached() {
        val current = createKeyVersion(keyId = "current-kid")
        val extra1 = createKeyVersion(keyId = "extra-1").publicJwk
        val extra2 = createKeyVersion(keyId = "extra-2").publicJwk
        every { defaultClient.getLatestKeyVersion(false) } returns current
        every { jwkCache.fetchCachedJWKs() } returns mapOf(
            extra1.keyID to extra1.toJSONString(),
            extra2.keyID to extra2.toJSONString(),
        )

        val parsed = JWKSet.parse(signer.getJWKS())

        Assertions.assertThat(parsed.keys.map { it.keyID })
            .containsExactlyInAnyOrder("current-kid", "extra-1", "extra-2")
    }

    @Test
    fun getJWKS_cacheContainsCurrentKey_doesNotDuplicate() {
        val current = createKeyVersion(keyId = "current-kid")
        every { defaultClient.getLatestKeyVersion(false) } returns current
        every { jwkCache.fetchCachedJWKs() } returns mapOf(
            current.publicJwk.keyID to current.publicJwk.toJSONString()
        )

        val parsed = JWKSet.parse(signer.getJWKS())

        Assertions.assertThat(parsed.keys).hasSize(1)
        Assertions.assertThat(parsed.keys[0].keyID).isEqualTo("current-kid")
    }

    @Test
    fun getJWKS_noCachedKeyVersion_throwsServiceAccountKeyNotProvided() {
        every { defaultClient.getLatestKeyVersion(false) } throws CloudKMSServiceAccountKeyNotProvidedException()

        Assertions.assertThatThrownBy {
            signer.getJWKS()
        }.isInstanceOf(CloudKMSServiceAccountKeyNotProvidedException::class.java)
    }

    @Test
    fun getSigningAlgorithms_returnsAlgorithmFromCachedKeyVersion() {
        val keyVersion = createKeyVersion(jwsAlgorithm = JWSAlgorithm.RS256)
        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion

        Assertions.assertThat(signer.getSigningAlgorithms()).isEqualTo(listOf("RS256"))
    }

    @Test
    fun getSigningAlgorithms_noCachedKeyVersion_throwsServiceAccountKeyNotProvided() {
        every { defaultClient.getLatestKeyVersion(false) } throws CloudKMSServiceAccountKeyNotProvidedException()

        Assertions.assertThatThrownBy {
            signer.getSigningAlgorithms()
        }.isInstanceOf(CloudKMSServiceAccountKeyNotProvidedException::class.java)
    }

    @Test
    fun makeJWT_signFails_doesNotTrackKey() {
        val keyVersion = createKeyVersion(resolvedFromKey = true)
        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion
        every { defaultClient.sign(eq(keyVersion), any()) } throws CloudKMSUnauthenticatedException("nope")

        Assertions.assertThatThrownBy {
            signer.makeJWT(build, "{}".toByteArray(), Instant.parse("2030-01-01T00:00:00Z"))
        }.isInstanceOf(CloudKMSUnauthenticatedException::class.java)

        verify(exactly = 0) { jwkCache.trackKey(any(), any(), any()) }
    }

    @Test
    fun makeJWT_initialKeyResolutionThrows_doesNotTrackKey() {
        every { defaultClient.getLatestKeyVersion(false) } throws CloudKMSServiceAccountKeyNotProvidedException()

        Assertions.assertThatThrownBy {
            signer.makeJWT(build, "{}".toByteArray(), Instant.parse("2030-01-01T00:00:00Z"))
        }.isInstanceOf(CloudKMSServiceAccountKeyNotProvidedException::class.java)

        verify(exactly = 0) { jwkCache.trackKey(any(), any(), any()) }
    }

    @Test
    fun getCurrentKeyPublicJWK_happyPath_returnsCachedKeyVersionPublicJwkJson() {
        val keyVersion = createKeyVersion(keyId = "current-kid")
        every { defaultClient.getLatestKeyVersion(false) } returns keyVersion

        val result = signer.getCurrentKeyPublicJWK()

        Assertions.assertThat(result).isEqualTo(keyVersion.publicJwk.toJSONString())
        verify(exactly = 0) { defaultClient.getLatestKeyVersion(true) }
    }

    @Test
    fun getCurrentKeyPublicJWK_keyResolutionThrowsJWTSignerException_propagates() {
        every { defaultClient.getLatestKeyVersion(false) } throws CloudKMSServiceAccountKeyNotProvidedException()

        Assertions.assertThatThrownBy {
            signer.getCurrentKeyPublicJWK()
        }.isInstanceOf(CloudKMSServiceAccountKeyNotProvidedException::class.java)
    }

    @Test
    fun getCurrentKeyPublicJWK_keyResolutionThrowsGenericException_wrapsInJWTSignerException() {
        val cause = RuntimeException("boom")
        every { defaultClient.getLatestKeyVersion(false) } throws cause

        val ex = Assertions.catchThrowableOfType(
            { signer.getCurrentKeyPublicJWK() },
            JWTSignerException::class.java
        )
        Assertions.assertThat(ex.cause).isSameAs(cause)
    }
}
