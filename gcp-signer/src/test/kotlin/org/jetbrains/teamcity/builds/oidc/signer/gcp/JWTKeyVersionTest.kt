package org.jetbrains.teamcity.builds.oidc.signer.gcp

import com.google.cloud.kms.v1.ChecksummedData
import com.google.cloud.kms.v1.CryptoKeyVersion
import com.google.cloud.kms.v1.CryptoKeyVersionName
import com.google.cloud.kms.v1.PublicKey
import com.google.protobuf.ByteString
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyAlgorithmNotSupportedException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.util.Base64URL
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.DataProvider
import org.testng.annotations.Test
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.util.Base64

class JWTKeyVersionTest : BaseTestCase() {

    companion object {
        // Generated once per test class run; reused across all RSA happy-path tests.
        private val RSA_KEY_PEM: String by lazy {
            val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            val encoded = Base64.getMimeEncoder().encodeToString(keyPair.public.encoded)
            "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----"
        }
    }

    @DataProvider(name = "supportedRsaAlgorithms")
    fun supportedRsaAlgorithms(): Array<Array<Any>> = arrayOf(
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_2048_SHA256,  JWSAlgorithm.PS256),
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_3072_SHA256,  JWSAlgorithm.PS256),
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA256,  JWSAlgorithm.PS256),
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA512,  JWSAlgorithm.PS512),
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256, JWSAlgorithm.RS256),
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256, JWSAlgorithm.RS256),
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256, JWSAlgorithm.RS256),
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512, JWSAlgorithm.RS512),
    )

    @DataProvider(name = "ecAlgorithms")
    fun ecAlgorithms(): Array<Array<Any>> = arrayOf(
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256),
        arrayOf(CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384),
    )

    private fun createPublicKey(
        algorithm: CryptoKeyVersion.CryptoKeyVersionAlgorithm,
        pem: String
    ): PublicKey = PublicKey.newBuilder()
        .setPublicKey(
            ChecksummedData.newBuilder()
                .setData(ByteString.copyFrom(pem.toByteArray(StandardCharsets.UTF_8)))
                .build()
        )
        .setAlgorithm(algorithm)
        .build()

    private fun createVersionName(): CryptoKeyVersionName =
        CryptoKeyVersionName.of("test-project", "global", "test-ring", "test-key", "1")

    @Test(dataProvider = "supportedRsaAlgorithms")
    fun rsaKey_wrapProducesCorrectJwk(
        gcpAlgorithm: CryptoKeyVersion.CryptoKeyVersionAlgorithm,
        expectedJwsAlgorithm: JWSAlgorithm
    ) {
        val publicKey = createPublicKey(gcpAlgorithm, RSA_KEY_PEM)

        val result = publicKey.asVersion(createVersionName(), resolvedFromKey = false)

        Assertions.assertThat(result.publicJwk.keyType).isEqualTo(KeyType.RSA)
        Assertions.assertThat(result.publicJwk.algorithm).isEqualTo(expectedJwsAlgorithm)
        Assertions.assertThat(result.publicJwk.keyUse).isEqualTo(KeyUse.SIGNATURE)
        Assertions.assertThat(result.publicJwk.keyID).isNotNull()
    }

    @Test
    fun rsaKey_wrapPreservesNameGcpAlgAndResolvedFromKey() {
        val versionName = createVersionName()
        val publicKey = createPublicKey(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256, RSA_KEY_PEM)

        val result = publicKey.asVersion(versionName, resolvedFromKey = true)

        Assertions.assertThat(result.name).isEqualTo(versionName)
        Assertions.assertThat(result.gcpAlg).isEqualTo(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256)
        Assertions.assertThat(result.resolvedFromKey).isTrue()
    }

    @Test
    fun rsaKey_jwsHeaderStrIsValidHeaderWithMatchingAlgAndKeyId() {
        val publicKey = createPublicKey(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256, RSA_KEY_PEM)

        val result = publicKey.asVersion(createVersionName(), resolvedFromKey = false)

        val parsedHeader = JWSHeader.parse(Base64URL(result.jwsHeaderStr))
        Assertions.assertThat(parsedHeader.algorithm).isEqualTo(JWSAlgorithm.RS256)
        Assertions.assertThat(parsedHeader.keyID).isEqualTo(result.publicJwk.keyID)
    }

    @Test(dataProvider = "ecAlgorithms")
    // EC algorithms are commented out in toJwsAlg(); the EC branch in wrap() is currently unreachable.
    fun gcpEcAlgorithm_throwsCloudKMSKeyAlgorithmNotSupportedException(
        algorithm: CryptoKeyVersion.CryptoKeyVersionAlgorithm
    ) {
        val publicKey = createPublicKey(algorithm, "placeholder")

        Assertions.assertThatThrownBy {
            publicKey.asVersion(createVersionName(), resolvedFromKey = false)
        }.isInstanceOf(CloudKMSKeyAlgorithmNotSupportedException::class.java)
    }

    @Test
    fun unspecifiedAlgorithm_throwsCloudKMSKeyAlgorithmNotSupportedException() {
        val publicKey = createPublicKey(
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED,
            "placeholder"
        )

        Assertions.assertThatThrownBy {
            publicKey.asVersion(createVersionName(), resolvedFromKey = false)
        }.isInstanceOf(CloudKMSKeyAlgorithmNotSupportedException::class.java)
    }

    @Test
    fun nonPemKey_throwsException() {
        val publicKey = createPublicKey(
            CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256,
            "not!valid!pem"
        )

        Assertions.assertThatThrownBy {
            publicKey.asVersion(createVersionName(), resolvedFromKey = false)
        }.isInstanceOf(IllegalArgumentException::class.java)
    }
}
