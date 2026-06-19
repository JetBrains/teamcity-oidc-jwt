package org.jetbrains.teamcity.builds.oidc.signer.gcp

import com.google.cloud.kms.v1.CryptoKeyVersion
import com.google.cloud.kms.v1.CryptoKeyVersionName
import com.google.cloud.kms.v1.PublicKey
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.util.toJwsAlg
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyAlgorithmNotSupportedException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Wrapper around a KMS key version that can be used to sign JWTs.
 */
data class JWTKeyVersion(
    val name: CryptoKeyVersionName,
    val gcpAlg: CryptoKeyVersion.CryptoKeyVersionAlgorithm,
    val publicJwk: JWK,
    val jwsHeaderStr: String,
    val resolvedFromKey: Boolean
)

fun PublicKey.asVersion(versionName: CryptoKeyVersionName, resolvedFromKey: Boolean): JWTKeyVersion {
    val jwsAlg = this.algorithm.toJwsAlg(versionName.toString())

    val pem = this.publicKey.data.toString(StandardCharsets.UTF_8)
    val pemBody = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace("\\s".toRegex(), "")
    val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(pemBody))

    val jwk: JWK = when(jwsAlg) {
        JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
        JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512 -> {
            val rsaPublicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec) as RSAPublicKey
            RSAKey.Builder(rsaPublicKey)
                .algorithm(jwsAlg)
                .keyUse(KeyUse.SIGNATURE)
                .keyIDFromThumbprint()
                .build()
        }

        JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512 -> {
            val ecPublicKey = KeyFactory.getInstance("EC").generatePublic(keySpec) as ECPublicKey
            ECKey.Builder(Curve.forJWSAlgorithm(jwsAlg).first(), ecPublicKey)
                .algorithm(jwsAlg)
                .keyUse(KeyUse.SIGNATURE)
                .keyIDFromThumbprint()
                .build()
        }

        else -> throw CloudKMSKeyAlgorithmNotSupportedException(versionName.toString(), this.algorithm.name)
    }
    val jwsHeader = JWSHeader.Builder(jwsAlg)
        .keyID(jwk.keyID)
        .build().toBase64URL().toString()

    return JWTKeyVersion(
        name = versionName,
        gcpAlg = this.algorithm,
        publicJwk = jwk,
        jwsHeaderStr = jwsHeader,
        resolvedFromKey = resolvedFromKey
    )
}
