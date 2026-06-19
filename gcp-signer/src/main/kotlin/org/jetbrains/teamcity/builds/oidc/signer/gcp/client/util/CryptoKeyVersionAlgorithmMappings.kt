package org.jetbrains.teamcity.builds.oidc.signer.gcp.client.util

import com.google.cloud.kms.v1.CryptoKeyVersion
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyAlgorithmNotSupportedException
import com.nimbusds.jose.JWSAlgorithm

// When adding new algorithms, remember to update the JWTKeyVersion's `wrap` method

fun CryptoKeyVersion.CryptoKeyVersionAlgorithm.toHumanReadable() = when (this) {
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_2048_SHA256 -> "2048 bit RSA - PSS Padding - SHA256 Digest"
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_3072_SHA256 -> "3072 bit RSA - PSS Padding - SHA256 Digest"
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA256 -> "4096 bit RSA - PSS Padding - SHA256 Digest"
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA512 -> "4096 bit RSA - PSS Padding - SHA512 Digest"
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256 -> "2048 bit RSA - PKCS#1 v1.5 padding - SHA256 Digest"
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256 -> "3072 bit RSA - PKCS#1 v1.5 padding - SHA256 Digest"
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256 -> "4096 bit RSA - PKCS#1 v1.5 padding - SHA256 Digest"
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512 -> "4096 bit RSA - PKCS#1 v1.5 padding - SHA512 Digest"
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256 -> "Elliptic Curve P-256 - SHA256 Digest"
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384 -> "Elliptic Curve P-384 - SHA384 Digest"
    else -> this.name
}

fun CryptoKeyVersion.CryptoKeyVersionAlgorithm.toJwsAlg(keyId: String? = null): JWSAlgorithm = when(this) {
    // PS256
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_2048_SHA256,
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_3072_SHA256,
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA256 -> JWSAlgorithm.PS256
    // PS512
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA512 -> JWSAlgorithm.PS512
    // RS256
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256,
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256,
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256 -> JWSAlgorithm.RS256
    // RS512
    CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512 -> JWSAlgorithm.RS512
    // TODO Check if GCP signs with ES256 and ES384 properly, as jwt.io does not like the signatures
    // ES256
    // CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256 -> JWSAlgorithm.ES256
    // ES384
    // CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384 -> JWSAlgorithm.ES384
    else -> throw CloudKMSKeyAlgorithmNotSupportedException(keyId, this.name)
}
