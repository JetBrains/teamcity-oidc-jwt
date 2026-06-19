package org.jetbrains.teamcity.builds.oidc.signer.gcp

import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerAdminSettings
import org.jetbrains.teamcity.builds.oidc.signer.gcp.admin.CloudKMSAdminSettings
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.CloudKMSDefaultClient
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSAccessDeniedException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyNotFoundException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyVersionNotEnabledException
import com.nimbusds.jose.util.Base64URL
import jetbrains.buildServer.serverSide.SBuild
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import java.nio.charset.StandardCharsets
import java.time.Instant

class CloudKMSSigner(
    private val adminSettings: CloudKMSAdminSettings,
    private val defaultClient: CloudKMSDefaultClient,
    private val jwkCache: JWKCache
): JWTSigner {
    override fun getId(): String = CloudKMSConstants.SIGNER_ID
    override fun getDisplayName() = CloudKMSConstants.SIGNER_DISPLAY_NAME
    override fun getAdminSettings(): JWTSignerAdminSettings = adminSettings

    private fun signJWTWithKey(keyVersion: JWTKeyVersion, payload: String, expiresAt: Instant): String {
        val toSign = "${keyVersion.jwsHeaderStr}.$payload"
        val toSignBytes = toSign.toByteArray(StandardCharsets.UTF_8)
        val signature = defaultClient.sign(keyVersion, toSignBytes)
        jwkCache.trackKey(keyVersion.publicJwk.keyID, keyVersion.publicJwk.toJSONString(), expiresAt)
        return "${toSign}.${signature}"
    }

    override fun makeJWT(build: SBuild, claimsJSON: ByteArray, expiresAt: Instant): String {
        val keyVersion = defaultClient.getLatestKeyVersion(false)
        val payload = Base64URL.encode(claimsJSON).toString()

        return try {
            signJWTWithKey(keyVersion, payload, expiresAt)
        } catch (e: CloudKMSException) {
            // The issue might be related to the key version being disabled or deleted.
            // If that's the case, it can be fixed by resolving the key version again.
            if (!keyVersion.resolvedFromKey) {
                // Re-resolution will not help since it is a specific version
                throw e
            }

            // Only try to re-resolve if the exception is either explicit 404, Access Denied (which also acts as 404)
            // or the key version is not enabled
            when(e) {
                is CloudKMSKeyNotFoundException -> {}
                is CloudKMSAccessDeniedException -> {}
                is CloudKMSKeyVersionNotEnabledException -> {}
                else -> throw e
            }

            // Explicitly fetch the KMS resource name again, since it might have changed from the last resolution.
            val invalidatedKeyVersion = defaultClient.getLatestKeyVersion(true)
            if (invalidatedKeyVersion.publicJwk.keyID == keyVersion.publicJwk.keyID) {
                // If re-resolution resulted in the same key, the failure cannot be fixed with re-resolution
                throw e
            }
            signJWTWithKey(invalidatedKeyVersion, payload, expiresAt)
        } catch (e: Exception) {
            if (e is JWTSignerException) throw e
            throw JWTSignerException(e)
        }
    }

    override fun getJWKS(): String {
        val keySet = mutableSetOf(currentKeyPublicJWK)
        keySet.addAll(jwkCache.fetchCachedJWKs().values)
        return """{"keys":[${keySet.joinToString(",")}]}"""
    }

    override fun getCurrentKeyPublicJWK(): String {
        try {
            val cachedVersion = defaultClient.getLatestKeyVersion(false)
            return cachedVersion.publicJwk.toJSONString()
        } catch (e: Exception) {
            if (e is JWTSignerException) throw e
            throw JWTSignerException(e)
        }
    }

    override fun getSigningAlgorithms(): List<String?> {
        return listOf(defaultClient.getLatestKeyVersion(false).publicJwk.algorithm.name)
    }
}
