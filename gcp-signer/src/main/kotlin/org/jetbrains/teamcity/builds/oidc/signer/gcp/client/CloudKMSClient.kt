package org.jetbrains.teamcity.builds.oidc.signer.gcp.client

import com.google.api.gax.core.FixedCredentialsProvider
import com.google.api.gax.retrying.RetrySettings
import com.google.api.gax.rpc.ApiException
import com.google.api.gax.rpc.FailedPreconditionException
import com.google.api.gax.rpc.InvalidArgumentException
import com.google.api.gax.rpc.NotFoundException
import com.google.api.gax.rpc.PermissionDeniedException
import com.google.api.gax.rpc.UnauthenticatedException
import com.google.cloud.kms.v1.AsymmetricSignRequest
import com.google.cloud.kms.v1.AsymmetricSignResponse
import com.google.cloud.kms.v1.CryptoKeyVersion
import com.google.cloud.kms.v1.CryptoKeyVersionName
import com.google.cloud.kms.v1.GetPublicKeyRequest
import com.google.cloud.kms.v1.KeyManagementServiceClient
import com.google.cloud.kms.v1.KeyManagementServiceSettings
import com.google.cloud.kms.v1.ListCryptoKeyVersionsRequest
import com.google.cloud.kms.v1.PublicKey
import com.google.cloud.location.ListLocationsRequest
import com.google.protobuf.ByteString
import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSConstants
import org.jetbrains.teamcity.builds.oidc.signer.gcp.JWTKeyVersion
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSAccessDeniedException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyNotFoundException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyVersionNotEnabledException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSNoEnabledVersionsException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSUnauthenticatedException
import com.nimbusds.jose.util.Base64URL
import jetbrains.buildServer.serverSide.IOGuard
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.util.validateKeyResourceName
import org.jetbrains.teamcity.builds.oidc.signer.gcp.asVersion
import org.threeten.bp.Duration
import java.io.Closeable

/**
 * [CloudKMSClient] is a thin wrapper around the [KeyManagementServiceClient] that handles
 * authentication and translates expected exceptions into [org.jetbrains.teamcity.builds.oidc.api.JWTSignerException]s.
 */
class CloudKMSClient (
    credentials: GCPCredentials,
    val gcpEndpoint: String? = null,
    timeoutSeconds: Long? = null,
    maxAttempts: Int? = null,
    provider: GoogleKMSClientProvider = GoogleKMSClientProvider.Default(),
) : Closeable {
    private val client: KeyManagementServiceClient = provider.create(
        KeyManagementServiceSettings.newBuilder().apply {
            // Generate a provider from GCPCredentials
            credentialsProvider = FixedCredentialsProvider.create(credentials.asGoogleCredentials())

            // Update endpoint if provided
            if (gcpEndpoint?.isNotBlank() == true) {
                endpoint = gcpEndpoint
            }

            // Update timeout and retries policy
            if (timeoutSeconds != null || maxAttempts != null) {
                val retrySettings = RetrySettings.newBuilder().apply {
                    if (timeoutSeconds != null) {
                        totalTimeout = Duration.ofSeconds(timeoutSeconds)
                    }
                    if (maxAttempts != null) {
                        setMaxAttempts(maxAttempts)
                    }
                }.build()

                applyToAllUnaryMethods {
                    it.retrySettings = retrySettings
                    null
                }
            }
        }.build()
    )

    /**
     * Maps expected exceptions from GCP to [org.jetbrains.teamcity.builds.oidc.api.JWTSignerException]s.
     *
     * @param keyName The name of the key that was being used for the operation.
     * @param block The block of code that may throw an expected exception.
     * @return The result of the block of code.
     */
    private fun<T> wrapExpectedErrors(keyName: String, block: () -> T): T {
        try {
            return block()
        } catch (e: NotFoundException) {
            // TODO Are all 404s about keys? I mean, most of them are, but still
            throw CloudKMSKeyNotFoundException(keyName)
        } catch (e: PermissionDeniedException) {
            throw CloudKMSAccessDeniedException(e.cause?.message ?: e.message ?: "${e.javaClass.simpleName}: $e")
        } catch (e: FailedPreconditionException) {
            val message = e.message

            // io.grpc.StatusRuntimeException: FAILED_PRECONDITION: <resourceName> is not enabled, current state is: DISABLED.
            if (message?.contains("is not enabled") == true) {
                throw CloudKMSKeyVersionNotEnabledException(
                    keyName,
                    message.substringAfterLast(": ", missingDelimiterValue = "").removeSuffix(".")
                )
            }
            throw e
        } catch (e: UnauthenticatedException) {
            // GCP does not know who we are
            if (e.message?.contains("Failed computing credential metadata") ?: false) {
                throw CloudKMSUnauthenticatedException(
                    "Could not prepare GCP credentials with scope '${CloudKMSConstants.Client.AUTH_SCOPE}'.", e
                )
            }
            throw e
        }
    }

    /**
     * Fetches a name of the first enabled CryptoKeyVersion returned by GCP for the given CryptoKey resource name.
     *
     * @param cryptoKeyResourceName The resource name of the CryptoKey to fetch the version for.
     * @return The CryptoKeyVersion resource name of the first returned enabled version.
     */
    private fun fetchAnyEnabledKeyVersion(cryptoKeyResourceName: String): CryptoKeyVersionName {
        val enabledVersion = IOGuard.allowNetworkCall<CryptoKeyVersion, Exception> {
            val versions = wrapExpectedErrors(cryptoKeyResourceName) {
                client.listCryptoKeyVersions(
                    ListCryptoKeyVersionsRequest.newBuilder()
                        .setParent(cryptoKeyResourceName)
                        .setFilter("state=ENABLED")
                        .setPageSize(1)  // We only need a single version
                        .build()
                )
            }
            versions.iteratePages().firstOrNull()?.values?.firstOrNull()
                ?: throw CloudKMSNoEnabledVersionsException(cryptoKeyResourceName)
        }

        return CryptoKeyVersionName.parse(enabledVersion.name)
    }

    /**
     * Fetches the public key for the given CryptoKeyVersion resource name.
     *
     * @param resolvedName The resource name of the CryptoKeyVersion to fetch the public key for.
     * @return The [PublicKey] object representing the public key.
     */
    private fun publicKey(resolvedName: CryptoKeyVersionName): PublicKey {
        val keyName = resolvedName.toString()

        return wrapExpectedErrors(keyName) {
            IOGuard.allowNetworkCall<PublicKey, Exception> {
                client.getPublicKey(
                    GetPublicKeyRequest.newBuilder()
                        .setName(keyName)
                        .setPublicKeyFormat(PublicKey.PublicKeyFormat.PEM)
                        .build()
                )
            }
        }
    }

    /**
     * Resolves the given resource name (CryptoKey or CryptoKeyVersion) to a [JWTKeyVersion].
     *
     * @param resourceName The resource name to resolve. Should be a resource name of a CryptoKey or CryptoKeyVersion.
     * @return A [JWTKeyVersion] object representing the resolved key version.
     */
    fun resolveKeyVersion(resourceName: String): JWTKeyVersion {
        validateKeyResourceName(resourceName)

        val isKeyReference = !resourceName.contains("/cryptoKeyVersions/")
        val resolved = if (isKeyReference) {
            fetchAnyEnabledKeyVersion(resourceName)
        } else {
            CryptoKeyVersionName.parse(resourceName)
        }

        val kmsPublicKey = publicKey(resolved)
        return kmsPublicKey.asVersion(resolved, isKeyReference)
    }

    /**
     * Tries to sign the given byte array using the provided [JWTKeyVersion].
     *
     * @param keyVersion The [JWTKeyVersion] to use for signing.
     * @param payload The byte array to sign.
     * @return The signature as a Base64URL-encoded string.
     */
    fun sign(keyVersion: JWTKeyVersion, payload: ByteArray): String {
        val keyName = keyVersion.name.toString()

        val result = wrapExpectedErrors(keyName) {
            IOGuard.allowNetworkCall<AsymmetricSignResponse, Exception> {
                client.asymmetricSign(
                    AsymmetricSignRequest.newBuilder()
                        .setName(keyName)
                        .setData(ByteString.copyFrom(payload))
                        .build()
                )
            }
        }

        return Base64URL.encode(result.signature.toByteArray()).toString()
    }

    /**
     * Checks if the credentials are valid and can be used to authenticate with GCP by making a simple request.
     * Throws an exception if authentication fails.
     *
     * This is a dirty hack, but it works, and I'm not sure if there's a better way to do it.
     */
    fun checkAuthentication(): Unit = IOGuard.allowNetworkCall<Unit, Exception> {
        try {
            // Use a simple dummy request to check credentials
            client.listLocations(ListLocationsRequest.newBuilder().setName("projects/?").build())
        } catch (e: ApiException) {
            when(e) {
                is InvalidArgumentException -> {
                    // The argument is indeed invalid, but we were only interested if GCP authenticated us or not,
                    // which it did. Success!
                }
                is PermissionDeniedException -> {
                    // GCP knows who we are, but we don't have permission to do the list.
                    // This might be an impersonation issue, so we throw an `AccessDeniedException`.
                    // TODO Catch impersonation issues meaningfully?
                    throw CloudKMSAccessDeniedException(e.cause?.message ?: e.message ?: "${e.javaClass.simpleName}: $e")
                }
                is UnauthenticatedException -> {
                    // GCP does not know who we are
                    if (e.message?.contains("Failed computing credential metadata") ?: false) {
                        throw CloudKMSUnauthenticatedException(
                            "Could not prepare GCP credentials with scope '${CloudKMSConstants.Client.AUTH_SCOPE}'.", e
                        )
                    }
                    throw e
                }
                else -> throw e
            }
        }
    }

    override fun close() {
        client.shutdownNow()
        client.close()
    }
}
