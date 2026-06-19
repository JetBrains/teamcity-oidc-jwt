package org.jetbrains.teamcity.builds.oidc.signer.gcp.exception

import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException

abstract class CloudKMSException(message: String, cause: Throwable? = null) : JWTSignerException(message, cause)

abstract class CloudKMSKeyRelatedException(
    keyID: String?,
    private val messageWithNoKeyID: String,
    private val messageSuffix: String? = null,
    cause: Throwable? = null
)
    : CloudKMSException("${messageWithNoKeyID}${keyID?.let { ": $it" }}${messageSuffix?.let { " $it" } ?: ""}", cause) {
    fun messageWithoutKeyID() = messageWithNoKeyID + (messageSuffix?.let { " $it" } ?: "")
}

class CloudKMSKeyNotFoundException(keyId: String) : CloudKMSKeyRelatedException(keyId, "Key not found")

class CloudKMSKeyVersionNotEnabledException(keyVersion: String, state: String)
    : CloudKMSKeyRelatedException(keyVersion, "Key version is not enabled", if (state.isNotBlank()) "(state: $state)" else "")

class CloudKMSNoEnabledVersionsException(keyId: String) : CloudKMSKeyRelatedException(keyId, "Key has no enabled versions")

class CloudKMSKeyAlgorithmNotSupportedException(keyId: String?, algorithm: String)
    : CloudKMSKeyRelatedException(keyId, "Key algorithm $algorithm is unsupported")

class CloudKMSAccessDeniedException(message: String) : CloudKMSException(message)

class CloudKMSNoResourceNameException : CloudKMSException("No key resource name provided")

class CloudKMSInvalidResourceNameException(resourceName: String) : CloudKMSException("Invalid resource name: $resourceName.\n" +
        "Expected one of:\n" +
        "- projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}\n" +
        "- projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}"
)

class CloudKMSUnauthenticatedException(message: String, cause: Throwable? = null) : CloudKMSException(message, cause)

class CloudKMSServiceAccountKeyNotProvidedException : CloudKMSException("Service account key is not provided")
