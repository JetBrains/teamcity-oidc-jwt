package org.jetbrains.teamcity.builds.oidc.signer.gcp.client

fun interface CloudKMSClientFactory {
    fun create(
        credentials: GCPCredentials,
        gcpEndpoint: String?,
        timeoutSeconds: Long,
        maxAttempts: Int,
    ): CloudKMSClient

    // This could be an object, but we want to reduce the number of objects
    // for plugin unloading.
    class Default: CloudKMSClientFactory {
        override fun create(
            credentials: GCPCredentials,
            gcpEndpoint: String?,
            timeoutSeconds: Long,
            maxAttempts: Int
        ): CloudKMSClient {
            return CloudKMSClient(credentials, gcpEndpoint, timeoutSeconds, maxAttempts)
        }
    }
}
