package org.jetbrains.teamcity.builds.oidc.signer.gcp.client

import com.google.cloud.kms.v1.KeyManagementServiceClient
import com.google.cloud.kms.v1.KeyManagementServiceSettings

fun interface GoogleKMSClientProvider {
    fun create(settings: KeyManagementServiceSettings): KeyManagementServiceClient

    // This could be an object, but we want to reduce the number of objects
    // for plugin unloading.
    class Default: GoogleKMSClientProvider {
        override fun create(settings: KeyManagementServiceSettings): KeyManagementServiceClient {
            return KeyManagementServiceClient.create(settings)
        }
    }
}
