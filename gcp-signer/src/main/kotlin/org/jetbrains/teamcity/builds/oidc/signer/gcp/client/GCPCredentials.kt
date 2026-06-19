package org.jetbrains.teamcity.builds.oidc.signer.gcp.client

import com.google.auth.oauth2.GoogleCredentials
import com.google.auth.oauth2.ImpersonatedCredentials
import com.google.auth.oauth2.ServiceAccountCredentials
import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSConstants
import java.nio.charset.StandardCharsets

/**
 * [GCPCredentials] is a simple data class that represents different supported types of GCP credentials
 * and the intent to impersonate a different service account with said credentials.
 *
 * As of today, only [Environment] and [ServiceAccount] are supported.
 */
sealed class GCPCredentials(open val impersonationChain: String? = null) {
    abstract val typeName: String
    protected abstract val nonImpersonated: GoogleCredentials

    /**
     * Returns a pair <impersonated service account, delegation chain> (or null if the impersonation chain is not specified).
     * The delegation chain can be empty if there's a single service account specified.
     */
    private fun impersonateWithDelegates() = impersonationChain?.let {
        if (it.isBlank()) return@let null

        val split = it.split(CloudKMSConstants.Settings.DELEGATION_SEPARATOR).filter { d -> d.isNotBlank() }
        split.last() to split.dropLast(1)
    }

    /**
     * Returns a potentially impersonated [GoogleCredentials] instance built from the credentials object.
     */
    fun asGoogleCredentials(): GoogleCredentials {
        return impersonateWithDelegates()?.let {
            ImpersonatedCredentials.create(
                nonImpersonated,
                it.first,
                it.second,
                listOf(CloudKMSConstants.Client.AUTH_SCOPE),
                CloudKMSConstants.Client.IMPERSONATED_CREDENTIALS_LIFETIME_SECONDS
            )
        } ?: nonImpersonated.createScoped(CloudKMSConstants.Client.AUTH_SCOPE)
    }

    /**
     * Represents the [application default credentials](https://docs.cloud.google.com/docs/authentication/application-default-credentials)
     */
    data class Environment(override val impersonationChain: String? = null) : GCPCredentials() {
        override val typeName = CloudKMSConstants.CredentialsType.ENVIRONMENT
        override val nonImpersonated: GoogleCredentials by lazy { GoogleCredentials.getApplicationDefault() }
    }

    /**
     * Represents service account credentials (typically a JSON-encoded private key).
     */
    data class ServiceAccount(val key: String, override val impersonationChain: String? = null) : GCPCredentials() {
        override val typeName = CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY
        override val nonImpersonated: GoogleCredentials by lazy {
            ServiceAccountCredentials.fromStream(key.byteInputStream(StandardCharsets.UTF_8))
        }
    }
}
