package org.jetbrains.teamcity.builds.oidc.signer.gcp.admin

import com.intellij.openapi.diagnostic.Logger
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSConstants
import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSSettings
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.CloudKMSClientFactory
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.GCPCredentials
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSKeyRelatedException
import jetbrains.buildServer.log.Loggers
import java.nio.charset.StandardCharsets

class CloudKMSConnectionChecker @JvmOverloads constructor(
    private val settings: CloudKMSSettings,
    private val cloudKMSClientFactory: CloudKMSClientFactory = CloudKMSClientFactory.Default(),
) {
    private val LOG = Logger.getInstance(Loggers.SERVER_CATEGORY + "." + this.javaClass.name)

    // TODO this class retains as ThreadLocal in http-nio worker threads on plugin unload.
    enum class Step {
        AUTHENTICATING,
        FETCHING_PUBLIC_KEY,
        SIGNING_TEST_PAYLOAD,
    }

    data class Result(
        val success: Boolean,
        val failedStep: Step? = null,
        val error: String? = null,
    )

    fun providedOrDefaultSAKey(serviceAccountKey: String?, chain: String?): GCPCredentials.ServiceAccount? {
        if (serviceAccountKey?.isNotBlank() == true) {
            return GCPCredentials.ServiceAccount(serviceAccountKey, impersonationChain = chain)
        }

        val currentCredentials = settings.getCredentials()
        return if (currentCredentials is GCPCredentials.ServiceAccount) {
            currentCredentials.copy(impersonationChain = chain)
        } else {
            null
        }
    }

    fun check(
        credentialsType: String,
        serviceAccountKey: String?,
        impersonationChain: String?,
        gcpEndpoint: String?,
        kmsResourceName: String,
    ): Result {
        var currentStep: Step = Step.AUTHENTICATING

        val chain = impersonationChain?.ifBlank { null }
        val credentials = when (credentialsType) {
            CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY ->
                providedOrDefaultSAKey(serviceAccountKey, chain) ?: return Result(
                    success = false,
                    failedStep = currentStep,
                    error = "A service account JSON key is required when using service account credentials."
                )
            else -> GCPCredentials.Environment(impersonationChain = chain)
        }

        try {
            cloudKMSClientFactory.create(
                credentials,
                gcpEndpoint?.ifBlank { null },
                CloudKMSConstants.Client.TEST_CONNECTION_TIMEOUT_SECONDS,
                CloudKMSConstants.Client.TEST_CONNECTION_MAX_ATTEMPTS,
            ).use { client ->
                client.checkAuthentication()

                currentStep = Step.FETCHING_PUBLIC_KEY
                val resolvedVersion = client.resolveKeyVersion(kmsResourceName)

                currentStep = Step.SIGNING_TEST_PAYLOAD
                client.sign(resolvedVersion, "teamcity-test-connection".toByteArray(StandardCharsets.UTF_8))
            }

            return Result(success = true)
        } catch (e: JWTSignerException) {
            val errorMessage = if (e is CloudKMSKeyRelatedException) {
                e.messageWithoutKeyID()
            } else {
                e.message ?: "Unknown signer error (${e.javaClass.name}: ${e})"
            }.lines().firstOrNull()?.takeIf { it.isNotBlank() } ?: "Unknown error (${e.javaClass.name})"

            return Result(
                success = false,
                failedStep = currentStep,
                error = errorMessage
            )
        } catch (e: Exception) {
            LOG.error("Unexpected error testing GCP connection", e)
            return Result(
                success = false,
                failedStep = currentStep,
                error = e.message?.lines()?.firstOrNull()?.takeIf { it.isNotBlank() }?.let { "${e.javaClass.name}: $it" }
                    ?: "Unknown error (${e.javaClass.name})"
            )
        }
    }
}
