package org.jetbrains.teamcity.builds.oidc.signer.gcp.admin

import org.jetbrains.teamcity.builds.oidc.api.JWTSignerAdminSettings
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSConstants
import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSSettings
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.CloudKMSDefaultClient
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.GCPCredentials
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.util.toHumanReadable
import jetbrains.buildServer.web.openapi.PluginDescriptor
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.util.validateKeyResourceName
import java.net.URI

/**
 * [CloudKMSAdminSettings] handles the admin page requests for the Cloud KMS signer.
 * Connection testing is performed by the provided [CloudKMSConnectionChecker],
 * and settings are stored by the provided [CloudKMSSettings] instance.
 */
class CloudKMSAdminSettings(
    val pluginDescriptor: PluginDescriptor,
    val settings: CloudKMSSettings,
    val defaultClient: CloudKMSDefaultClient,
    val cloudKMSConnectionChecker: CloudKMSConnectionChecker
) : JWTSignerAdminSettings {
    private val urlStartRegex = Regex("^[a-z0-9+.-]+?://.*$", RegexOption.IGNORE_CASE)

    override fun getSettingsPagePath(): String =
        pluginDescriptor.getPluginResourcesPath(CloudKMSConstants.Admin.SETTINGS_JSP)

    private fun hasServiceAccountKey(creds: GCPCredentials): Boolean {
        return creds is GCPCredentials.ServiceAccount && creds.key.isNotBlank()
    }

    override fun fillSettingsModel(model: MutableMap<String, Any>) {
        // Populate credentials info
        val credentials = settings.getCredentials()
        model["credentialsType"] = credentials.typeName
        model["impersonationChain"] = credentials.impersonationChain ?: ""
        model["hasServiceAccountKey"] = hasServiceAccountKey(credentials)

        // Populate GCP endpoint info
        model["gcpEndpoint"] = settings.getGCPEndpoint() ?: ""

        // Populate key resource name
        val resourceName = settings.getKeyResourceName()
        model["kmsResourceName"] = resourceName ?: ""

        // Populate key version info if the resource name is valid
        if (resourceName != null) {
            try {
                val keyVersion = defaultClient.getKeyVersion(resourceName, false)
                model["currentKeyVersionName"] = keyVersion.name.toString()
                model["currentKeyVersionGCPAlgorithm"] = keyVersion.gcpAlg.toHumanReadable()
                model["currentKeyVersionJWSAlgorithm"] = keyVersion.publicJwk.algorithm.name
            } catch (_: Exception) {
                // Key version info is best-effort; don't break the admin page
            }
        }
    }

    override fun validateSettings(params: Map<String, String>): Map<String, String> {
        val credentialsTypeStr = params[CloudKMSConstants.Settings.CREDENTIALS_TYPE_ATTR]?.trim() ?: ""
        val kmsResourceName = params[CloudKMSConstants.Settings.KMS_RESOURCE_NAME_ELEMENT]?.trim() ?: ""
        val serviceAccountKey = params[CloudKMSConstants.Settings.SERVICE_ACCOUNT_KEY_ELEMENT]?.trim() ?: ""
        val impersonationChain = params[CloudKMSConstants.Settings.IMPERSONATION_CHAIN_ELEMENT]?.trim() ?: ""
        val gcpEndpoint = params[CloudKMSConstants.Settings.GCP_ENDPOINT_ELEMENT]?.trim() ?: ""

        // Validate the resource name
        try {
            validateKeyResourceName(kmsResourceName)
        } catch (e: Exception) {
            return mapOf("kmsResourceName" to (e.message?.lines()?.firstOrNull() ?: "Could not validate KMS resource name."))
        }

        // Validate credentials
        if (credentialsTypeStr != CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY &&
            credentialsTypeStr != CloudKMSConstants.CredentialsType.ENVIRONMENT) {
            return mapOf("credentialsError" to "Invalid credentials type '$credentialsTypeStr'.")
        }

        // Fail if the selected credentials type is Service Account, but there's no key anywhere
        // (in user request and currently saved)
        val currentCredentials = settings.getCredentials()
        if (credentialsTypeStr == CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY
            && serviceAccountKey.isBlank() && !hasServiceAccountKey(currentCredentials)) {
            return mapOf("serviceAccountKey" to "A service account JSON key is required when using service account credentials.")
        }

        // Validate impersonation chain
        if (impersonationChain.isNotBlank()) {
            val parts = impersonationChain.split(CloudKMSConstants.Settings.DELEGATION_SEPARATOR)
            if (parts.any { it.isBlank() }) {
                return mapOf("impersonationChain" to "The impersonation chain contains blank entries. Use '${CloudKMSConstants.Settings.DELEGATION_SEPARATOR}' to separate service account emails.")
            }
        }

        // Prepare GCP endpoint
        val preparedGCPEndpoint = try {
            prepareGCPEndpoint(gcpEndpoint)
        } catch (e: Exception) {
            return mapOf("gcpEndpointError" to (e.message?.lines()?.firstOrNull() ?: "Failed to parse GCP endpoint: $gcpEndpoint"))
        }

        // Test GCP connection
        val testResult = cloudKMSConnectionChecker.check(
            credentialsTypeStr,
            serviceAccountKey,
            impersonationChain,
            preparedGCPEndpoint,
            kmsResourceName
        )
        if (!testResult.success) {
            return when(testResult.failedStep) {
                CloudKMSConnectionChecker.Step.AUTHENTICATING -> {
                    mapOf("credentialsError" to ("Credential validation failed. ${testResult.error ?: "Unknown credentials error"}"))
                }

                CloudKMSConnectionChecker.Step.FETCHING_PUBLIC_KEY ->
                    mapOf("testConnectionKey" to ("Failed to fetch the public key. ${testResult.error ?: "Unknown public key fetching error"}"))

                CloudKMSConnectionChecker.Step.SIGNING_TEST_PAYLOAD ->
                    mapOf("testConnectionKey" to ("Failed to sign a test token. ${testResult.error ?: "Unknown signing error"}"))

                null -> mapOf("testConnectionKey" to "Unknown error: ${testResult.error ?: "Unknown error"}")
            }
        }

        return emptyMap()
    }

    private fun prepareGCPEndpoint(endpoint: String): String? {
        val trimmed = endpoint.trim()
        if (trimmed.isBlank()) return null

        return try {
            val uriToParse = if (trimmed.matches(urlStartRegex)) {
                trimmed
            } else {
                "https://$trimmed"
            }

            val uri = URI.create(uriToParse)

            val host = uri.host?.takeIf { it.isNotBlank() } ?: return null
            val port = if (uri.port != -1) {
                uri.port
            } else {
                if (uri.scheme?.lowercase() == "http") 80 else 443
            }

            "$host:$port"
        } catch (e: Exception) {
            throw JWTSignerException("Failed to parse GCP endpoint: $trimmed", e)
        }
    }

    override fun saveSettings(params: Map<String, String>): Map<String, String> {
        val credentialsTypeStr = params[CloudKMSConstants.Settings.CREDENTIALS_TYPE_ATTR]?.trim()!!
        val kmsResourceName = params[CloudKMSConstants.Settings.KMS_RESOURCE_NAME_ELEMENT]?.trim()!!
        val serviceAccountKey = params[CloudKMSConstants.Settings.SERVICE_ACCOUNT_KEY_ELEMENT]?.trim()!!
        val impersonationChain = params[CloudKMSConstants.Settings.IMPERSONATION_CHAIN_ELEMENT]?.trim() ?: ""
        val gcpEndpoint = params[CloudKMSConstants.Settings.GCP_ENDPOINT_ELEMENT]?.trim() ?: ""

        val preparedGCPEndpoint = try {
            prepareGCPEndpoint(gcpEndpoint)
        } catch (e: Exception) {
            return mapOf("gcpEndpointError" to (e.message?.lines()?.firstOrNull() ?: "Failed to parse GCP endpoint: $gcpEndpoint"))
        }

        settings.update(credentialsTypeStr, kmsResourceName, serviceAccountKey, impersonationChain, preparedGCPEndpoint)
        return emptyMap()
    }
}
