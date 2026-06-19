package org.jetbrains.teamcity.builds.oidc.signer.gcp

object CloudKMSConstants {
    const val SIGNER_ID = "gcp-kms"
    const val SIGNER_DISPLAY_NAME = "Google Cloud KMS"

    object Admin {
        const val SETTINGS_JSP = "gcp-kms.jsp"
    }

    object CredentialsType {
        const val SERVICE_ACCOUNT_KEY = "SERVICE_ACCOUNT_KEY"
        const val ENVIRONMENT = "ENVIRONMENT"
    }

    object Client {
        const val AUTH_SCOPE = "https://www.googleapis.com/auth/cloudkms"

        const val IMPERSONATED_CREDENTIALS_LIFETIME_SECONDS = 300

        const val DEFAULT_TIMEOUT_SECONDS = 15L
        const val DEFAULT_MAX_ATTEMPTS = 3

        const val TEST_CONNECTION_TIMEOUT_SECONDS = 5L
        const val TEST_CONNECTION_MAX_ATTEMPTS = 1
    }

    object Settings {
        const val IMPERSONATION_CHAIN_ELEMENT = "impersonationChain"
        const val DELEGATION_SEPARATOR = "|"

        const val GCP_ENDPOINT_ELEMENT = "gcpEndpoint"

        const val KMS_RESOURCE_NAME_ELEMENT = "kmsResourceName"
        const val KMS_RESOURCE_NAME_REGEX = "^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+(/cryptoKeyVersions/[^/]+)?$"

        const val FILE_NAME = "oidc-jwt-gcp-kms-settings.xml"
        const val ROOT_ELEMENT = "oidc-jwt-gcp-kms-settings"
        const val VERSION_ATTR = "version"
        const val FILE_VERSION = "1"
        const val PERSIST_DESCRIPTION = "Save GCP Cloud KMS signer settings"

        const val CREDENTIALS_TYPE_ATTR = "credentialsType"
        const val SERVICE_ACCOUNT_KEY_ELEMENT = "serviceAccountKey"
    }
}
