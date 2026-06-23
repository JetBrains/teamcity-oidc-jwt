package org.jetbrains.teamcity.builds.oidc

import jetbrains.buildServer.agent.Constants.ENV_PREFIX
import jetbrains.buildServer.serverSide.auth.Permission

object OIDCConstants {
    const val PLUGIN_ID = "oidc-jwt"
    const val OIDC_ROOT_URL = "/app/$PLUGIN_ID"

    object BuiltInRSASigner {
        // A compromise between a faster 2048 (which NIST and others want to be gone by 2030) and a much slower 4096
        const val DEFAULT_RSA_KEY_BITS = 3072
        val ALLOWED_RSA_KEY_BITS = listOf(2048, 3072, 4096)

        const val DEFAULT_JWS_ALGORITHM = "RS256"
        val ALLOWED_JWS_ALGORITHMS = listOf("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")

        const val KEY_ROOT = PLUGIN_ID
        const val KEY_SUBDIR = "rsa"
        const val PRIVATE_KEY_NAME = "private.key"
        const val ID = "builtin-rsa"
        const val DISPLAY_NAME = "Built-in (RSA)"
        const val SETTINGS_JSP = "signerSettings/builtin-rsa.jsp"

        const val SETTINGS_FILE_NAME = "oidc-jwt-builtin-rsa-settings.xml"
        const val SETTINGS_ROOT_ELEMENT = "oidc-jwt-builtin-rsa-settings"
        const val SETTINGS_VERSION_ATTR = "version"
        const val SETTINGS_FILE_VERSION = "1"
        const val SETTINGS_PERSIST_DESCRIPTION = "Save OIDC plugin built-in RSA signer settings"

        const val SETTINGS_RSA_KEY_BITS_ATTR = "rsaKeyBits"
        const val SETTINGS_JWS_ALGORITHM_ATTR = "jwsAlgorithm"

        const val ROTATE_TASK_TYPE = "oidc-jwt-rotate-key-rsa"
    }

    object BuiltInECDSASigner {
        const val DEFAULT_JWS_ALGORITHM = "ES256"
        val ALLOWED_JWS_ALGORITHMS = listOf("ES256", "ES384", "ES512")

        const val KEY_ROOT = PLUGIN_ID
        const val KEY_SUBDIR = "ecdsa"
        const val PRIVATE_KEY_NAME = "private.key"
        const val ID = "builtin-ecdsa"
        const val DISPLAY_NAME = "Built-in (ECDSA)"
        const val SETTINGS_JSP = "signerSettings/builtin-ecdsa.jsp"

        const val SETTINGS_FILE_NAME = "oidc-jwt-builtin-ecdsa-settings.xml"
        const val SETTINGS_ROOT_ELEMENT = "oidc-jwt-builtin-ecdsa-settings"
        const val SETTINGS_VERSION_ATTR = "version"
        const val SETTINGS_FILE_VERSION = "1"
        const val SETTINGS_PERSIST_DESCRIPTION = "Save OIDC plugin built-in ECDSA signer settings"

        const val SETTINGS_JWS_ALGORITHM_ATTR = "jwsAlgorithm"

        const val ROTATE_TASK_TYPE = "oidc-jwt-rotate-key-ecdsa"
    }

    object BuiltInRotationController {
        // Root is /app/$PLUGIN_ID/$SIGNER_ID/rotate
        const val ROTATE_PATH = "/rotate"
    }

    object BuildFeatureInParams {
        const val FEATURE_TYPE = "oidcTokenInParams"
        const val DISPLAY_NAME = "OIDC Token (in build parameters)"

        const val BUILD_FEATURE_PATH_JSP = "oidcTokenInParamsBuildFeature.jsp"
        const val BUILD_FEATURE_PATH_HTML = "oidcTokenInParamsBuildFeature.html"

        // Kotlin DSL also refers to these parameters. Please update it as well.
        const val JWT_LIFETIME_BUFFER_MINUTES = 10

        const val DEFAULT_BUILDPARAM = ENV_PREFIX + "TEAMCITY_BUILD_OIDC_TOKEN"

        const val BUILDPARAM_PARAM = "buildParam"
        const val TOKEN_LIFETIME_SECONDS_PARAM = "tokenLifetimeSeconds"
        const val AUDIENCES_PARAM = "audiences"
    }

    object BuildFeatureOnDemand {
        const val FEATURE_TYPE = "oidcTokenOnDemand"
        const val DISPLAY_NAME = "OIDC Token (on demand via HTTP request)"

        const val BUILD_FEATURE_PATH_JSP = "oidcTokenOnDemandBuildFeature.jsp"
        const val BUILD_FEATURE_PATH_HTML = "oidcTokenOnDemandBuildFeature.html"

        // Kotlin DSL also refers to this parameter. Please update it as well.
        const val ENDPOINT_URL_PARAM = "teamcity.build.oidc.endpoint"
        const val AUDIENCES_PARAM = "audiences"

        const val CONTROLLER_ROOT = "issue"
        const val TOKEN_LIFETIME_SECONDS = 300L
    }

    object WellKnownController {
        const val ROOT = ".well-known"
        const val CONTROLLER_ROOT = "/${PLUGIN_ID}/${ROOT}"
        const val JWKS_PATH = "/jwks"
        const val CONFIG_PATH = "/openid-configuration"
        const val CONFIG_DOWNLOAD_PATH = "/openid-configuration.json"
        const val CACHE_SECONDS = 10L
    }

    object Injection {
        const val PROJECT_LOOKUP_ERROR_IDENTITY = "oidc_TokenInjector_ProjectLookupError"
        const val PROJECT_LOOKUP_ERROR_MESSAGE = "[OIDC JWT] Failed to look up the build's active project"

        const val SIGNER_LOOKUP_ERROR_IDENTITY = "oidc_TokenInjector_SignerLookupError"
        const val SIGNER_LOOKUP_ERROR_MESSAGE = "[OIDC JWT] Failed to look up the active signer"

        const val TOKEN_GENERATION_ERROR_IDENTITY = "oidc_TokenInjector_TokenGenerationError"
        const val TOKEN_GENERATION_ERROR_MESSAGE = "[OIDC JWT] Failed to generate JWT"

        const val DUPLICATE_INJECTION_PARAM_ERROR_IDENTITY = "oidc_TokenInjector_DuplicateInjectionParamError"
        const val DUPLICATE_INJECTION_PARAM_ERROR_MESSAGE = "[OIDC JWT] Duplicate injection parameter"
    }

    object Settings {
        const val FILE_NAME = "oidc-jwt-settings.xml"
        const val ROOT_ELEMENT = "oidc-jwt-settings"
        const val VERSION_ATTR = "version"
        const val FILE_VERSION = "1"
        const val PERSIST_DESCRIPTION = "Save OIDC plugin global settings"

        const val ACTIVE_SIGNER_ID_ATTR = "activeSignerId"
        const val OVERRIDE_ISSUER_ELEMENT = "issuer"
    }

    object JWKCache {
        const val STORAGE_ID_PREFIX = "oidc-jwt-jwk-cache-"

        const val FETCH_CACHE_EXPIRATION_MS = 500L

        const val MAX_JWK_WRITE_RETRIES = 3

        const val REVOCATION_PREFIX = "revoked:"

        const val CLEANUP_INTERVAL_MINUTES = 60L
        // Time to wait before considering the node offline and its JWK timestamps orphaned.
        const val OFFLINE_NODE_GRACE_PERIOD_MINUTES = 120L

        // Time to wait before deleting revoked JWKs from the database.
        // Needs to be long enough for all nodes to have switched to a new key.
        const val REVOCATION_GRACE_PERIOD_MINUTES = 10L

        const val PURGE_URL = "$OIDC_ROOT_URL/jwk-cache/purge"
    }

    object AdminPage {
        const val PLUGIN_NAME = PLUGIN_ID
        const val INCLUDE_URL_PATH = "oidcSignerSettings.jsp"
        const val MISSING_SIGNER_JSP = "signerSettings/missing-signer.jsp"
        const val TAB_TITLE = "OIDC Tokens"
        const val SAVE_URL = "/admin/oidcSignerSettings/save.html"
        val REQUIRED_PERMISSION = Permission.CHANGE_SERVER_SETTINGS
    }
}
