package org.jetbrains.teamcity.builds.oidc.signer.builtin

import org.jetbrains.teamcity.builds.oidc.api.JWTSignerAdminSettings
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.ALLOWED_JWS_ALGORITHMS
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.ALLOWED_RSA_KEY_BITS
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.KEY_ROOT
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.KEY_SUBDIR
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.PRIVATE_KEY_NAME
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.SETTINGS_JSP
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.SETTINGS_JWS_ALGORITHM_ATTR
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.SETTINGS_RSA_KEY_BITS_ATTR
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.ServerResponsibility
import jetbrains.buildServer.serverSide.crypt.Encryption
import jetbrains.buildServer.util.Cached
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.concurrent.write

/**
 * File-based RSA JWT signer. The key size is configurable; changing it rotates the key on save.
 */
class BuiltInRSASigner(
    controllerManager: WebControllerManager,
    serverResponsibility: ServerResponsibility,
    serverPaths: ServerPaths,
    encryption: Encryption,
    pluginDescriptor: PluginDescriptor,
    private val settingsStore: BuiltInRSASettingsStore,
    jwkCache: JWKCache,
    ) : AbstractFileBasedJWTSigner<RSAKey>(
    controllerManager,
    serverResponsibility,
    serverPaths,
    encryption,
    pluginDescriptor,
    jwkCache,
    keyRoot = KEY_ROOT,
    keySubdir = KEY_SUBDIR,
    keyFileName = PRIVATE_KEY_NAME,
    settingsJsp = SETTINGS_JSP,
) {
    override fun getId(): String = OIDCConstants.BuiltInRSASigner.ID
    override fun getDisplayName(): String = OIDCConstants.BuiltInRSASigner.DISPLAY_NAME

    private val cachedSigningAlgorithm: Cached<JWSAlgorithm?> = Cached {
        JWSAlgorithm.parse(settingsStore.get().jwsAlgorithm)
    }

    init {
        settingsStore.registerUpdateHandler {
            cachedSigningAlgorithm.invalidate()
        }
    }

    override fun getSigningAlgorithm(): JWSAlgorithm = cachedSigningAlgorithm.get()

    override fun parseKey(json: String): RSAKey = RSAKey.parse(json)
    override fun makeJWSSigner(key: RSAKey): JWSSigner = RSASSASigner(key)

    override fun getKeySize(key: RSAKey?): String? {
        val size = key?.toRSAPublicKey()?.modulus?.bitLength() ?: return null

        if (size !in ALLOWED_RSA_KEY_BITS) {
            // Some key generators may produce keys of a slightly shorter length.
            // Find the closest allowed value.
            return ALLOWED_RSA_KEY_BITS.minOfOrNull { size - it }?.toString()
        }
        return size.toString()
    }

    override fun generateKey(): RSAKey {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(getConfiguredKeyBits())
        }.generateKeyPair()
        return RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyIDFromThumbprint()
            .build()
    }

    internal fun getConfiguredKeyBits(): Int = settingsStore.get().rsaKeyBits

    override fun getSigningAlgorithms(): List<String?> = listOf(getSigningAlgorithm().name)

    override fun getAdminSettings(): JWTSignerAdminSettings = this

    override fun fillSettingsModel(model: MutableMap<String, Any>) {
        super.fillSettingsModel(model)
        model["rsaKeyBits"] = getConfiguredKeyBits()
        model["allowedRsaKeyBits"] = ALLOWED_RSA_KEY_BITS
        model["jwsAlgorithm"] = getSigningAlgorithm().name
        model["allowedJwsAlgorithms"] = ALLOWED_JWS_ALGORITHMS
    }

    override fun validateSettings(params: Map<String, String>): Map<String, String> {
        val errors = mutableMapOf<String, String>()

        val rsaKeyBits = params[SETTINGS_RSA_KEY_BITS_ATTR]?.toIntOrNull()
        if (rsaKeyBits == null) {
            errors["rsaKeyBits"] = "Invalid or missing RSA key size"
        } else if (rsaKeyBits !in ALLOWED_RSA_KEY_BITS) {
            errors["rsaKeyBits"] = "Invalid RSA key size: $rsaKeyBits. Allowed values: ${ALLOWED_RSA_KEY_BITS.joinToString()}"
        }

        val jwsAlgorithm = params[SETTINGS_JWS_ALGORITHM_ATTR]
        if (jwsAlgorithm.isNullOrEmpty()) {
            errors["jwsAlgorithm"] = "Invalid or missing JWS algorithm"
        } else if (jwsAlgorithm !in ALLOWED_JWS_ALGORITHMS) {
            errors["jwsAlgorithm"] = "Invalid JWS algorithm: $jwsAlgorithm. Allowed values: ${ALLOWED_JWS_ALGORITHMS.joinToString()}"
        }

        return errors
    }

    override fun saveSettings(params: MutableMap<String, String>): Map<String, String> {
        // Validation should have already happened
        val rsaKeyBits = params[SETTINGS_RSA_KEY_BITS_ATTR]?.toIntOrNull()!!
        val jwsAlgorithm = params[SETTINGS_JWS_ALGORITHM_ATTR]!!

        val current = settingsStore.get()
        val bitsChanged = rsaKeyBits != current.rsaKeyBits
        val algorithmChanged = jwsAlgorithm != current.jwsAlgorithm

        if (!bitsChanged && !algorithmChanged) return emptyMap()

        val newSettings = BuiltInRSASettings(jwsAlgorithm = jwsAlgorithm, rsaKeyBits = rsaKeyBits)
        keyLock.write {
            settingsStore.save(newSettings)
            if (bitsChanged) {
                rotateKey()
            }
        }

        return emptyMap()
    }
}
