package org.jetbrains.teamcity.builds.oidc.signer.builtin

import org.jetbrains.teamcity.builds.oidc.api.JWTSignerAdminSettings
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.ALLOWED_JWS_ALGORITHMS
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.KEY_ROOT
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.KEY_SUBDIR
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.PRIVATE_KEY_NAME
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.SETTINGS_JSP
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.SETTINGS_JWS_ALGORITHM_ATTR
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import jetbrains.buildServer.serverSide.MultiNodeTasks
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.ServerResponsibility
import jetbrains.buildServer.serverSide.TeamCityNodes
import jetbrains.buildServer.serverSide.crypt.Encryption
import jetbrains.buildServer.util.Cached
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import kotlin.concurrent.write

/**
 * File-based ECDSA JWT signer. The signing algorithm (ES256 / ES384 / ES512) is configurable;
 * because each algorithm is bound to a different curve, changing it always rotates the key on save.
 */
class BuiltInECDSASigner(
    controllerManager: WebControllerManager,
    teamCityNodes: TeamCityNodes,
    serverResponsibility: ServerResponsibility,
    serverPaths: ServerPaths,
    encryption: Encryption,
    pluginDescriptor: PluginDescriptor,
    multiNodeTasks: MultiNodeTasks,
    private val settingsStore: BuiltInECDSASettingsStore,
    jwkCache: JWKCache,
) : AbstractFileBasedJWTSigner<ECKey>(
    controllerManager,
    teamCityNodes,
    serverResponsibility,
    serverPaths,
    encryption,
    pluginDescriptor,
    multiNodeTasks,
    jwkCache,
    keyRoot = KEY_ROOT,
    keySubdir = KEY_SUBDIR,
    keyFileName = PRIVATE_KEY_NAME,
    settingsJsp = SETTINGS_JSP,
    rotationTaskType = OIDCConstants.BuiltInECDSASigner.ROTATE_TASK_TYPE,
) {
    override fun getId(): String = OIDCConstants.BuiltInECDSASigner.ID
    override fun getDisplayName(): String = OIDCConstants.BuiltInECDSASigner.DISPLAY_NAME

    private val cachedSigningAlgorithm: Cached<JWSAlgorithm?> = Cached {
        JWSAlgorithm.parse(settingsStore.get().jwsAlgorithm)
    }

    init {
        settingsStore.registerUpdateHandler {
            cachedSigningAlgorithm.invalidate()
        }
    }

    override fun getSigningAlgorithm(): JWSAlgorithm = cachedSigningAlgorithm.get()

    override fun parseKey(json: String): ECKey = ECKey.parse(json)
    override fun makeJWSSigner(key: ECKey): JWSSigner = ECDSASigner(key)
    override fun getKeySize(key: ECKey?): String? = key?.curve?.name

    override fun generateKey(): ECKey =
        ECKeyGenerator(curveFor(getSigningAlgorithm()))
            .keyIDFromThumbprint(true)
            .generate()

    private fun curveFor(alg: JWSAlgorithm): Curve = when (alg) {
        JWSAlgorithm.ES256 -> Curve.P_256
        JWSAlgorithm.ES384 -> Curve.P_384
        JWSAlgorithm.ES512 -> Curve.P_521
        else -> error("Unsupported ECDSA algorithm: $alg")
    }

    override fun getSigningAlgorithms(): List<String?> = listOf(getSigningAlgorithm().name)

    override fun getAdminSettings(): JWTSignerAdminSettings = this

    override fun fillSettingsModel(model: MutableMap<String, Any>) {
        super.fillSettingsModel(model)
        model["jwsAlgorithm"] = getSigningAlgorithm().name
        model["allowedJwsAlgorithms"] = ALLOWED_JWS_ALGORITHMS
    }

    override fun validateSettings(params: Map<String, String>): Map<String, String> {
        val errors = mutableMapOf<String, String>()

        val jwsAlgorithm = params[SETTINGS_JWS_ALGORITHM_ATTR]
        if (jwsAlgorithm.isNullOrEmpty()) {
            errors["jwsAlgorithm"] = "Invalid or missing JWS algorithm"
        } else if (jwsAlgorithm !in ALLOWED_JWS_ALGORITHMS) {
            errors["jwsAlgorithm"] = "Invalid JWS algorithm: $jwsAlgorithm. Allowed values: ${ALLOWED_JWS_ALGORITHMS.joinToString()}"
        }

        return errors
    }

    override fun saveSettings(params: MutableMap<String, String>): Map<String, String> {
        val jwsAlgorithm = params[SETTINGS_JWS_ALGORITHM_ATTR]!!

        if (jwsAlgorithm == settingsStore.get().jwsAlgorithm) return emptyMap()

        settingsStore.save(BuiltInECDSASettings(jwsAlgorithm = jwsAlgorithm))
        requestKeyRotation()

        return emptyMap()
    }
}
