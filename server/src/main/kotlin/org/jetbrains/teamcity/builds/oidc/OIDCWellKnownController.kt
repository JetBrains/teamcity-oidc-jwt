package org.jetbrains.teamcity.builds.oidc

import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.controllers.AuthorizationInterceptor
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Clock
import java.time.Instant

@RestController
@RequestMapping(OIDCConstants.WellKnownController.CONTROLLER_ROOT)
class OIDCWellKnownController @JvmOverloads constructor(
    ai: AuthorizationInterceptor,
    private val registry: JWTSignerRegistry,
    private val settings: OIDCSettings,
    private val clock: Clock = Clock.systemUTC()
) {
    @Volatile private var cachedIssuer: String? = null
    @Volatile private var cachedIssuerTs: Instant? = null

    init {
        // We use the deprecated version because TC currently does not allow registering annotated method controllers
        // with the (Class, String) overload. Well, technically it does, but it won't work as expected unless the class
        // you pass is `org.springframework.web.method.HandlerMethod`, which is, erm, undesirable to say the least.
        @Suppress("DEPRECATION")
        ai.addPathNotRequiringAuth(
            OIDCConstants.WellKnownController.CONTROLLER_ROOT + OIDCConstants.WellKnownController.CONFIG_PATH)
        @Suppress("DEPRECATION")
        ai.addPathNotRequiringAuth(
            OIDCConstants.WellKnownController.CONTROLLER_ROOT + OIDCConstants.WellKnownController.JWKS_PATH)
    }

    private fun getEffectiveIssuer(): String {
        val now = Instant.now(clock)
        val cached = cachedIssuer
        val stale = cachedIssuerTs?.plusSeconds(
            OIDCConstants.WellKnownController.CACHE_SECONDS)?.isBefore(now)
            ?: true
        if (cached != null && !stale) {
            return cached
        }
        val result = settings.getEffectiveIssuer()
        cachedIssuer = result
        cachedIssuerTs = now
        return result
    }

    @RequestMapping(OIDCConstants.WellKnownController.JWKS_PATH,
        method = [RequestMethod.GET], produces = ["application/json", "application/jwk-set+json"])
    fun jwks(@RequestParam(required = false) currentOnly: Boolean = false): String {
        if (currentOnly) {
            return """{"keys": [${registry.getActiveSigner().currentKeyPublicJWK}]}"""
        }
        return registry.getActiveSigner().getJWKS()
    }

    private fun openidConfiguration(effectiveIssuer: String): Map<String, Any> {
        return mapOf(
            "issuer" to effectiveIssuer,
            "jwks_uri" to "$effectiveIssuer/${OIDCConstants.WellKnownController.ROOT}${OIDCConstants.WellKnownController.JWKS_PATH}",
            "id_token_signing_alg_values_supported" to registry.getActiveSigner().getSigningAlgorithms(),
            "response_types_supported" to arrayOf("id_token"),
            "subject_types_supported" to arrayOf("public"),
            "authorization_endpoint" to "$effectiveIssuer/blackhole",
            "claims_supported" to JWTClaimsGenerator.getSupportedClaims()
        )
    }

    @RequestMapping(OIDCConstants.WellKnownController.CONFIG_PATH,
        method = [RequestMethod.GET], produces = ["application/json"])
    fun publicOpenidConfiguration(): Map<String, Any> {
        return openidConfiguration(getEffectiveIssuer())
    }

    @RequestMapping(OIDCConstants.WellKnownController.CONFIG_DOWNLOAD_PATH,
        method = [RequestMethod.GET], produces = ["application/json"])
    fun downloadOpenidConfiguration(): Map<String, Any> {
        return openidConfiguration(settings.getEffectiveIssuer())
    }
}
