package org.jetbrains.teamcity.builds.oidc

import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.PLUGIN_ID
import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.controllers.AuthorizationInterceptor
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

class OIDCWellKnownControllerTest : BaseTestCase() {

    @Test
    fun registersCorrectUrlsWithAuthorizationInterceptor() {
        val ai = mockk<AuthorizationInterceptor>(relaxed = true)

        OIDCWellKnownController(ai, mockk(relaxed = true), mockk(relaxed = true))

        verify { ai.addPathNotRequiringAuth(
            eq("/$PLUGIN_ID/.well-known/openid-configuration")
        ) }
        verify { ai.addPathNotRequiringAuth(
            eq("/$PLUGIN_ID/.well-known/jwks")
        ) }
    }

    @Test
    fun jwks_returnsExpectedJWKS() {
        val expectedJwks = """{"keys":[{"kty":"RSA","kid":"test-key"}]}"""
        val signer = mockk<JWTSigner> {
            every { getJWKS() } returns expectedJwks
        }
        val registry = mockk<JWTSignerRegistry> {
            every { getActiveSigner() } returns signer
        }

        val target = OIDCWellKnownController(mockk(relaxed = true), registry, mockk(relaxed = true))

        Assertions.assertThat(target.jwks()).isEqualTo(expectedJwks)
    }

    @Test
    fun publicOpenidConfiguration_returnsExpectedValues() {
        val signer = mockk<JWTSigner> {
            every { getSigningAlgorithms() } returns listOf("RS256", "RS512")
        }
        val registry = mockk<JWTSignerRegistry> {
            every { getActiveSigner() } returns signer
        }
        val settings = mockk<OIDCSettings> {
            every { getEffectiveIssuer() } returns "https://example.com"
        }

        val target = OIDCWellKnownController(mockk(relaxed = true), registry, settings)
        val config = target.publicOpenidConfiguration()

        Assertions.assertThat(config["issuer"]).isEqualTo("https://example.com")
        Assertions.assertThat(config["jwks_uri"]).isEqualTo("https://example.com/.well-known/jwks")
        Assertions.assertThat(config["authorization_endpoint"]).isEqualTo("https://example.com/blackhole")
        Assertions.assertThat(config["response_types_supported"] as Array<*>).isEqualTo(arrayOf("id_token"))
        Assertions.assertThat(config["subject_types_supported"] as Array<*>).isEqualTo(arrayOf("public"))
        Assertions.assertThat(config["id_token_signing_alg_values_supported"] as List<*>).isEqualTo(listOf("RS256", "RS512"))
        Assertions.assertThat(config["claims_supported"]).isEqualTo(JWTClaimsGenerator.getSupportedClaims())
    }

    @Test
    fun publicOpenidConfiguration_cachesIssuerAndInvalidatesAfterTTL() {
        val baseInstant = Instant.parse("2026-01-01T00:00:00Z")
        var currentInstant = baseInstant
        val clock = mockk<Clock> {
            every { instant() } answers { currentInstant }
            every { zone } returns ZoneOffset.UTC
        }

        val signer = mockk<JWTSigner> {
            every { getSigningAlgorithms() } returns listOf("RS256", "RS512")
        }
        val registry = mockk<JWTSignerRegistry> {
            every { getActiveSigner() } returns signer
        }
        val settings = mockk<OIDCSettings> {
            every { getEffectiveIssuer() } returnsMany listOf("https://first.example.com", "https://second.example.com")
        }

        val target = OIDCWellKnownController(mockk(relaxed = true), registry, settings, clock)

        // First call: cache miss, hits settings
        val config1 = target.publicOpenidConfiguration()
        Assertions.assertThat(config1["issuer"]).isEqualTo("https://first.example.com")
        verify(exactly = 1) { settings.getEffectiveIssuer() }

        // Second call within TTL: cache hit, settings not called again
        currentInstant = baseInstant + Duration.ofSeconds(OIDCConstants.WellKnownController.CACHE_SECONDS - 1)
        val config2 = target.publicOpenidConfiguration()
        Assertions.assertThat(config2["issuer"]).isEqualTo("https://first.example.com")
        verify(exactly = 1) { settings.getEffectiveIssuer() }

        // Third call after TTL: cache invalidated, hits settings again
        currentInstant = baseInstant + Duration.ofSeconds(OIDCConstants.WellKnownController.CACHE_SECONDS + 1)
        val config3 = target.publicOpenidConfiguration()
        Assertions.assertThat(config3["issuer"]).isEqualTo("https://second.example.com")
        verify(exactly = 2) { settings.getEffectiveIssuer() }
    }

    @Test
    fun downloadOpenidConfiguration_returnsExpectedValues() {
        val signer = mockk<JWTSigner> {
            every { getSigningAlgorithms() } returns listOf("RS256", "RS512")
        }
        val registry = mockk<JWTSignerRegistry> {
            every { getActiveSigner() } returns signer
        }
        val settings = mockk<OIDCSettings> {
            every { getEffectiveIssuer() } returns "https://example.com"
        }

        val target = OIDCWellKnownController(mockk(relaxed = true), registry, settings)
        val config = target.downloadOpenidConfiguration()

        Assertions.assertThat(config["issuer"]).isEqualTo("https://example.com")
        Assertions.assertThat(config["jwks_uri"]).isEqualTo("https://example.com/.well-known/jwks")
        Assertions.assertThat(config["authorization_endpoint"]).isEqualTo("https://example.com/blackhole")
        Assertions.assertThat(config["response_types_supported"] as Array<*>).isEqualTo(arrayOf("id_token"))
        Assertions.assertThat(config["subject_types_supported"] as Array<*>).isEqualTo(arrayOf("public"))
        Assertions.assertThat(config["id_token_signing_alg_values_supported"] as List<*>).isEqualTo(listOf("RS256", "RS512"))
        Assertions.assertThat(config["claims_supported"]).isEqualTo(JWTClaimsGenerator.getSupportedClaims())
    }

    @Test
    fun downloadOpenidConfiguration_doesNotCacheIssuer() {
        val baseInstant = Instant.parse("2026-01-01T00:00:00Z")
        var currentInstant = baseInstant
        val clock = mockk<Clock> {
            every { instant() } answers { currentInstant }
            every { zone } returns ZoneOffset.UTC
        }

        val signer = mockk<JWTSigner> {
            every { getSigningAlgorithms() } returns listOf("RS256")
        }
        val registry = mockk<JWTSignerRegistry> {
            every { getActiveSigner() } returns signer
        }
        val settings = mockk<OIDCSettings> {
            every { getEffectiveIssuer() } returnsMany listOf("https://first.example.com", "https://second.example.com")
        }

        val target = OIDCWellKnownController(mockk(relaxed = true), registry, settings, clock)

        val config1 = target.downloadOpenidConfiguration()
        Assertions.assertThat(config1["issuer"]).isEqualTo("https://first.example.com")
        verify(exactly = 1) { settings.getEffectiveIssuer() }

        currentInstant = baseInstant + Duration.ofSeconds(OIDCConstants.WellKnownController.CACHE_SECONDS - 1)
        val config2 = target.downloadOpenidConfiguration()
        Assertions.assertThat(config2["issuer"]).isEqualTo("https://second.example.com")
        verify(exactly = 2) { settings.getEffectiveIssuer() }
    }
}
