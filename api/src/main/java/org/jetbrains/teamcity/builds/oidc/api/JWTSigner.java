package org.jetbrains.teamcity.builds.oidc.api;

import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.ServerExtension;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;
import java.util.List;

/**
 * An interface for a generic JWT signer.
 */
public interface JWTSigner extends ServerExtension {
    /**
     * Returns a unique identifier for this signer implementation.
     *
     * @return unique signer ID
     */
    @NotNull String getId();

    /**
     * Returns a human-readable name for this signer, suitable for display in the admin UI.
     *
     * @return display name
     */
    @NotNull String getDisplayName();

    /**
     * Signs the JSON-encoded claims as a JWT. The signer is expected not to alter the provided claims.
     *
     * @param build      build for which the JWT is being generated
     * @param claimsJSON JSON-encoded claims bytes to sign
     * @param expiresAt  expiration Instant (e.g., for JWKS cache)
     * @return a valid signed JWT
     * @throws JWTSignerException when JWT signing fails for some reason.
     */
    @NotNull String makeJWT(SBuild build, @NotNull byte[] claimsJSON, @NotNull Instant expiresAt) throws JWTSignerException;

    /**
     * Returns a valid public JWK string for the current signing key.
     * This method is used by the `/app/oidc-jwt/.well-known/jwks` endpoint when
     * downloading the JWKS for upload to an external host.
     *
     * @return JSON-encoded public JWK
     * @throws JWTSignerException when JWK generation fails for some reason.
     */
    @NotNull String getCurrentKeyPublicJWK() throws JWTSignerException;

    /**
     * Returns the JWKS JSON string to be returned by `/app/oidc-jwt/.well-known/jwks` endpoint.
     *
     * <p>
     * The implementation should consider that the endpoint is accessible without authentication
     * and the output of this method will not be cached by the caller. Please refrain from uncached
     * expensive computations or operations (e.g., network calls) when returning the value.
     * </p>
     *
     * @return JWKS JSON string
     * @throws JWTSignerException when JWKS generation fails for some reason.
     */
    @NotNull String getJWKS() throws JWTSignerException;

    /**
     * Returns a list of possible "alg" claim values as defined by RFC7518 section 3.1. The values are returned as the
     * `id_token_signing_alg_values_supported` value of the `/app/oidc-jwt/.well-known/openid-configuration` endpoint.
     *
     * <p>
     * The implementation should consider that the endpoint is accessible without authentication
     * and the output of this method will not be cached by the caller. Please refrain from uncached
     * expensive computations or operations (e.g., network calls) when returning the value.
     * </p>
     *
     * @return List of possible "alg" claim values
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">RFC7518 section 3.1</a>
     */
    @NotNull List<String> getSigningAlgorithms();

    /**
     * Returns the admin settings handler for this signer, or {@code null} if this signer
     * has no configurable settings UI.
     *
     * @return admin settings, or null
     */
    @Nullable default JWTSignerAdminSettings getAdminSettings() { return null; }
}
