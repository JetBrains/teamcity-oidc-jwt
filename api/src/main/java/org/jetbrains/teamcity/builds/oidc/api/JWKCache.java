package org.jetbrains.teamcity.builds.oidc.api;

import org.jetbrains.annotations.NotNull;

import java.time.Instant;
import java.util.Map;

/**
 * Distributed cache for JWK public keys used by a single signer.
 *
 * <p>
 * When a signing key is rotated, the JWKS endpoint must continue to serve
 * the old public key until all tokens signed with it expire. This cache
 * tracks which public keys are still needed and their expiration times
 * across all nodes in the cluster.
 * </p>
 */
public interface JWKCache {
    /**
     * Records that a token was signed with the given key and expires at the given time.
     * The corresponding public JWK will be included in {@link #fetchCachedJWKs()} results
     * until all tokens signed with it have expired.
     *
     * @param kid      key ID (e.g., `kid` claim of the JWK)
     * @param jwkJson  public JWK JSON string
     * @param expiresAt expiration time of the token that was just signed
     */
    void trackKey(@NotNull String kid, @NotNull String jwkJson, @NotNull Instant expiresAt);

    /**
     * Returns all cached public JWKs that are still needed (i.e., at least one token
     * signed with them has not yet expired).
     *
     * @return map of key ID to public JWK JSON string
     */
    @NotNull Map<String, String> fetchCachedJWKs();

    /**
     * Clears all DB data and invalidates all nodes' in-memory caches.
     * For emergency use when a private key has been compromised and its
     * corresponding public key must be removed from JWK set immediately.
     */
    void purge();
}
