package org.jetbrains.teamcity.builds.oidc.signer.gcp.client

import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSConstants
import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSSettings
import org.jetbrains.teamcity.builds.oidc.signer.gcp.JWTKeyVersion
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSServiceAccountKeyNotProvidedException
import org.springframework.beans.factory.DisposableBean
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * [CloudKMSDefaultClient] holds a [CloudKMSClient] instance with the most recent settings.
 * It also has a cache for the most recent key version requested.
 *
 * Whenever settings are updated, the key cache is cleared and the client is recreated.
 * Key cache is also cleared whenever a version is requested with a new resource name (or when forced).
 */
class CloudKMSDefaultClient @JvmOverloads constructor(
    private val settings: CloudKMSSettings,
    private val cloudKMSClientFactory: CloudKMSClientFactory = CloudKMSClientFactory.Default(),
): DisposableBean {
    @Volatile private var closed = false
    private val clientLock = Any()
    private var cachedClient: CloudKMSClient? = null

    private val keyCacheLock = ReentrantReadWriteLock()
    @Volatile private var keyCacheResourceName: String? = null
    @Volatile private var keyCacheVersion: JWTKeyVersion? = null

    init {
        settings.registerUpdateHandler {
            // Clear the key cache on settings update (so that `cachedKeyVersion` will not return potentially stale data)
            keyCacheLock.write {
                keyCacheResourceName = null
                keyCacheVersion = null
            }

            // Create a new client on settings update
            val oldClient = synchronized(clientLock) {
                val oldCached = cachedClient
                cachedClient = null
                oldCached
            }

            // Close the old client if it exists
            oldClient?.close()
        }
    }

    /**
     * Returns the current [CloudKMSClient] instance. Creates a new one if it hasn't been created yet.
     */
    fun currentClient(): CloudKMSClient {
        if (closed) throw IllegalStateException("Client is closed")
        return synchronized(clientLock) {
            cachedClient ?: cloudKMSClientFactory.create(
                settings.getCredentials(),
                gcpEndpoint = settings.getGCPEndpoint(),
                timeoutSeconds = CloudKMSConstants.Client.DEFAULT_TIMEOUT_SECONDS,
                maxAttempts = CloudKMSConstants.Client.DEFAULT_MAX_ATTEMPTS,
            ).also {
                cachedClient = it
            }
        }
    }

    /**
     * Returns the key version resolved from the resource name that's currently configured.
     * When `force` is false, a cached version will be returned (if available).
     *
     * Since this method uses [getKeyVersion], it will overwrite the cached version if `force` is true
     * or if the currently configured key resource name is different from the cached one.
     *
     * @param force Whether to force a refresh of the key version.
     * @return The resolved key version.
     */
    fun getLatestKeyVersion(force: Boolean): JWTKeyVersion {
        val keyResourceName = settings.getKeyResourceName()
            ?: throw CloudKMSServiceAccountKeyNotProvidedException()
        return getKeyVersion(keyResourceName, force)
    }

    /**
     * Returns the key version resolved from the given resource name. When `force` is false,
     * a cached version will be returned (if available).
     *
     * If `force` is true or the resource name is different from the cached one, a new key version
     * will be resolved and cached.
     *
     * @param resourceName The resource name of the key version to resolve.
     * @param force Whether to force a refresh of the key version.
     * @return The resolved key version.
     */
    fun getKeyVersion(resourceName: String, force: Boolean): JWTKeyVersion {
        if (!force) {
            keyCacheLock.read {
                val cachedResourceName = keyCacheResourceName
                val cachedVersion = keyCacheVersion
                if (cachedResourceName == resourceName) {
                    return cachedVersion!!
                }
            }
        }

        val resolved = resolve(resourceName)
        keyCacheLock.write {
            keyCacheResourceName = resourceName
            keyCacheVersion = resolved
        }
        return resolved
    }

    /**
     * Resolves the given resource name (CryptoKey or CryptoKeyVersion) to a [JWTKeyVersion] with the current client.
     *
     * @param resourceName The resource name to resolve. Should be a resource name of a CryptoKey or CryptoKeyVersion.
     * @return A [JWTKeyVersion] object representing the resolved key version.
     */
    fun resolve(resourceName: String): JWTKeyVersion = currentClient().resolveKeyVersion(resourceName)

    /**
     * Tries to sign the given byte array using the provided [JWTKeyVersion] with the current client.
     *
     * @param keyVersion The [JWTKeyVersion] to use for signing.
     * @param payload The byte array to sign.
     * @return The signature as a Base64URL-encoded string.
     */
    fun sign(keyVersion: JWTKeyVersion, payload: ByteArray): String = currentClient().sign(keyVersion, payload)

    override fun destroy() {
        closed = true
        synchronized(clientLock) {
            cachedClient?.close()
            cachedClient = null
        }
    }
}
