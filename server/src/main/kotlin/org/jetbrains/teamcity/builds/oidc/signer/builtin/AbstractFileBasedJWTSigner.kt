package org.jetbrains.teamcity.builds.oidc.signer.builtin

import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerAdminSettings
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.JWK
import jetbrains.buildServer.configuration.ChangeListener
import jetbrains.buildServer.configuration.FileWatcher
import jetbrains.buildServer.serverSide.IOGuard
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.ServerResponsibility
import jetbrains.buildServer.serverSide.crypt.Encryption
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import org.springframework.beans.factory.DisposableBean
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * Base class for built-in file-backed JWT signers. Persists a JWK on disk encrypted with TC encryption,
 * caches it in memory, and invalidates the cache when the file changes on disk.
 *
 * Subclasses provide the concrete JWK type, the JWS algorithm, key generation, and the JWS signer.
 */
abstract class AbstractFileBasedJWTSigner<K : JWK>(
    controllerManager: WebControllerManager,
    private val serverResponsibility: ServerResponsibility,
    serverPaths: ServerPaths,
    private val encryption: Encryption,
    private val pluginDescriptor: PluginDescriptor,
    private val jwkCache: JWKCache,
    keyRoot: String,
    keySubdir: String,
    keyFileName: String,
    private val settingsJsp: String,
) : JWTSigner, JWTSignerAdminSettings, ChangeListener, DisposableBean {

    protected val keyDir: Path = serverPaths.pluginDataDirectory.toPath().resolve(keyRoot).resolve(keySubdir)
    protected val keyFile: Path = keyDir.resolve(keyFileName)

    protected val keyLock = ReentrantReadWriteLock(true)
    @Volatile internal var cachedKey: K? = null

    protected val fileWatcher: FileWatcher

    private val rotationController = BuiltInRotationController(controllerManager, serverResponsibility, this)

    init {
        fileWatcher = FileWatcher(keyFile.toFile())
        fileWatcher.registerListener(this)
        fileWatcher.start()
    }

    /** JWS algorithm to use and advertise. */
    protected abstract fun getSigningAlgorithm(): JWSAlgorithm

    /** Parse a JWK JSON string into the concrete key type. */
    protected abstract fun parseKey(json: String): K

    /** Generate a brand new key pair. Called when no key file exists yet. */
    protected abstract fun generateKey(): K

    /** Build the Nimbus JWS signer for this key. */
    protected abstract fun makeJWSSigner(key: K): JWSSigner

    /** Key size to use in the key file name. */
    protected abstract fun getKeySize(key: K?): String?

    override fun changeOccured(requestor: String?) {
        cachedKey = null
    }

    private fun loadKey(): K? {
        if (!Files.exists(keyFile)) return null
        val encrypted = Files.readString(keyFile)
        val json = encryption.decrypt(encrypted)
        return parseKey(json)
    }

    protected fun saveKey(key: K, path: Path) = IOGuard.allowDiskWrite<Exception> {
        Files.createDirectories(path.parent)
        val encrypted = encryption.encrypt(key.toJSONString())
        Files.writeString(path, encrypted)
    }

    protected fun getKey(generateIfMissing: Boolean): K? {
        keyLock.read {
            cachedKey?.let { return it }
        }

        keyLock.write {
            cachedKey?.let { return it }

            try {
                val key = loadKey()
                    ?: if (generateIfMissing) {
                        if (!serverResponsibility.canManageBuilds()) {
                            throw JWTSignerException("Cannot generate signing key: server is not configured to manage builds")
                        }
                        generateKey().also { saveKey(it, keyFile) }
                    } else null
                cachedKey = key
                return key
            } catch (e: Exception) {
                throw JWTSignerException("Failed to load or generate signing key", e)
            }
        }
    }

    internal fun rotateKey() {
        // Get the current key if exists, do not generate a new one
        val currentKey = getKey(generateIfMissing = false)
        val keySize = getKeySize(currentKey) ?: "unknown"
        fileWatcher.runActionWithDisabledObserver {
            keyLock.write {
                // Save the current key if it exists
                if (currentKey != null) {
                    val rotatedName =
                        "private.${keySize}.${currentKey.keyID}.rotated-on-${Instant.now().epochSecond}"
                    saveKey(currentKey, keyDir.resolve(rotatedName))
                }
                Files.deleteIfExists(keyFile)
                cachedKey = null
            }
        }
    }

    override fun makeJWT(build: SBuild, claimsJSON: ByteArray, expiresAt: Instant): String {
        try {
            val key = getKey(generateIfMissing = true) ?: throw JWTSignerException("Cannot load or generate key")
            val header = JWSHeader.Builder(getSigningAlgorithm())
                .keyID(key.keyID)
                .build()
            val jwsObject = JWSObject(header, Payload(claimsJSON))
            jwsObject.sign(makeJWSSigner(key))
            jwkCache.trackKey(key.keyID, key.toPublicJWK().toJSONString(), expiresAt)
            return jwsObject.serialize()
        } catch (e: JWTSignerException) {
            throw e
        } catch (e: Exception) {
            throw JWTSignerException(e)
        }
    }

    override fun getJWKS(): String {
        try {
            val current = getCurrentKeyPublicJWK()
            val keySet = if (!current.isBlank()) {
                mutableSetOf(current)
            } else {
                mutableSetOf()
            }
            keySet.addAll(jwkCache.fetchCachedJWKs().values)
            return """{"keys":[${keySet.joinToString(",")}]}"""
        } catch (e: JWTSignerException) {
            throw e
        } catch (e: Exception) {
            throw JWTSignerException("Failed to produce JWKS", e)
        }
    }

    override fun getCurrentKeyPublicJWK(): String {
        try {
            return getKey(generateIfMissing = false)?.toPublicJWK()?.toJSONString() ?: ""
        } catch (e: JWTSignerException) {
            throw e
        } catch (e: Exception) {
            throw JWTSignerException("Failed to produce the public JWK for the current key", e)
        }
    }

    override fun getSettingsPagePath(): String =
        pluginDescriptor.getPluginResourcesPath(settingsJsp)

    override fun fillSettingsModel(model: MutableMap<String, Any>) {
        model["keyFilePath"] = keyFile.toString()
        model["keyFingerprint"] = getKey(generateIfMissing = false)?.keyID ?: "<will be generated on first use>"
        model["rotationEndpoint"] = rotationController.rotationURL()
        model["rotationRequiredPermission"] = rotationController.requiredPermission()
    }

    override fun destroy() {
        // The order is important here: unregister the listener first,
        // so that listener type caches of EventDispatcherHandlers
        // will not hold this class as a hashmap key.
        fileWatcher.unregisterListener(this)
        fileWatcher.stop()
        fileWatcher.clear()
    }
}
