package org.jetbrains.teamcity.builds.oidc.signer.builtin

import com.intellij.openapi.diagnostic.Logger
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.JWK
import jetbrains.buildServer.configuration.ChangeListener
import jetbrains.buildServer.configuration.FileWatcher
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.serverSide.IOGuard
import jetbrains.buildServer.serverSide.MultiNodeTasks
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.ServerResponsibility
import jetbrains.buildServer.serverSide.TeamCityNodes
import jetbrains.buildServer.serverSide.crypt.Encryption
import jetbrains.buildServer.util.Dates
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.AbstractSigner.KEY_ROTATION_TASK_FINISH_THRESHOLD_MS
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerAdminSettings
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import org.springframework.beans.factory.DisposableBean
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.UUID
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
    private val teamCityNodes: TeamCityNodes,
    private val serverResponsibility: ServerResponsibility,
    serverPaths: ServerPaths,
    private val encryption: Encryption,
    private val pluginDescriptor: PluginDescriptor,
    private val multiNodeTasks: MultiNodeTasks,
    private val jwkCache: JWKCache,
    keyRoot: String,
    keySubdir: String,
    keyFileName: String,
    private val settingsJsp: String,
    private val rotationTaskType: String,
) : JWTSigner, JWTSignerAdminSettings, ChangeListener, DisposableBean {

    protected val keyDir: Path = serverPaths.pluginDataDirectory.toPath().resolve(keyRoot).resolve(keySubdir)
    protected val keyFile: Path = keyDir.resolve(keyFileName)

    protected val keyLock = ReentrantReadWriteLock(true)
    @Volatile internal var cachedKey: K? = null

    protected val fileWatcher: FileWatcher

    private val rotationController = BuiltInRotationController(controllerManager, this)

    init {
        fileWatcher = FileWatcher(keyFile.toFile())
        fileWatcher.registerListener(this)
        fileWatcher.start()

        multiNodeTasks.subscribeOnSingletonTask(rotationTaskType, RotationTaskConsumer())
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
                            throw JWTSignerException(
                                "Cannot generate signing key on the current node (${teamCityNodes.currentNode.id})"
                            )
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

    fun requestKeyRotation(): String {
        val currentKey = keyLock.write {
            // Reset the cache to get a fresh key ID
            cachedKey = null
            getKey(generateIfMissing = false)
        }

        val currentKeyID = currentKey?.keyID ?: throw JWTSignerException("Cannot get a key to rotate. Please make sure the key has been generated.")
        if (isKeyRotationInProgress(currentKeyID)) {
            throw JWTSignerException("Key rotation $currentKeyID is already in progress.")
        }

        // Identity needs to be randomized because tasks are marked as finished
        // regardless of their outcome (success/failure).
        val taskID = "${currentKeyID}@${UUID.randomUUID()}"
        multiNodeTasks.submit(MultiNodeTasks.TaskData(rotationTaskType, taskID))
        return taskID
    }

    fun isKeyRotationInProgress(currentKey: String): Boolean {
        val taskType = listOf(rotationTaskType)
        val processingTasks = (multiNodeTasks.findPendingTasks(taskType)
                + multiNodeTasks.findInProgressTasks(taskType))
        // Also, fetch recently finished succeeded tasks to cover the gap
        // between rotation and current node refreshing cache.
        //
        // Emptiness check is a workaround: when `t?.finished()` is called, `getResult` on that task throws an NPE
        val finishedSucceededTasks = multiNodeTasks.findFinishedTasks(taskType, KEY_ROTATION_TASK_FINISH_THRESHOLD_MS)
            .filter { it.result?.isEmpty() ?: true }
        val inProgressTasks = processingTasks + finishedSucceededTasks
        val identityPrefix = "$currentKey@"
        return inProgressTasks.any { it.identity.startsWith(identityPrefix) }
    }

    fun getLatestKeyRotationError(currentKey: String): String? {
        val taskType = listOf(rotationTaskType)

        // Unfortunately, there's no way to fetch all finished tasks without a date cutoff,
        // so we use a month-long threshold here. The default TTL of finished tasks is 8 hours, btw.
        val finishedTasks = multiNodeTasks.findFinishedTasks(taskType, Dates.ONE_WEEK * 4)
        if (finishedTasks.isEmpty()) return null

        // Get the latest failed finished task
        val identityPrefix = "$currentKey@"

        // Emptiness check is a workaround: when `t?.finished()` is called, `getResult` on that task throws an NPE
        val latestFailedTask = finishedTasks
            .filter { it.identity.startsWith(identityPrefix) && it.result?.isNotEmpty() ?: false }
            .maxByOrNull { it.lastActivityTime?.time ?: 0 } ?: return null

        // There is at least one failed task. However, let's also check if there are any tasks in progress.
        // If there are, ignore the error (it's in progress, perhaps it will not fail).
        val processingTasks = (multiNodeTasks.findPendingTasks(taskType)
                + multiNodeTasks.findInProgressTasks(taskType)).filter { it.identity.startsWith(identityPrefix) }
        if (processingTasks.isNotEmpty()) return null

        // If there are no processing tasks, the latest failed task is the one we're interested in.
        return latestFailedTask.result
    }

    fun rotationTaskStatus(taskID: String): String? {
        val task = multiNodeTasks.findTask(rotationTaskType, taskID) ?: return null

        return when {
            task.isDoneSuccessfully && task.result?.isNotEmpty() ?: false -> "Failed: ${task.result}"
            task.isDoneSuccessfully -> "Success"
            task.isDone -> "Cancelled"
            task.executorNodeId != null -> "In progress on ${task.executorNodeId}"
            else -> "Pending"
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
        var keyFingerprint = getKey(generateIfMissing = false)?.keyID
        if (keyFingerprint != null) {
            val rotating = isKeyRotationInProgress(keyFingerprint)
            if (rotating) {
                keyFingerprint += " (rotation in progress)"
            }
            val lastError = getLatestKeyRotationError(keyFingerprint)
            if (lastError != null) {
                model["keyRotationLastError"] = lastError
            }
        }
        model["keyFingerprint"] = keyFingerprint ?: "<will be generated on first use>"
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

        multiNodeTasks.unsubscribe(rotationTaskType)
    }

    private inner class RotationTaskConsumer: MultiNodeTasks.TaskConsumer() {
        private val log: Logger = Logger.getInstance(Loggers.SERVER_CATEGORY + "." + this::class.java.name + "#" + rotationTaskType)

        override fun beforeAccept(task: MultiNodeTasks.PerformingTask): Boolean {
            return serverResponsibility.canManageBuilds()
        }

        /**
         * Rotate the current signing key if its id matches the provided expected key id.
         *
         * Expected key ID check is there to prevent rotation conflicts where
         * - A rotation task is scheduled twice for the same key
         * - One of the nodes has successfully performed the first scheduled task
         * - Any node has already generated a new key after the rotation
         * - After that, a second node processes the second rotation task, rotating the newly generated key
         *
         * There's still a race condition between rotating nodes that can result in two copies of the rotated key.
         *
         * @param expectedKeyID the key id that the task is expected to rotate.
         */
        private fun rotateKey(expectedKeyID: String?) = IOGuard.allowDiskWrite<Exception> {
            // Get the current key from the file system if exists, do not generate a new one
            val currentKey = keyLock.write {
                // Reset the cache to get a fresh key ID
                cachedKey = null
                getKey(generateIfMissing = false)
            } ?: return@allowDiskWrite  // If there's nothing to rotate, exit early

            val keySize = getKeySize(currentKey) ?: "unknown"
            if (expectedKeyID != null && currentKey.keyID != expectedKeyID) {
                throw JWTSignerException("Expected rotated key ID $expectedKeyID, got ${currentKey.keyID}")
            }

            fileWatcher.runActionWithDisabledObserver {
                keyLock.write {
                    // Save the current key.
                    val rotatedName =
                        "private.${keySize}.${currentKey.keyID}.rotated-on-${Instant.now().epochSecond}"
                    saveKey(currentKey, keyDir.resolve(rotatedName))
                    Files.deleteIfExists(keyFile)
                    cachedKey = null
                }
            }
        }

        override fun accept(t: MultiNodeTasks.PerformingTask?) {
            try {
                rotateKey(t?.identity?.substringBefore('@'))
                // Empty result is a workaround: when `t?.finished()` is called, `getResult` on that task throws an NPE
                t?.finished(Dates.now(), "")
            } catch (e: Exception) {
                log.warnAndDebugDetails("Failed to rotate the key", e)
                // Task must be finished even if rotation fails. Otherwise, it will be stuck in the `in progress` state
                // until the assigned node gets offline.
                t?.finished(Dates.now(), "Failed to rotate the key due to ${e.javaClass.name}: ${e.message ?: "$e (no message)"}")
            }
        }
    }
}
