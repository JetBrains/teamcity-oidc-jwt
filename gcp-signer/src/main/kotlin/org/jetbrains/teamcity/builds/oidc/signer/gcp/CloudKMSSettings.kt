package org.jetbrains.teamcity.builds.oidc.signer.gcp

import com.intellij.openapi.diagnostic.Logger
import jetbrains.buildServer.configuration.ChangeListener
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.SettingsPersister
import jetbrains.buildServer.serverSide.crypt.Encryption
import jetbrains.buildServer.serverSide.impl.FileWatcherFactory
import jetbrains.buildServer.util.FileUtil
import org.jdom.Document
import org.jdom.Element
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.GCPCredentials
import org.springframework.beans.factory.DisposableBean
import java.io.File
import java.util.concurrent.atomic.AtomicReference

class CloudKMSSettings(
    serverPaths: ServerPaths,
    fileWatcherFactory: FileWatcherFactory,
    private val settingsPersister: SettingsPersister,
    private val encryption: Encryption,
) : ChangeListener, DisposableBean {
    private val LOG = Logger.getInstance(Loggers.SERVER_CATEGORY + "." + this.javaClass.name)

    private data class State(
        val credentialsType: String = CloudKMSConstants.CredentialsType.ENVIRONMENT,
        val kmsResourceName: String = "",
        val impersonationChain: String = "",
        val gcpEndpoint: String = "",
        val encryptedServiceAccountKey: String = "",
    )

    private val configFile = File(serverPaths.configDir, CloudKMSConstants.Settings.FILE_NAME)
    private val watcher = fileWatcherFactory.createFileWatcher(configFile)
    private val current = AtomicReference(State())
    private val updateHandlers = mutableListOf<() -> Unit>()

    init {
        watcher.registerListener(this)
        current.set(readFromDisk())
        watcher.start()
    }

    override fun changeOccured(requestor: String?) {
        current.set(readFromDisk())
        notifyUpdateHandlers()
    }

    fun registerUpdateHandler(handler: () -> Unit) {
        synchronized(updateHandlers) { updateHandlers.add(handler) }
    }

    fun getCredentials(): GCPCredentials {
        val state = current.get()
        val impersonationChain = state.impersonationChain.ifBlank { null }

        return when (state.credentialsType) {
            CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY -> {
                state.encryptedServiceAccountKey
                    .takeIf { it.isNotEmpty() }
                    ?.let { encryption.decrypt(it) }
                    ?.let { GCPCredentials.ServiceAccount(it, impersonationChain) }
            }
            else -> null
        } ?: GCPCredentials.Environment(impersonationChain)
    }

    fun getKeyResourceName(): String? = current.get().kmsResourceName.ifBlank { null }

    fun getGCPEndpoint(): String? = current.get().gcpEndpoint.ifBlank { null }

    fun update(
        credentialsType: String,
        kmsResourceName: String,
        serviceAccountKey: String,
        impersonationChain: String?,
        gcpEndpoint: String?,
    ) {
        LOG.info(
            "Updating Cloud KMS settings: credentials type '$credentialsType', " +
                "key '$kmsResourceName', len(service account key): ${serviceAccountKey.length}"
        )

        val existing = current.get()
        val newEncryptedKey = when {
            credentialsType != CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY -> ""
            serviceAccountKey.isBlank() -> existing.encryptedServiceAccountKey
            else -> encryption.encrypt(serviceAccountKey)
        }
        val next = State(
            credentialsType = credentialsType,
            kmsResourceName = kmsResourceName,
            impersonationChain = impersonationChain.orEmpty(),
            gcpEndpoint = gcpEndpoint.orEmpty(),
            encryptedServiceAccountKey = newEncryptedKey,
        )

        settingsPersister.scheduleSaveDocument(
            CloudKMSConstants.Settings.PERSIST_DESCRIPTION,
            watcher,
            toDocument(next),
        )
        current.set(next)
        // Fire handlers locally so caches owned by other components on this node are invalidated
        // immediately. The watcher will fire again later when the file write lands; handlers must
        // therefore be idempotent (they are: pure cache invalidations).
        notifyUpdateHandlers()
    }

    private fun notifyUpdateHandlers() {
        LOG.debug("Notifying Cloud KMS settings update handlers")
        val snapshot = synchronized(updateHandlers) { updateHandlers.toList() }
        snapshot.forEach {
            try {
                it()
            } catch (e: Exception) {
                LOG.error("Failed to notify Cloud KMS settings update handler", e)
            }
        }
    }

    private fun readFromDisk(): State {
        if (!configFile.isFile || !configFile.canRead()) return State()

        return try {
            val root = FileUtil.parseDocument(configFile)
            if (root.name != CloudKMSConstants.Settings.ROOT_ELEMENT) return State()

            val storedType = root.getAttributeValue(CloudKMSConstants.Settings.CREDENTIALS_TYPE_ATTR)
            val credentialsType = when (storedType) {
                CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY,
                CloudKMSConstants.CredentialsType.ENVIRONMENT -> storedType
                else -> CloudKMSConstants.CredentialsType.ENVIRONMENT
            }

            State(
                credentialsType = credentialsType,
                kmsResourceName = root.getChildTextTrim(CloudKMSConstants.Settings.KMS_RESOURCE_NAME_ELEMENT).orEmpty(),
                impersonationChain = root.getChildTextTrim(CloudKMSConstants.Settings.IMPERSONATION_CHAIN_ELEMENT).orEmpty(),
                gcpEndpoint = root.getChildTextTrim(CloudKMSConstants.Settings.GCP_ENDPOINT_ELEMENT).orEmpty(),
                encryptedServiceAccountKey = root.getChildTextTrim(CloudKMSConstants.Settings.SERVICE_ACCOUNT_KEY_ELEMENT).orEmpty(),
            )
        } catch (e: Exception) {
            LOG.warn("Failed to read Cloud KMS settings from $configFile, falling back to defaults", e)
            State()
        }
    }

    private fun toDocument(state: State): Document {
        val root = Element(CloudKMSConstants.Settings.ROOT_ELEMENT).apply {
            setAttribute(CloudKMSConstants.Settings.VERSION_ATTR, CloudKMSConstants.Settings.FILE_VERSION)
            setAttribute(CloudKMSConstants.Settings.CREDENTIALS_TYPE_ATTR, state.credentialsType)
            if (state.kmsResourceName.isNotEmpty()) {
                addContent(Element(CloudKMSConstants.Settings.KMS_RESOURCE_NAME_ELEMENT).setText(state.kmsResourceName))
            }
            if (state.impersonationChain.isNotEmpty()) {
                addContent(Element(CloudKMSConstants.Settings.IMPERSONATION_CHAIN_ELEMENT).setText(state.impersonationChain))
            }
            if (state.gcpEndpoint.isNotEmpty()) {
                addContent(Element(CloudKMSConstants.Settings.GCP_ENDPOINT_ELEMENT).setText(state.gcpEndpoint))
            }
            if (state.encryptedServiceAccountKey.isNotEmpty()) {
                addContent(Element(CloudKMSConstants.Settings.SERVICE_ACCOUNT_KEY_ELEMENT).setText(state.encryptedServiceAccountKey))
            }
        }
        return Document(root)
    }

    override fun destroy() {
        watcher.unregisterListener(this)
        watcher.stop()
        watcher.clear()
        synchronized(updateHandlers) { updateHandlers.clear() }
    }
}
