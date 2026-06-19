package org.jetbrains.teamcity.builds.oidc.util

import com.intellij.openapi.diagnostic.Logger
import jetbrains.buildServer.configuration.ChangeListener
import jetbrains.buildServer.configuration.FileWatcher
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.SettingsPersister
import jetbrains.buildServer.serverSide.impl.FileWatcherFactory
import jetbrains.buildServer.util.FileUtil
import org.jdom.Document
import org.jdom.Element
import org.springframework.beans.factory.DisposableBean
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/**
 * Generic typed XML settings store backed by a single file under `<TeamCity data dir>/config`.
 * Writes go through `SettingsPersister` so secondary nodes pick up changes via the shared file
 * watcher; reads are served from an in-memory `AtomicReference<T>` snapshot.
 */
abstract class XmlSettingsStore<T : Any>(
    private val fileName: String,
    private val description: String,
    private val default: T,
    serverPaths: ServerPaths,
    fileWatcherFactory: FileWatcherFactory,
    private val settingsPersister: SettingsPersister,
) : ChangeListener, DisposableBean {

    private val log: Logger = Logger.getInstance(Loggers.SERVER_CATEGORY + "." + this::class.java.name + "#" + fileName)

    protected val configFile: File = File(serverPaths.configDir, fileName)
    private val watcher: FileWatcher = fileWatcherFactory.createFileWatcher(configFile)
    private val current: AtomicReference<T> = AtomicReference(default)
    private val updateHandlers: MutableList<() -> Unit> = mutableListOf()

    init {
        watcher.registerListener(this)
        current.set(readFromDisk())
        watcher.start()
    }

    fun get(): T = current.get()

    fun save(value: T, waitForDisk: Boolean = false) {
        val task = settingsPersister.scheduleSaveDocument(description, watcher, toDocument(value))
        current.set(value)
        // Fire handlers locally so caches owned by other components on this node are invalidated
        // immediately. The watcher will fire again later when the file write lands; handlers
        // must therefore be idempotent (they are: pure cache invalidations).
        notifyUpdateHandlers()
        if (waitForDisk) {
            task.awaitUninterruptibly()
            task.error?.let {
                throw IllegalStateException("Failed to persist $fileName", it)
            }
        }
    }

    fun registerUpdateHandler(handler: () -> Unit) {
        synchronized(updateHandlers) { updateHandlers.add(handler) }
    }

    fun unregisterUpdateHandler(handler: () -> Unit) {
        synchronized(updateHandlers) { updateHandlers.remove(handler) }
    }

    /**
     * Reads the file from disk and returns the parsed value, or the default if the file is
     * missing, unreadable, or malformed. Implementations should never throw.
     */
    protected fun readFromDisk(): T {
        if (!configFile.isFile || !configFile.canRead()) return default

        return try {
            val root = FileUtil.parseDocument(configFile)
            parseRoot(root) ?: default
        } catch (e: Exception) {
            log.warnAndDebugDetails("Failed to read $fileName from ${configFile.absolutePath}; falling back to defaults", e)
            default
        }
    }

    /**
     * Parses the root element into a typed value. Returns null if the element is unrecognized
     * (wrong root name, unknown version) so the caller falls back to defaults.
     */
    protected abstract fun parseRoot(root: Element): T?

    /**
     * Serializes the value into a JDOM document with a stable structure (so unchanged values
     * produce byte-identical files).
     */
    protected abstract fun toDocument(value: T): Document

    private fun notifyUpdateHandlers() {
        val snapshot = synchronized(updateHandlers) { updateHandlers.toList() }
        snapshot.forEach {
            try {
                it()
            } catch (e: Exception) {
                log.error("Settings update handler threw", e)
            }
        }
    }

    override fun changeOccured(requestor: String) {
        current.set(readFromDisk())
        notifyUpdateHandlers()
    }

    override fun destroy() {
        // The order is important here: unregister the listener first,
        // so that listener type caches of EventDispatcherHandlers
        // will not hold this class as a hashmap key.
        watcher.unregisterListener(this)
        watcher.stop()
        watcher.clear()
        synchronized(updateHandlers) { updateHandlers.clear() }
    }
}
