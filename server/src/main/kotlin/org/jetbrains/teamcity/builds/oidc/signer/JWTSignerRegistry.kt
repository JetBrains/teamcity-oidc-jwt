package org.jetbrains.teamcity.builds.oidc.signer

import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import jetbrains.buildServer.ExtensionsProvider
import jetbrains.buildServer.plugins.PluginManager
import jetbrains.buildServer.plugins.PluginManagerListenerAdapter
import jetbrains.buildServer.plugins.bean.PluginInfo
import jetbrains.buildServer.plugins.classLoaders.PluginInfoSearcher
import jetbrains.buildServer.util.Cached
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerUnavailableException
import org.springframework.beans.factory.DisposableBean

class JWTSignerRegistry(
    private val settings: OIDCSettings,
    private val extensionsProvider: ExtensionsProvider,
    private val pluginManager: PluginManager,
    private val pluginInfoSearcher: PluginInfoSearcher
): PluginManagerListenerAdapter(), DisposableBean {
    private data class CachedSigner(val signer: JWTSigner, val pluginInfo: PluginInfo)

    private var destroyed = false

    private val cachedSigner: Cached<CachedSigner?> = Cached {
        if (destroyed) {
            throw JWTSignerException("JWTSignerRegistry is already destroyed")
        }

        val activeID = settings.getActiveSignerId()
        val signer = locateSigners().find { it.id == activeID }
            ?: throw JWTSignerUnavailableException("JWT signer '$activeID' is not available")
        val cachedSignerPlugin = pluginInfoSearcher.findPluginInfoByClass(signer.javaClass)
            ?: throw JWTSignerUnavailableException("Plugin info not found for JWT signer class ${signer.javaClass.name}")
        CachedSigner(signer, cachedSignerPlugin)
    }

    init {
        settings.registerUpdateHandler(this::handleSettingsUpdate)
        pluginManager.pluginLifecycleEventDispatcher.addListener(this)
    }

    private fun handleSettingsUpdate() {
        cachedSigner.invalidate()
    }

    private fun locateSigners(): Collection<JWTSigner> = extensionsProvider.getExtensions(JWTSigner::class.java)

    fun getSigners(): Map<String, JWTSigner> = locateSigners().sortedBy { it.displayName }.associateBy { it.id }

    fun getActiveSigner(): JWTSigner = cachedSigner.get().signer

    override fun pluginResourcesCleaned(pluginInfo: PluginInfo) {
        val current = try {
            cachedSigner.get()
        } catch (e: JWTSignerUnavailableException) {
            return  // No cached signer => no reasons to worry
        }

        if (pluginInfo.uuid == current.pluginInfo.uuid) {
            cachedSigner.invalidate()
        }
    }

    override fun destroy() {
        destroyed = true
        cachedSigner.invalidate()
        pluginManager.pluginLifecycleEventDispatcher.removeListener(this)
        settings.unregisterUpdateHandler(this::handleSettingsUpdate)
    }
}
