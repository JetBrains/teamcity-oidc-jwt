package org.jetbrains.teamcity.builds.oidc

import jetbrains.buildServer.serverSide.SBuildServer

class OIDCSettings(
    private val store: OIDCGlobalSettingsStore,
    private val buildServer: SBuildServer
) {
    fun registerUpdateHandler(handler: () -> Unit) {
        store.registerUpdateHandler(handler)
    }

    fun unregisterUpdateHandler(handler: () -> Unit) {
        store.unregisterUpdateHandler(handler)
    }

    fun getOverrideIssuer(): String = store.get().overrideIssuer

    private fun normalizeRootUrl(url: String): String =
        url.replaceFirst("http://", "https://").trimEnd('/')

    fun getDefaultIssuer(): String = normalizeRootUrl(buildServer.rootUrl) + OIDCConstants.OIDC_ROOT_URL

    fun getEffectiveIssuer(): String = getOverrideIssuer().ifBlank { getDefaultIssuer() }

    fun getActiveSignerId(): String = store.get().activeSignerId

    fun updateSettings(activeSignerID: String, issuer: String?) {
        val newSettings = OIDCGlobalSettings(
            activeSignerId = activeSignerID,
            overrideIssuer = issuer?.trim().orEmpty(),
        )
        store.save(newSettings)
    }
}
