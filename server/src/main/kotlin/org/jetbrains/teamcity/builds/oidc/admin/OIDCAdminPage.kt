package org.jetbrains.teamcity.builds.oidc.admin

import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.controllers.admin.AdminPage
import jetbrains.buildServer.web.openapi.PagePlaces
import jetbrains.buildServer.web.openapi.PluginDescriptor
import javax.servlet.http.HttpServletRequest

data class SignerView(
    val id: String,
    val displayName: String,
    val paramPrefix: String,
    val errorPrefix: String,
    val settingsPagePath: String?,
    val settings: Map<String, Any>
)

class OIDCAdminPage(
    pagePlaces: PagePlaces,
    private val pluginDescriptor: PluginDescriptor,
    private val registry: JWTSignerRegistry,
    private val settings: OIDCSettings
) : AdminPage(pagePlaces) {

    init {
        pluginName = OIDCConstants.AdminPage.PLUGIN_NAME
        includeUrl = pluginDescriptor.getPluginResourcesPath(OIDCConstants.AdminPage.INCLUDE_URL_PATH)
        tabTitle = OIDCConstants.AdminPage.TAB_TITLE
        register()
    }

    override fun getGroup(): String = INTEGRATIONS_GROUP

    override fun fillModel(model: MutableMap<String, Any>, request: HttpServletRequest) {
        super.fillModel(model, request)
        val defaultIssuer = settings.getDefaultIssuer()
        val effectiveIssuer = settings.getEffectiveIssuer()
        model["issuer"] = settings.getOverrideIssuer()
        model["defaultIssuer"] = defaultIssuer
        model["effectiveIssuer"] = effectiveIssuer

        model["jwksURL"] = "${OIDCConstants.OIDC_ROOT_URL}/${OIDCConstants.WellKnownController.ROOT}${OIDCConstants.WellKnownController.JWKS_PATH}?currentOnly=true"
        model["jwksFilename"] = "${effectiveIssuer.removePrefix("https://")}_jwks.json"
        model["configURL"] = "${OIDCConstants.OIDC_ROOT_URL}/${OIDCConstants.WellKnownController.ROOT}${OIDCConstants.WellKnownController.CONFIG_DOWNLOAD_PATH}"
        model["configFilename"] = "${effectiveIssuer.removePrefix("https://")}_openid-configuration.json"

        val signers = registry.getSigners().map { (id, signer) ->
            val adminSettings = signer.adminSettings
            val settingsModel = mutableMapOf<String, Any>()
            adminSettings?.fillSettingsModel(settingsModel)
            SignerView(
                id = id,
                displayName = signer.displayName,
                paramPrefix = "$id.",
                errorPrefix = "signerError_${id}_",
                settingsPagePath = adminSettings?.settingsPagePath,
                settings = settingsModel
            )
        }
        val activeSignerId = settings.getActiveSignerId()

        // Add the currently selected signer if it's missing (e.g., plugin is unloaded)
        val signersForView = if (signers.none { it.id == activeSignerId }) {
            listOf(
                SignerView(
                    id = activeSignerId,
                    displayName = "$activeSignerId (missing)",
                    paramPrefix = "$activeSignerId.",
                    errorPrefix = "signerError_${activeSignerId}_",
                    settingsPagePath = pluginDescriptor.getPluginResourcesPath(OIDCConstants.AdminPage.MISSING_SIGNER_JSP),
                    settings = emptyMap()
                )
            ) + signers
        } else {
            signers
        }
        model["signers"] = signersForView
        model["activeSignerId"] = activeSignerId

        model["saveUrl"] = OIDCConstants.AdminPage.SAVE_URL

        model["jwkCachePurgeURL"] = OIDCConstants.JWKCache.PURGE_URL
        model["jwkCachePurgeRequiredPermission"] = OIDCConstants.AdminPage.REQUIRED_PERMISSION.description
    }

    override fun isAvailable(request: HttpServletRequest): Boolean {
        return checkHasGlobalPermission(request, OIDCConstants.AdminPage.REQUIRED_PERMISSION)
    }
}
