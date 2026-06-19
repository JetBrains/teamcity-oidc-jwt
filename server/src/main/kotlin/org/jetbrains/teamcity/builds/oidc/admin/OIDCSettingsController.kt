package org.jetbrains.teamcity.builds.oidc.admin

import com.intellij.openapi.diagnostic.Logger
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.controllers.ActionErrors
import jetbrains.buildServer.controllers.BaseFormXmlController
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.jdom.Element
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import kotlin.collections.emptyMap

class OIDCSettingsController(
    controllerManager: WebControllerManager,
    private val registry: JWTSignerRegistry,
    private val settings: OIDCSettings,
) : BaseFormXmlController() {
    private val LOG = Logger.getInstance(Loggers.SERVER_CATEGORY + "." + this.javaClass.name)

    init {
        controllerManager.registerController(OIDCConstants.AdminPage.SAVE_URL, this)
    }

    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) = null

    /**
     * Save the settings for the currently selected signer. If the signer is currently unavailable
     * (e.g., plugin is unloaded), notify the user and don't save the global settings.
     *
     * 0. Check user authorization. Return early if not authorized.
     * 1. Validate the issuer URL. Add an error to the list if invalid.
     * 2. Check whether the request has a signer ID provided. Add an error to the list if missing. Return early if missing.
     * 3. Look up the signer by ID. If it's not missing, take its instance and
     * 3.1. Validate the signer settings using `validateSettings`. Add errors to the list.
     * 3.2. Return the list if it's not empty. This will return all signer validation errors alongside errors from 1 and 2.
     * 3.3. Save the signer settings using `saveSettings`. Add errors if returned.
     * 4. If the signer is missing,
     * 4.1. Add an error for `signerId` field about a missing signer
     * 4.2. For each signer-specific field from the request, add errors about the signer being missing.
     * 5. If the error list is not empty, return it. This will return signer save errors if the signer is not missing
     *    and errors from 1, 2, and 4 otherwise.
     * 5. Save the global settings.
     */
    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse, xmlResponse: Element) {
        val errors = ActionErrors()

        val user = jetbrains.buildServer.web.util.SessionUser.getUser(request)
        // TODO Cloud users cannot use this with CHANGE_SERVER_SETTINGS. But it's good.
        // In fact, we could disable this controller entirely and populate the config from the commandline params
        // for cloud installations.
        if (user == null || !user.isPermissionGrantedGlobally(OIDCConstants.AdminPage.REQUIRED_PERMISSION)) {
            errors.addError("permission", "You do not have permission to change server settings.")
            errors.serialize(xmlResponse)
            return
        }

        LOG.info("Received settings update (requested by '${user.username}')")

        // Validate the issuer URL parameter
        val issuerParam = request.getParameter("issuer")?.trim()?.ifBlank { null }?.let {
            if (!it.startsWith("https://")) {
                errors.addError("issuer", "Issuer URL must start with https://")
                null
            } else {
                it
            }
        }

        // Figure out which signer was chosen.
        val chosenSignerId = request.getParameter("signerId")?.ifBlank { null }
        if (chosenSignerId == null) {
            errors.addError("signerId", "Signer ID is required.")
            // Signer ID was not provided, the request is clearly incorrect.
            // We cannot verify the signer settings, so we cannot save them either. Fail here.
            errors.serialize(xmlResponse)
            return
        }

        // Look up the chosen signer. It might be from a disabled plugin, but it should not prevent us from saving settings.
        val signersById = registry.getSigners()
        val chosenSigner = chosenSignerId.let { signersById[chosenSignerId] }

        // Collect signer settings from the page to either save settings or display errors about missing signer
        val chosenSignerSettings = chosenSignerId.let {
            val paramFieldPrefix = "$chosenSignerId."  // TODO Hardcoded prefix format from `OIDCAdminPage`
            request.parameterNames.asSequence()
                .filter { it.startsWith(paramFieldPrefix) }
                .associate { it.removePrefix(paramFieldPrefix) to request.getParameter(it) }
        } ?: emptyMap()

        if (chosenSigner == null) {
            // Add error about signer being missing
            errors.addError("signerId", "Missing or disabled signer: $chosenSignerId. Unable to save signer settings.")
            // Add error message for each field rendered when the signer wasn't missing
            chosenSignerSettings.forEach { (field, value) ->
                errors.addError(
                    "signerError_${chosenSignerId}_${field}",
                    "Cannot save settings of missing or disabled signer"
                )
            }
        } else {
            // Validate the chosen signer settings
            try {
                chosenSigner.adminSettings?.validateSettings(chosenSignerSettings)
                    ?: emptyMap()
            } catch (e: Exception) {
                errors.addError(
                    "signerId",
                    "Failed to validate signer settings, ${e.javaClass.simpleName}: ${e.message}"
                )
                emptyMap()
            }.forEach { (field, message) ->
                errors.addError("signerError_${chosenSignerId}_${field}", message)
            }

            if (errors.hasErrors()) {
                // Note: this will return if there were either signer validation errors or global settings errors.
                // The goal is to prevent saving signer settings if there were problems with global ones.
                LOG.warn("Validation errors on settings update (requested by '${user.username}'): $errors")
                errors.serialize(xmlResponse)
                return
            }

            // Save the signer settings, see if anything breaks
            try {
                chosenSigner.adminSettings?.saveSettings(chosenSignerSettings)
                    ?: emptyMap()
            } catch (e: Exception) {
                errors.addError("signerId", "Failed to save signer settings, ${e.javaClass.simpleName}: ${e.message}")
                emptyMap()
            }.forEach { (field, message) ->
                errors.addError("signerError_${chosenSignerId}_${field}", message)
            }
        }

        // If there were any errors we haven't returned yet, return them now before we save global settings.
        if (errors.hasErrors()) {
            LOG.warn("Save errors on settings update (requested by '${user.username}'): $errors")
            errors.serialize(xmlResponse)
            return
        }

        // Since chosen signer might be null in some cases, fall back to the currently active one.
        settings.updateSettings(
            chosenSigner?.id ?: settings.getActiveSignerId(),
            issuerParam
        )

        LOG.info("Saved settings (requested by '${user.username}'): issuer '$issuerParam', signer '$chosenSignerId'")
    }
}
