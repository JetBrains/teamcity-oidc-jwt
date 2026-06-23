package org.jetbrains.teamcity.builds.oidc.signer.builtin

import com.intellij.openapi.diagnostic.Logger
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import jetbrains.buildServer.controllers.ActionErrors
import jetbrains.buildServer.controllers.BaseFormXmlController
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.serverSide.auth.Permission
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.jdom.Element
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class BuiltInRotationController(
    controllerManager: WebControllerManager,
    private val signer: AbstractFileBasedJWTSigner<*>
): BaseFormXmlController() {
    private val LOG = Logger.getInstance(Loggers.SERVER_CATEGORY + "." + this.javaClass.name + "#" + signer.id)

    init {
        controllerManager.registerController(rotationURL(), this)
    }

    fun rotationURL(): String {
        return "${OIDCConstants.OIDC_ROOT_URL}/${signer.id}${OIDCConstants.BuiltInRotationController.ROTATE_PATH}"
    }

    fun requiredPermission(): Permission {
        return OIDCConstants.AdminPage.REQUIRED_PERMISSION
    }

    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) = null

    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse, xmlResponse: Element) {
        val errors = ActionErrors()

        val user = jetbrains.buildServer.web.util.SessionUser.getUser(request)
        if (user == null || !user.isPermissionGrantedGlobally(requiredPermission())) {
            errors.addError("rotation", "You do not have permission to rotate keys.")
            errors.serialize(xmlResponse)
            return
        }

        LOG.info("Received key rotation request (requested by '${user.username}')")

        try {
            signer.requestKeyRotation()
            LOG.info("Key rotation scheduled (requested by '${user.username}')")
        } catch (e: Exception) {
            LOG.error("Key rotation failed to be scheduled (requested by '${user.username}')", e)
            errors.addError("rotation", e.message ?: "Rotation scheduling failed")
        }
        errors.serialize(xmlResponse)
        return
    }
}
