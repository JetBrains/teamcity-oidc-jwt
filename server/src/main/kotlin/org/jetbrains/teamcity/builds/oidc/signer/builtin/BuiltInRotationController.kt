package org.jetbrains.teamcity.builds.oidc.signer.builtin

import com.intellij.openapi.diagnostic.Logger
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import jetbrains.buildServer.controllers.ActionErrors
import jetbrains.buildServer.controllers.BaseFormXmlController
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.serverSide.NodeResponsibility
import jetbrains.buildServer.serverSide.ServerResponsibility
import jetbrains.buildServer.serverSide.auth.Permission
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.jdom.Element
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class BuiltInRotationController(
    controllerManager: WebControllerManager,
    private val serverResponsibility: ServerResponsibility,
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

        if (!serverResponsibility.canProcessUserDataModificationRequests()) {
            errors.addError(
                "rotation",
                "This node cannot rotate keys. Please use a node with '${NodeResponsibility.CAN_PROCESS_USER_DATA_MODIFICATION_REQUESTS.displayName}' responsibility."
            )
            errors.serialize(xmlResponse)
            return
        }

        val user = jetbrains.buildServer.web.util.SessionUser.getUser(request)
        if (user == null || !user.isPermissionGrantedGlobally(requiredPermission())) {
            errors.addError("rotation", "You do not have permission to rotate keys.")
            errors.serialize(xmlResponse)
            return
        }

        LOG.info("Received key rotation request (requested by '${user.username}')")

        try {
            signer.rotateKey()
            LOG.info("Key rotation successful (requested by '${user.username}')")
        } catch (e: Exception) {
            LOG.error("Key rotation failed (requested by '${user.username}')", e)
            errors.addError("rotation", e.message ?: "Rotation failed")
        }
        errors.serialize(xmlResponse)
        return
    }
}
