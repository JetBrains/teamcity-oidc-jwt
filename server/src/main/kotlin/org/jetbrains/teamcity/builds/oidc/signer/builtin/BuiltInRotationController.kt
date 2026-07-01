package org.jetbrains.teamcity.builds.oidc.signer.builtin

import com.intellij.openapi.diagnostic.Logger
import jetbrains.buildServer.controllers.ActionErrors
import jetbrains.buildServer.controllers.BaseFormXmlController
import jetbrains.buildServer.controllers.XmlResponseUtil
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.serverSide.auth.Permission
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.jdom.Content
import org.jdom.Element
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.springframework.web.servlet.ModelAndView
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

    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse): ModelAndView? {
        val xmlResponse = XmlResponseUtil.newXmlResponse()
        val errors = ActionErrors()
        response.contentType = "application/xml"

        val user = jetbrains.buildServer.web.util.SessionUser.getUser(request)
        if (user == null || !user.isPermissionGrantedGlobally(requiredPermission())) {
            errors.addError("permission", "You do not have permission to get key rotation status.")
            errors.serialize(xmlResponse)
            response.status = 403
            XmlResponseUtil.writeXmlResponse(xmlResponse, response)
            return null
        }

        val taskID = request.getParameter("taskID")
        if (taskID == null) {
            errors.addError("taskID", "`taskID` parameter is required")
            errors.serialize(xmlResponse)
            response.status = 400
            XmlResponseUtil.writeXmlResponse(xmlResponse, response)
            return null
        }

        val intTaskID = try {
            Integer.parseInt(taskID)
        } catch (e: NumberFormatException) {
            errors.addError("taskID", "`taskID` parameter must be an integer")
            errors.serialize(xmlResponse)
            response.status = 404
            XmlResponseUtil.writeXmlResponse(xmlResponse, response)
            return null
        }

        val status = signer.rotationTaskStatus(intTaskID)
        if (status == null) {
            errors.addError("taskID", "Unknown task ID")
            errors.serialize(xmlResponse)
            response.status = 404
            XmlResponseUtil.writeXmlResponse(xmlResponse, response)
            return null
        }
        val responseElement = Element("response")
        val resultElement = Element("task")
        xmlResponse.addContent(responseElement as Content)
        responseElement.addContent(resultElement as Content)
        resultElement.setAttribute("id", taskID)
        resultElement.setAttribute("status", status)
        XmlResponseUtil.writeXmlResponse(xmlResponse, response)
        return null
    }

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
            val taskID = signer.requestKeyRotation()
            LOG.info("Key rotation '$taskID' scheduled (requested by '${user.username}')")

            val resultElement = Element("task")
            xmlResponse.addContent(resultElement as Content)
            resultElement.setAttribute("id", taskID)
            return
        } catch (e: Exception) {
            LOG.error("Key rotation failed to be scheduled (requested by '${user.username}')", e)
            errors.addError("rotation", e.message ?: "Rotation scheduling failed due to ${e.javaClass.name}")
        }
        errors.serialize(xmlResponse)
        return
    }
}
