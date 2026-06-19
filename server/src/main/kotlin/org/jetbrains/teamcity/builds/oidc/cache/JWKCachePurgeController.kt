package org.jetbrains.teamcity.builds.oidc.cache

import com.intellij.openapi.diagnostic.Logger
import jetbrains.buildServer.controllers.ActionErrors
import jetbrains.buildServer.controllers.BaseFormXmlController
import jetbrains.buildServer.log.Loggers
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.jdom.Element
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JWKCachePurgeController(
    controllerManager: WebControllerManager,
    private val jwkCache: JWKCache
): BaseFormXmlController() {
    private val LOG = Logger.getInstance(Loggers.SERVER_CATEGORY + "." + this.javaClass.name)

    init {
        controllerManager.registerController(OIDCConstants.JWKCache.PURGE_URL, this)
    }

    public override fun doGet(request: HttpServletRequest, response: HttpServletResponse) = null

    public override fun doPost(request: HttpServletRequest, response: HttpServletResponse, xmlResponse: Element) {
        val errors = ActionErrors()

        val user = jetbrains.buildServer.web.util.SessionUser.getUser(request)
        if (user == null || !user.isPermissionGrantedGlobally(OIDCConstants.AdminPage.REQUIRED_PERMISSION)) {
            errors.addError("jwkCachePurge", "You do not have permission to purge the JWK cache.")
            errors.serialize(xmlResponse)
            return
        }

        LOG.info("Received JWK cache purge request (requested by '${user.username}')")

        try {
            jwkCache.purge()
            LOG.info("JWK cache purge successful (requested by '${user.username}')")
        } catch (e: Exception) {
            LOG.error("JWK cache purge failed (requested by '${user.username}')", e)
            errors.addError("jwkCachePurge", e.message ?: "JWK cache purge failed")
        }
        errors.serialize(xmlResponse)
        return
    }
}
