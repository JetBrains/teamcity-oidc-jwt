package org.jetbrains.teamcity.builds.oidc.buildfeature

import org.jetbrains.teamcity.builds.oidc.JWTClaimsGenerator
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import jetbrains.buildServer.controllers.BaseController
import jetbrains.buildServer.controllers.admin.projects.EditBuildTypeForm
import jetbrains.buildServer.serverSide.SBuildType
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.springframework.web.servlet.ModelAndView
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import kotlin.collections.set

abstract class AbstractOIDCBuildFeatureController(
    webControllerManager: WebControllerManager,
    private val settings: OIDCSettings,
    private val jspPath: String,
    htmlPath: String
) : BaseController() {

    init {
        webControllerManager.registerController(htmlPath, this)
    }

    override fun doHandle(request: HttpServletRequest, response: HttpServletResponse): ModelAndView {
        val mv = ModelAndView(jspPath)
        val effectiveIssuer = settings.getEffectiveIssuer()
        mv.model["issuer"] = effectiveIssuer

        val buildTypeForm = request.getAttribute("buildForm") as? EditBuildTypeForm
        val buildConfig: SBuildType? = buildTypeForm?.settingsBuildType
        mv.model["sub"] = buildConfig?.let { JWTClaimsGenerator.sub(it.project, it.buildTypeId) }

        mv.model["jwksURL"] = "${OIDCConstants.OIDC_ROOT_URL}/${OIDCConstants.WellKnownController.ROOT}${OIDCConstants.WellKnownController.JWKS_PATH}?currentOnly=true"
        mv.model["jwksFilename"] = "${effectiveIssuer.removePrefix("https://")}_jwks.json"

        return mv
    }
}
