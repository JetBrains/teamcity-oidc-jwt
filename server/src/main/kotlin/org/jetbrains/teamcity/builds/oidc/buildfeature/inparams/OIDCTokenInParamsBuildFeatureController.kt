package org.jetbrains.teamcity.builds.oidc.buildfeature.inparams

import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.buildfeature.AbstractOIDCBuildFeatureController
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.web.openapi.WebControllerManager
import org.springframework.web.servlet.ModelAndView
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class OIDCTokenInParamsBuildFeatureController(
    descriptor: PluginDescriptor,
    webControllerManager: WebControllerManager,
    settings: OIDCSettings
) : AbstractOIDCBuildFeatureController(
    webControllerManager = webControllerManager,
    settings = settings,
    jspPath = descriptor.getPluginResourcesPath(OIDCConstants.BuildFeatureInParams.BUILD_FEATURE_PATH_JSP),
    htmlPath = descriptor.getPluginResourcesPath(OIDCConstants.BuildFeatureInParams.BUILD_FEATURE_PATH_HTML)
) {
    override fun doHandle(request: HttpServletRequest, response: HttpServletResponse): ModelAndView {
        val mv = super.doHandle(request, response)
        mv.model["defaultTimeoutSeconds"] = OIDCConstants.BuildFeatureInParams.JWT_LIFETIME_BUFFER_MINUTES * 60L
        return mv
    }
}
