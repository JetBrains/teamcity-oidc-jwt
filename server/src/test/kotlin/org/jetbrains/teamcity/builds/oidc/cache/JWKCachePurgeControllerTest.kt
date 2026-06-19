package org.jetbrains.teamcity.builds.oidc.cache

import jetbrains.buildServer.BaseTestCase
import jetbrains.buildServer.serverSide.auth.Permission
import jetbrains.buildServer.users.SUser
import jetbrains.buildServer.web.openapi.WebControllerManager
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions
import org.jdom.Element
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JWKCachePurgeControllerTest : BaseTestCase() {
    private lateinit var controllerManager: WebControllerManager
    private lateinit var jwkCache: JWKCache
    private lateinit var request: HttpServletRequest
    private lateinit var response: HttpServletResponse
    private lateinit var xmlResponse: Element
    private lateinit var controller: JWKCachePurgeController

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        controllerManager = mockk(relaxed = true)
        jwkCache = mockk()
        request = mockk()
        response = mockk()
        xmlResponse = Element("response")

        controller = JWKCachePurgeController(controllerManager, jwkCache)
    }

    private fun mockAuthorizedUser(): SUser = mockk {
        every { isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS) } returns true
        every { username } returns "admin"
    }

    private fun mockUnauthorizedUser(): SUser = mockk {
        every { isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS) } returns false
        every { username } returns "reader"
    }

    private fun stubSessionUser(user: SUser?) {
        every { request.getAttribute("USER_KEY") } returns user
    }

    private fun getErrors(element: Element): Map<String, String> {
        val errorsElement = element.getChild("errors") ?: return emptyMap()
        @Suppress("UNCHECKED_CAST")
        return (errorsElement.getChildren("error") as List<Element>).associate { child ->
            child.getAttributeValue("id") to child.text
        }
    }

    private fun assertHasError(element: Element, fieldId: String, messageSubstring: String? = null) {
        val errors = getErrors(element)
        Assertions.assertThat(errors).containsKey(fieldId)
        if (messageSubstring != null) {
            Assertions.assertThat(errors[fieldId]).contains(messageSubstring)
        }
    }

    private fun assertNoErrors(element: Element) {
        val errors = getErrors(element)
        Assertions.assertThat(errors).isEmpty()
    }

    @Test
    fun init_registersControllerUnderExpectedURL() {
        verify(exactly = 1) { controllerManager.registerController(eq("/app/oidc-jwt/jwk-cache/purge"), eq(controller)) }
    }

    @Test
    fun doGet_returnsNull() {
        val result: Any? = controller.doGet(request, response)
        Assertions.assertThat(result).isNull()
    }

    @Test
    fun doPost_nullUser_doesNotPurgeAndReturnsError() {
        stubSessionUser(null)

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 0) { jwkCache.purge() }
        assertHasError(xmlResponse, "jwkCachePurge", "permission")
    }

    @Test
    fun doPost_userWithoutPermission_doesNotPurgeAndReturnsError() {
        stubSessionUser(mockUnauthorizedUser())

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 0) { jwkCache.purge() }
        assertHasError(xmlResponse, "jwkCachePurge", "permission")
    }

    @Test
    fun doPost_authorizedUser_purgesCacheAndReturnsNoErrors() {
        stubSessionUser(mockAuthorizedUser())
        every { jwkCache.purge() } just Runs

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 1) { jwkCache.purge() }
        assertNoErrors(xmlResponse)
    }

    @Test
    fun doPost_purgeThrows_returnsError() {
        stubSessionUser(mockAuthorizedUser())
        every { jwkCache.purge() } throws RuntimeException("db down")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "jwkCachePurge", "db down")
        clearFailure()
    }

    @Test
    fun doPost_purgeThrowsWithoutMessage_returnsGenericError() {
        stubSessionUser(mockAuthorizedUser())
        every { jwkCache.purge() } throws RuntimeException()

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "jwkCachePurge", "JWK cache purge failed")
        clearFailure()
    }
}
