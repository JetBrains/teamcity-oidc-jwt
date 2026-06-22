package org.jetbrains.teamcity.builds.oidc.signer.builtin

import jetbrains.buildServer.serverSide.ServerResponsibility
import jetbrains.buildServer.serverSide.auth.Permission
import jetbrains.buildServer.users.SUser
import jetbrains.buildServer.web.openapi.WebControllerManager
import jetbrains.buildServer.BaseTestCase
import org.jdom.Element
import org.assertj.core.api.Assertions
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class BuiltInRotationControllerTest : BaseTestCase() {
    private lateinit var controllerManager: WebControllerManager
    private lateinit var serverResponsibility: ServerResponsibility
    private lateinit var signer: AbstractFileBasedJWTSigner<*>
    private lateinit var request: HttpServletRequest
    private lateinit var response: HttpServletResponse
    private lateinit var xmlResponse: Element
    private lateinit var controller: BuiltInRotationController

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        controllerManager = mockk(relaxed = true)
        serverResponsibility = mockk {
            every { canProcessUserDataModificationRequests() } returns true
        }
        signer = mockk {
            every { id } returns "builtin-rsa"
        }
        request = mockk()
        response = mockk()
        xmlResponse = Element("response")

        controller = BuiltInRotationController(controllerManager, serverResponsibility, signer)
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
        verify(exactly = 1) { controllerManager.registerController(eq("/app/oidc-jwt/builtin-rsa/rotate"), eq(controller)) }
    }

    @Test
    fun rotationURL_matchesExpectedFormat() {
        Assertions.assertThat(controller.rotationURL()).isEqualTo("/app/oidc-jwt/builtin-rsa/rotate")
    }

    @Test
    fun requiredPermission_isChangeServerSettings() {
        Assertions.assertThat(controller.requiredPermission()).isEqualTo(Permission.CHANGE_SERVER_SETTINGS)
    }

    @Test
    fun doGet_returnsNull() {
        val result: Any? = controller.doGet(request, response)
        Assertions.assertThat(result).isNull()
    }

    @Test
    fun doPost_nodeCannotProcessUserDataModifications_doesNotRotateAndReturnsError() {
        every { serverResponsibility.canProcessUserDataModificationRequests() } returns false

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 0) { signer.rotateKey() }
        assertHasError(xmlResponse, "rotation", "cannot rotate keys")
    }

    @Test
    fun doPost_nullUser_doesNotRotateAndReturnsError() {
        stubSessionUser(null)

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 0) { signer.rotateKey() }
        assertHasError(xmlResponse, "rotation", "permission")
    }

    @Test
    fun doPost_userWithoutPermission_doesNotRotateAndReturnsError() {
        stubSessionUser(mockUnauthorizedUser())

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 0) { signer.rotateKey() }
        assertHasError(xmlResponse, "rotation", "permission")
    }

    @Test
    fun doPost_authorizedUser_rotatesKeyAndReturnsNoErrors() {
        stubSessionUser(mockAuthorizedUser())
        every { signer.rotateKey() } just Runs

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 1) { signer.rotateKey() }
        assertNoErrors(xmlResponse)
    }

    @Test
    fun doPost_rotateThrows_returnsError() {
        stubSessionUser(mockAuthorizedUser())
        every { signer.rotateKey() } throws RuntimeException("disk full")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "rotation", "disk full")
        clearFailure()
    }

    @Test
    fun doPost_rotateThrowsWithoutMessage_returnsGenericError() {
        stubSessionUser(mockAuthorizedUser())
        every { signer.rotateKey() } throws RuntimeException()

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "rotation", "Rotation failed")
        clearFailure()
    }
}
