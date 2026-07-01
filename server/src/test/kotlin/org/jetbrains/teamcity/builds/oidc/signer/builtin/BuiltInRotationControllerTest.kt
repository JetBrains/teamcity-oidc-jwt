package org.jetbrains.teamcity.builds.oidc.signer.builtin

import jetbrains.buildServer.controllers.MockRequest
import jetbrains.buildServer.controllers.MockResponse
import jetbrains.buildServer.serverSide.auth.Permission
import jetbrains.buildServer.users.SUser
import jetbrains.buildServer.web.openapi.WebControllerManager
import jetbrains.buildServer.BaseTestCase
import org.jdom.Element
import org.assertj.core.api.Assertions
import org.testng.annotations.AfterMethod
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*

class BuiltInRotationControllerTest : BaseTestCase() {
    private lateinit var controllerManager: WebControllerManager
    private lateinit var signer: AbstractFileBasedJWTSigner<*>
    private lateinit var request: MockRequest
    private lateinit var response: MockResponse
    private lateinit var controller: BuiltInRotationController

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        controllerManager = mockk(relaxed = true)
        signer = mockk {
            every { id } returns "builtin-rsa"
        }
        request = MockRequest()
        response = MockResponse()

        controller = BuiltInRotationController(controllerManager, signer)
    }

    @AfterMethod
    override fun tearDown() {
        unmockkAll()
        super.tearDown()
    }

    private fun mockAuthorizedUser(): SUser = mockk {
        every { isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS) } returns true
        every { username } returns "admin"
    }

    private fun mockUnauthorizedUser(): SUser = mockk {
        every { isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS) } returns false
        every { username } returns "reader"
    }

    private fun loginAs(user: SUser?) {
        if (user != null) {
            request.setAttribute("USER_KEY", user)
        }
    }

    /** Parses the XML the controller serialized into the servlet response. */
    private fun responseXml(): Element = response.getReturnedContentAsXml()

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
    fun doGet_unauthorizedUser_returns403() {
        loginAs(mockUnauthorizedUser())

        controller.doGet(request, response)

        Assertions.assertThat(response.status).isEqualTo(403)
        assertHasError(responseXml(), "permission")
    }

    @Test
    fun doGet_nullUser_returns403() {
        loginAs(null)

        controller.doGet(request, response)

        Assertions.assertThat(response.status).isEqualTo(403)
        assertHasError(responseXml(), "permission")
    }

    @Test
    fun doGet_missingTaskID_returns400() {
        loginAs(mockAuthorizedUser())

        controller.doGet(request, response)

        Assertions.assertThat(response.status).isEqualTo(400)
        assertHasError(responseXml(), "taskID")
    }

    @Test
    fun doGet_nonIntegerTaskID_returns404() {
        loginAs(mockAuthorizedUser())
        request.setParameter("taskID", "not-a-number")

        controller.doGet(request, response)

        Assertions.assertThat(response.status).isEqualTo(404)
        assertHasError(responseXml(), "taskID")
        verify(exactly = 0) { signer.rotationTaskStatus(any()) }
    }

    @Test
    fun doGet_unknownTask_returns404() {
        loginAs(mockAuthorizedUser())
        request.setParameter("taskID", "1")
        every { signer.rotationTaskStatus(1) } returns null

        controller.doGet(request, response)

        Assertions.assertThat(response.status).isEqualTo(404)
        assertHasError(responseXml(), "taskID")
    }

    @Test
    fun doGet_knownTask_returnsTaskElementWithStatus() {
        loginAs(mockAuthorizedUser())
        request.setParameter("taskID", "1")
        every { signer.rotationTaskStatus(1) } returns "Pending"

        controller.doGet(request, response)

        val xml = responseXml()
        val task = xml.getChild("task")
        Assertions.assertThat(task).isNotNull
        Assertions.assertThat(task.getAttributeValue("id")).isEqualTo("1")
        Assertions.assertThat(task.getAttributeValue("status")).isEqualTo("Pending")
        assertNoErrors(xml)
    }

    @Test
    fun doPost_nullUser_doesNotRequestRotationAndReturnsError() {
        loginAs(null)
        val xmlResponse = Element("response")

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 0) { signer.requestKeyRotation() }
        assertHasError(xmlResponse, "rotation", "permission")
    }

    @Test
    fun doPost_userWithoutPermission_doesNotRequestRotationAndReturnsError() {
        loginAs(mockUnauthorizedUser())
        val xmlResponse = Element("response")

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 0) { signer.requestKeyRotation() }
        assertHasError(xmlResponse, "rotation", "permission")
    }

    @Test
    fun doPost_authorizedUser_returnsTaskElement() {
        loginAs(mockAuthorizedUser())
        val xmlResponse = Element("response")
        every { signer.requestKeyRotation() } returns "task-42"

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 1) { signer.requestKeyRotation() }
        assertNoErrors(xmlResponse)
        val task = xmlResponse.getChild("task")
        Assertions.assertThat(task).isNotNull
        Assertions.assertThat(task.getAttributeValue("id")).isEqualTo("task-42")
    }

    @Test
    fun doPost_requestRotationThrows_returnsError() {
        loginAs(mockAuthorizedUser())
        val xmlResponse = Element("response")
        every { signer.requestKeyRotation() } throws RuntimeException("disk full")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "rotation", "disk full")
        clearFailure()
    }

    @Test
    fun doPost_requestRotationThrowsWithoutMessage_returnsGenericError() {
        loginAs(mockAuthorizedUser())
        val xmlResponse = Element("response")
        every { signer.requestKeyRotation() } throws RuntimeException()

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "rotation", "Rotation scheduling failed")
        clearFailure()
    }
}
