package org.jetbrains.teamcity.builds.oidc.admin

import org.jetbrains.teamcity.builds.oidc.OIDCSettings
import org.jetbrains.teamcity.builds.oidc.api.JWTSigner
import org.jetbrains.teamcity.builds.oidc.api.JWTSignerAdminSettings
import org.jetbrains.teamcity.builds.oidc.signer.JWTSignerRegistry
import jetbrains.buildServer.users.SUser
import jetbrains.buildServer.web.openapi.WebControllerManager
import jetbrains.buildServer.BaseTestCase
import org.jdom.Element
import org.assertj.core.api.Assertions
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*
import jetbrains.buildServer.serverSide.auth.Permission
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class OIDCSettingsControllerTest : BaseTestCase() {
    private lateinit var controllerManager: WebControllerManager
    private lateinit var registry: JWTSignerRegistry
    private lateinit var settings: OIDCSettings
    private lateinit var request: HttpServletRequest
    private lateinit var response: HttpServletResponse
    private lateinit var xmlResponse: Element
    private lateinit var controller: OIDCSettingsController

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        controllerManager = mockk(relaxed = true)
        registry = mockk()
        settings = mockk()
        request = mockk()
        response = mockk()
        xmlResponse = Element("response")

        stubSessionUser(mockAuthorizedUser())

        controller = OIDCSettingsController(controllerManager, registry, settings)
    }


    private fun mockAuthorizedUser(): SUser = mockk {
        every { isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS) } returns true
        every { username } returns "admin"
    }

    private fun stubSessionUser(user: SUser?) {
        every { request.getAttribute("USER_KEY") } returns user
    }

    private fun mockUnauthorizedUser(): SUser = mockk {
        every { isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS) } returns false
        every { username } returns "reader"
    }

    private fun mockSigner(id: String, adminSettings: JWTSignerAdminSettings? = null): JWTSigner = mockk {
        every { getId() } returns id
        every { getAdminSettings() } returns adminSettings
    }

    private fun stubRequestWithSigner(
        signerId: String?,
        issuer: String? = null,
        signerParams: Map<String, String> = emptyMap()
    ) {
        every { request.getParameter("signerId") } returns signerId
        every { request.getParameter("issuer") } returns issuer

        val allParamNames = mutableListOf("signerId", "issuer")
        if (signerId != null) {
            signerParams.forEach { (key, value) ->
                val prefixedKey = "$signerId.$key"
                allParamNames.add(prefixedKey)
                every { request.getParameter(prefixedKey) } returns value
            }
        }
        every { request.parameterNames } returns Collections.enumeration(allParamNames)
    }

    private fun getErrors(element: Element): Map<String, String> {
        @Suppress("UNCHECKED_CAST")
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

    private fun verifyNoSettingsSaved() {
        verify(exactly = 0) { settings.updateSettings(any(), anyNullable()) }
    }

    @Test
    fun doGet_returnsNull() {
        val result: Any? = controller.doGet(request, response)
        Assertions.assertThat(result).isNull()
    }

    /*
     * Authorization checks
     */
    @Test
    fun doPost_nullUser_returnsPermissionError() {
        stubSessionUser(null)

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "permission", "You do not have permission")
        verifyNoSettingsSaved()
    }

    @Test
    fun doPost_unauthorizedUser_returnsPermissionError() {
        stubSessionUser(mockUnauthorizedUser())

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "permission", "You do not have permission")
        verifyNoSettingsSaved()
    }

    /*
     * Signer validation checks
     */
    @Test
    fun doPost_nullSignerId_returnsSignerIdRequired() {
        val otherSigner = mockSigner("other")
        stubRequestWithSigner(signerId = null)
        every { registry.getSigners() } returns mapOf("other" to otherSigner)

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "signerId", "Signer ID is required.")
        verifyNoSettingsSaved()
    }

    @Test
    fun doPost_blankSignerId_returnsSignerIdRequired() {
        stubRequestWithSigner(signerId = "  ")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "signerId", "Signer ID is required.")
        verifyNoSettingsSaved()
    }

    @Test
    fun doPost_unknownSignerId_savesCurrentSignerId() {
        val otherSigner = mockSigner("other")
        stubRequestWithSigner(signerId = "nonexistent")
        every { registry.getSigners() } returns mapOf("other" to otherSigner)

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "signerId", "Missing or disabled signer: nonexistent. Unable to save signer settings.")
        verifyNoSettingsSaved()
    }

    @Test
    fun doPost_missingSigner_withFields_errorPerField() {
        val otherSigner = mockSigner("other")
        stubRequestWithSigner(signerId = "nonexistent", signerParams = mapOf("key1" to "val1", "key2" to "val2"))
        every { registry.getSigners() } returns mapOf("other" to otherSigner)

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "signerId", "Missing or disabled signer: nonexistent")
        assertHasError(xmlResponse, "signerError_nonexistent_key1", "Cannot save settings of missing or disabled signer")
        assertHasError(xmlResponse, "signerError_nonexistent_key2", "Cannot save settings of missing or disabled signer")
        // One error per submitted field plus the signerId error, nothing silently dropped.
        Assertions.assertThat(getErrors(xmlResponse).keys)
            .containsExactlyInAnyOrder("signerId", "signerError_nonexistent_key1", "signerError_nonexistent_key2")
        verifyNoSettingsSaved()
    }

    @Test
    fun doPost_disabledSigner_withFields_errorPerField() {
        // A disabled signer is represented the same way as a missing one: absent from registry.getSigners().
        val enabledSigner = mockSigner("enabled")
        stubRequestWithSigner(signerId = "disabled", signerParams = mapOf("region" to "us", "keyId" to "abc"))
        every { registry.getSigners() } returns mapOf("enabled" to enabledSigner)

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "signerId", "Missing or disabled signer: disabled")
        assertHasError(xmlResponse, "signerError_disabled_region", "Cannot save settings of missing or disabled signer")
        assertHasError(xmlResponse, "signerError_disabled_keyId", "Cannot save settings of missing or disabled signer")
        Assertions.assertThat(getErrors(xmlResponse).keys)
            .containsExactlyInAnyOrder("signerId", "signerError_disabled_region", "signerError_disabled_keyId")
        verifyNoSettingsSaved()
    }

    /*
     * Issuer validation checks
     */
    @Test
    fun doPost_issuerWithoutHttps_returnsIssuerError() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns emptyMap()
            every { saveSettings(any()) } returns emptyMap()
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner", issuer = "http://example.com")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "issuer", "https://")
        verifyNoSettingsSaved()
    }

    @Test
    fun doPost_emptyIssuer_accepted() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns emptyMap()
            every { saveSettings(any()) } returns emptyMap()
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner", issuer = "")
        every { settings.updateSettings(any(), anyNullable()) } just Runs

        controller.doPost(request, response, xmlResponse)

        assertNoErrors(xmlResponse)
        verify { settings.updateSettings(eq("mySigner"), isNull()) }
    }

    /*
     * Signer settings validation tests
     */
    @Test
    fun doPost_validSigner_callsValidateSettings() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns emptyMap()
            every { saveSettings(any()) } returns emptyMap()
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner", signerParams = mapOf("key1" to "val1", "key2" to "val2"))
        every { settings.updateSettings(any(), anyNullable()) } just Runs

        controller.doPost(request, response, xmlResponse)

        val slot = slot<Map<String, String>>()
        verify { adminSettings.validateSettings(capture(slot)) }
        Assertions.assertThat(slot.captured).isEqualTo(mapOf("key1" to "val1", "key2" to "val2"))
    }

    @Test
    fun doPost_validateSettingsThrows_errorAdded() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } throws RuntimeException("boom")
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "signerId", "Failed to validate signer settings")
        assertHasError(xmlResponse, "signerId", "RuntimeException")
        assertHasError(xmlResponse, "signerId", "boom")
        verifyNoSettingsSaved()
    }

    @Test
    fun doPost_validateSettingsReturnsErrors_errorsInProperFormat() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns mapOf("field1" to "bad value")
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "signerError_mySigner_field1", "bad value")
    }

    @Test
    fun doPost_validateSettingsReturnsErrors_noSettingsSaved() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns mapOf("field1" to "bad value")
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner")

        controller.doPost(request, response, xmlResponse)

        verify(exactly = 0) { adminSettings.saveSettings(any()) }
        verifyNoSettingsSaved()
    }

    /*
     * Signer settings save tests
     */
    @Test
    fun doPost_validateAndSaveReceiveSameMapInstance() {
        val validateSlot = slot<Map<String, String>>()
        val saveSlot = slot<Map<String, String>>()
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns emptyMap()
            every { saveSettings(any()) } returns emptyMap()
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner", signerParams = mapOf("k" to "v"))
        every { settings.updateSettings(any(), anyNullable()) } just Runs

        controller.doPost(request, response, xmlResponse)

        verify { adminSettings.validateSettings(capture(validateSlot)) }
        verify { adminSettings.saveSettings(capture(saveSlot)) }
        Assertions.assertThat(validateSlot.captured).isSameAs(saveSlot.captured)
    }

    @Test
    fun doPost_saveSettingsReturnsErrors_errorsInResponse() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns emptyMap()
            every { saveSettings(any()) } returns mapOf("field2" to "save failed")
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "signerError_mySigner_field2", "save failed")
    }

    @Test
    fun doPost_saveSettingsReturnsErrors_noGeneralSettingsSaved() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns emptyMap()
            every { saveSettings(any()) } returns mapOf("field2" to "save failed")
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner")

        controller.doPost(request, response, xmlResponse)

        verifyNoSettingsSaved()
    }

    @Test
    fun doPost_saveSettingsThrows_errorAdded() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns emptyMap()
            every { saveSettings(any()) } throws RuntimeException("save boom")
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "signerId", "Failed to save signer settings")
        assertHasError(xmlResponse, "signerId", "RuntimeException")
        assertHasError(xmlResponse, "signerId", "save boom")
        verifyNoSettingsSaved()
    }

    /*
     * Happy path
     */
    @Test
    fun doPost_allValid_savesSettings() {
        val adminSettings: JWTSignerAdminSettings = mockk {
            every { validateSettings(any()) } returns emptyMap()
            every { saveSettings(any()) } returns emptyMap()
        }
        val signer = mockSigner("mySigner", adminSettings)
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner", issuer = "https://example.com")
        every { settings.updateSettings(any(), anyNullable()) } just Runs

        controller.doPost(request, response, xmlResponse)

        assertNoErrors(xmlResponse)
        verify { settings.updateSettings("mySigner", "https://example.com") }
    }

    /*
     * Signer without admin settings
     */
    @Test
    fun doPost_signerWithoutAdminSettings_savesSuccessfully() {
        val signer = mockSigner("mySigner")
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner", issuer = "https://example.com")
        every { settings.updateSettings(any(), anyNullable()) } just Runs

        controller.doPost(request, response, xmlResponse)

        assertNoErrors(xmlResponse)
        verify { settings.updateSettings("mySigner", "https://example.com") }
    }

    @Test
    fun doPost_signerWithoutAdminSettings_emptyIssuer_savesSuccessfully() {
        val signer = mockSigner("mySigner")
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner", issuer = "")
        every { settings.updateSettings(any(), anyNullable()) } just Runs

        controller.doPost(request, response, xmlResponse)

        assertNoErrors(xmlResponse)
        verify { settings.updateSettings(eq("mySigner"), isNull()) }
    }

    @Test
    fun doPost_signerWithoutAdminSettings_invalidIssuer_returnsError() {
        val signer = mockSigner("mySigner")
        every { registry.getSigners() } returns mapOf("mySigner" to signer)
        stubRequestWithSigner(signerId = "mySigner", issuer = "http://example.com")

        controller.doPost(request, response, xmlResponse)

        assertHasError(xmlResponse, "issuer", "https://")
        verifyNoSettingsSaved()
    }
}
