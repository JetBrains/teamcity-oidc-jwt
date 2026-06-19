package org.jetbrains.teamcity.builds.oidc.signer.gcp

import io.mockk.*
import jetbrains.buildServer.BaseTestCase
import jetbrains.buildServer.configuration.ChangeListener
import jetbrains.buildServer.configuration.FileWatcher
import jetbrains.buildServer.serverSide.PersistTask
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.SettingsPersister
import jetbrains.buildServer.serverSide.crypt.Encryption
import jetbrains.buildServer.serverSide.impl.FileWatcherFactory
import org.assertj.core.api.Assertions
import org.jdom.Document
import org.jdom.output.XMLOutputter
import org.jetbrains.teamcity.builds.oidc.signer.gcp.client.GCPCredentials
import org.testng.annotations.AfterMethod
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator

class CloudKMSSettingsTest : BaseTestCase() {

    private lateinit var tempDir: Path
    private lateinit var configFile: File

    private lateinit var serverPaths: ServerPaths
    private lateinit var fileWatcher: FileWatcher
    private lateinit var fileWatcherFactory: FileWatcherFactory
    private lateinit var settingsPersister: SettingsPersister
    private lateinit var encryption: Encryption

    private var capturedListener: ChangeListener? = null
    private var settings: CloudKMSSettings? = null

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        tempDir = Files.createTempDirectory("CloudKMSSettingsTest-")
        configFile = File(tempDir.toFile(), CloudKMSConstants.Settings.FILE_NAME)
        capturedListener = null

        serverPaths = mockk { every { configDir } returns tempDir.toString() }

        fileWatcher = mockk(relaxed = true)
        every { fileWatcher.registerListener(any()) } answers { invocation ->
            capturedListener = invocation.invocation.args[0] as ChangeListener
            Unit
        }

        fileWatcherFactory = mockk()
        every { fileWatcherFactory.createFileWatcher(any()) } returns fileWatcher

        settingsPersister = mockk()
        every { settingsPersister.scheduleSaveDocument(any(), any<FileWatcher>(), any<Document>()) } answers { invocation ->
            val document = invocation.invocation.args[2] as Document
            FileOutputStream(configFile).use { out -> XMLOutputter().output(document, out) }
            mockk<PersistTask>(relaxed = true)
        }

        encryption = mockk {
            every { encrypt(any()) } answers { invocation -> "enc:" + (invocation.invocation.args[0] as String) }
            every { decrypt(any()) } answers { invocation -> (invocation.invocation.args[0] as String).removePrefix("enc:") }
        }
    }

    @AfterMethod
    override fun tearDown() {
        try {
            settings?.destroy()
            try {
                Files.walk(tempDir)
                    .sorted(Comparator.reverseOrder())
                    .forEach { Files.deleteIfExists(it) }
            } catch (_: Exception) {
            }
        } finally {
            super.tearDown()
        }
    }

    private fun createSettings(): CloudKMSSettings =
        CloudKMSSettings(serverPaths, fileWatcherFactory, settingsPersister, encryption).also { settings = it }

    // --- init / file read ---

    @Test
    fun init_missingFile_returnsDefaults() {
        val s = createSettings()
        Assertions.assertThat(s.getCredentials()).isEqualTo(GCPCredentials.Environment(null))
        Assertions.assertThat(s.getKeyResourceName()).isNull()
        Assertions.assertThat(s.getGCPEndpoint()).isNull()
    }

    @Test
    fun init_existingFile_readsServiceAccountValues() {
        configFile.writeText(
            """<?xml version="1.0"?>
               <oidc-jwt-gcp-kms-settings version="1" credentialsType="SERVICE_ACCOUNT_KEY">
                 <kmsResourceName>projects/p/locations/global/keyRings/r/cryptoKeys/k</kmsResourceName>
                 <impersonationChain>sa@example.com</impersonationChain>
                 <gcpEndpoint>https://kms.example.com</gcpEndpoint>
                 <serviceAccountKey>enc:secret-json</serviceAccountKey>
               </oidc-jwt-gcp-kms-settings>""".trimIndent()
        )

        val s = createSettings()

        Assertions.assertThat(s.getKeyResourceName()).isEqualTo("projects/p/locations/global/keyRings/r/cryptoKeys/k")
        Assertions.assertThat(s.getGCPEndpoint()).isEqualTo("https://kms.example.com")
        Assertions.assertThat(s.getCredentials())
            .isEqualTo(GCPCredentials.ServiceAccount("secret-json", "sa@example.com"))
    }

    @Test
    fun init_existingFile_readsEnvironmentCredentialsWithoutImpersonation() {
        configFile.writeText(
            """<?xml version="1.0"?>
               <oidc-jwt-gcp-kms-settings version="1" credentialsType="ENVIRONMENT"/>""".trimIndent()
        )

        val s = createSettings()
        Assertions.assertThat(s.getCredentials()).isEqualTo(GCPCredentials.Environment(null))
    }

    @Test
    fun init_serviceAccountKeyTypeButKeyMissing_fallsBackToEnvironment() {
        configFile.writeText(
            """<?xml version="1.0"?>
               <oidc-jwt-gcp-kms-settings version="1" credentialsType="SERVICE_ACCOUNT_KEY">
                 <impersonationChain>sa@example.com</impersonationChain>
               </oidc-jwt-gcp-kms-settings>""".trimIndent()
        )

        val s = createSettings()
        Assertions.assertThat(s.getCredentials()).isEqualTo(GCPCredentials.Environment("sa@example.com"))
        verify(exactly = 0) { encryption.decrypt(any()) }
    }

    @Test
    fun init_unknownCredentialsType_fallsBackToEnvironment() {
        configFile.writeText(
            """<?xml version="1.0"?>
               <oidc-jwt-gcp-kms-settings version="1" credentialsType="garbage"/>""".trimIndent()
        )

        val s = createSettings()
        Assertions.assertThat(s.getCredentials()).isEqualTo(GCPCredentials.Environment(null))
    }

    @Test
    fun init_wrongRoot_returnsDefaults() {
        configFile.writeText(
            """<?xml version="1.0"?><something-else version="1" credentialsType="SERVICE_ACCOUNT_KEY"/>""".trimIndent()
        )

        val s = createSettings()
        Assertions.assertThat(s.getCredentials()).isEqualTo(GCPCredentials.Environment(null))
        Assertions.assertThat(s.getKeyResourceName()).isNull()
    }

    @Test
    fun init_malformedXml_returnsDefaults() {
        configFile.writeText("not xml")

        val s = createSettings()
        Assertions.assertThat(s.getCredentials()).isEqualTo(GCPCredentials.Environment(null))
        Assertions.assertThat(s.getKeyResourceName()).isNull()
        Assertions.assertThat(s.getGCPEndpoint()).isNull()
        clearFailure()
    }

    @Test
    fun init_startsWatcher() {
        createSettings()
        verify(exactly = 1) { fileWatcher.start() }
    }

    @Test
    fun init_registersListener() {
        createSettings()
        Assertions.assertThat(capturedListener).isNotNull()
    }

    // --- update / save ---

    @Test
    fun update_setsInMemorySnapshotImmediately() {
        val s = createSettings()

        s.update(
            credentialsType = CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY,
            kmsResourceName = "rn",
            serviceAccountKey = "raw-json",
            impersonationChain = "chain",
            gcpEndpoint = "https://e",
        )

        Assertions.assertThat(s.getKeyResourceName()).isEqualTo("rn")
        Assertions.assertThat(s.getGCPEndpoint()).isEqualTo("https://e")
        Assertions.assertThat(s.getCredentials()).isEqualTo(GCPCredentials.ServiceAccount("raw-json", "chain"))
    }

    @Test
    fun update_writesAttributesAndChildElementsToFile() {
        val s = createSettings()

        s.update(
            credentialsType = CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY,
            kmsResourceName = "rn",
            serviceAccountKey = "raw-json",
            impersonationChain = "chain",
            gcpEndpoint = "https://e",
        )

        val content = configFile.readText()
        Assertions.assertThat(content).contains("oidc-jwt-gcp-kms-settings")
        Assertions.assertThat(content).contains("""version="1"""")
        Assertions.assertThat(content).contains("""credentialsType="SERVICE_ACCOUNT_KEY"""")
        Assertions.assertThat(content).contains("<kmsResourceName>rn</kmsResourceName>")
        Assertions.assertThat(content).contains("<impersonationChain>chain</impersonationChain>")
        Assertions.assertThat(content).contains("<gcpEndpoint>https://e</gcpEndpoint>")
        Assertions.assertThat(content).contains("<serviceAccountKey>enc:raw-json</serviceAccountKey>")
    }

    @Test
    fun update_emptyOptionalFields_omitsChildElements() {
        val s = createSettings()

        s.update(
            credentialsType = CloudKMSConstants.CredentialsType.ENVIRONMENT,
            kmsResourceName = "",
            serviceAccountKey = "",
            impersonationChain = null,
            gcpEndpoint = null,
        )

        val content = configFile.readText()
        Assertions.assertThat(content).doesNotContain("<kmsResourceName")
        Assertions.assertThat(content).doesNotContain("<impersonationChain")
        Assertions.assertThat(content).doesNotContain("<gcpEndpoint")
        Assertions.assertThat(content).doesNotContain("<serviceAccountKey")
    }

    @Test
    fun update_serviceAccountKeyTypeWithBlankKey_preservesExistingEncryptedKey() {
        // Seed an existing encrypted key by writing the file before construction
        configFile.writeText(
            """<?xml version="1.0"?>
               <oidc-jwt-gcp-kms-settings version="1" credentialsType="SERVICE_ACCOUNT_KEY">
                 <serviceAccountKey>enc:original-secret</serviceAccountKey>
               </oidc-jwt-gcp-kms-settings>""".trimIndent()
        )

        val s = createSettings()
        clearMocks(encryption, answers = false)

        s.update(
            credentialsType = CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY,
            kmsResourceName = "rn",
            serviceAccountKey = "   ",
            impersonationChain = null,
            gcpEndpoint = null,
        )

        verify(exactly = 0) { encryption.encrypt(any()) }
        Assertions.assertThat(configFile.readText())
            .contains("<serviceAccountKey>enc:original-secret</serviceAccountKey>")
        // Decryption still resolves to the original secret on read
        Assertions.assertThat(s.getCredentials())
            .isEqualTo(GCPCredentials.ServiceAccount("original-secret", null))
    }

    @Test
    fun update_serviceAccountKeyTypeWithNonBlankKey_writesEncryptedKey() {
        val s = createSettings()

        s.update(
            credentialsType = CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY,
            kmsResourceName = "rn",
            serviceAccountKey = "raw-json",
            impersonationChain = null,
            gcpEndpoint = null,
        )

        verify(exactly = 1) { encryption.encrypt("raw-json") }
        Assertions.assertThat(configFile.readText())
            .contains("<serviceAccountKey>enc:raw-json</serviceAccountKey>")
    }

    @Test
    fun update_nonServiceAccountKeyType_clearsStoredKey() {
        configFile.writeText(
            """<?xml version="1.0"?>
               <oidc-jwt-gcp-kms-settings version="1" credentialsType="SERVICE_ACCOUNT_KEY">
                 <serviceAccountKey>enc:original-secret</serviceAccountKey>
               </oidc-jwt-gcp-kms-settings>""".trimIndent()
        )

        val s = createSettings()
        clearMocks(encryption, answers = false)

        s.update(
            credentialsType = CloudKMSConstants.CredentialsType.ENVIRONMENT,
            kmsResourceName = "rn",
            serviceAccountKey = "ignored",
            impersonationChain = null,
            gcpEndpoint = null,
        )

        verify(exactly = 0) { encryption.encrypt(any()) }
        Assertions.assertThat(configFile.readText()).doesNotContain("<serviceAccountKey")
        Assertions.assertThat(s.getCredentials()).isEqualTo(GCPCredentials.Environment(null))
    }

    @Test
    fun update_writtenFileRoundTrips() {
        val first = createSettings()
        first.update(
            credentialsType = CloudKMSConstants.CredentialsType.SERVICE_ACCOUNT_KEY,
            kmsResourceName = "rn",
            serviceAccountKey = "raw-json",
            impersonationChain = "chain",
            gcpEndpoint = "https://e",
        )
        first.destroy()
        settings = null

        val second = createSettings()
        Assertions.assertThat(second.getKeyResourceName()).isEqualTo("rn")
        Assertions.assertThat(second.getGCPEndpoint()).isEqualTo("https://e")
        Assertions.assertThat(second.getCredentials())
            .isEqualTo(GCPCredentials.ServiceAccount("raw-json", "chain"))
    }

    @Test
    fun update_firesUpdateHandlersLocally() {
        val s = createSettings()
        var fired = false
        s.registerUpdateHandler { fired = true }

        s.update(
            credentialsType = CloudKMSConstants.CredentialsType.ENVIRONMENT,
            kmsResourceName = "rn",
            serviceAccountKey = "",
            impersonationChain = null,
            gcpEndpoint = null,
        )

        Assertions.assertThat(fired).isTrue()
    }

    @Test
    fun update_handlerThatThrows_doesNotStopOtherHandlers() {
        val s = createSettings()
        var firstCalled = false
        var thirdCalled = false
        s.registerUpdateHandler { firstCalled = true }
        s.registerUpdateHandler { throw RuntimeException("boom") }
        s.registerUpdateHandler { thirdCalled = true }

        s.update(
            credentialsType = CloudKMSConstants.CredentialsType.ENVIRONMENT,
            kmsResourceName = "rn",
            serviceAccountKey = "",
            impersonationChain = null,
            gcpEndpoint = null,
        )

        Assertions.assertThat(firstCalled).isTrue()
        Assertions.assertThat(thirdCalled).isTrue()
        clearFailure()
    }

    // --- watcher listener ---

    @Test
    fun watcherListener_reReadsFromDisk() {
        val s = createSettings()

        configFile.writeText(
            """<?xml version="1.0"?>
               <oidc-jwt-gcp-kms-settings version="1" credentialsType="ENVIRONMENT">
                 <kmsResourceName>rn-from-other-node</kmsResourceName>
                 <gcpEndpoint>https://other.example.com</gcpEndpoint>
               </oidc-jwt-gcp-kms-settings>""".trimIndent()
        )

        capturedListener!!.changeOccured("test")

        Assertions.assertThat(s.getKeyResourceName()).isEqualTo("rn-from-other-node")
        Assertions.assertThat(s.getGCPEndpoint()).isEqualTo("https://other.example.com")
    }

    @Test
    fun watcherListener_firesUpdateHandlers() {
        val s = createSettings()
        var fired = 0
        s.registerUpdateHandler { fired++ }

        capturedListener!!.changeOccured("test")

        Assertions.assertThat(fired).isEqualTo(1)
    }

    // --- destroy ---

    @Test
    fun destroy_properlyClosesFileWatcher() {
        val s = createSettings()
        s.destroy()
        settings = null

        verify(ordering = Ordering.ORDERED) {
            fileWatcher.unregisterListener(s)
            fileWatcher.stop()
            fileWatcher.clear()
        }
    }
}
