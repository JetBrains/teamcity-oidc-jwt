package org.jetbrains.teamcity.builds.oidc.signer.builtin

import io.mockk.*
import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import jetbrains.buildServer.BaseTestCase
import jetbrains.buildServer.configuration.ChangeListener
import jetbrains.buildServer.configuration.FileWatcher
import jetbrains.buildServer.serverSide.PersistTask
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.SettingsPersister
import jetbrains.buildServer.serverSide.impl.FileWatcherFactory
import org.assertj.core.api.Assertions
import org.jdom.Document
import org.jdom.output.XMLOutputter
import org.testng.annotations.AfterMethod
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator

class BuiltInRSASettingsStoreTest : BaseTestCase() {

    private lateinit var tempDir: Path
    private lateinit var configFile: File

    private lateinit var serverPaths: ServerPaths
    private lateinit var fileWatcher: FileWatcher
    private lateinit var fileWatcherFactory: FileWatcherFactory
    private lateinit var settingsPersister: SettingsPersister

    private var capturedListener: ChangeListener? = null
    private var store: BuiltInRSASettingsStore? = null

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        tempDir = Files.createTempDirectory("BuiltInRSASettingsStoreTest-")
        configFile = File(tempDir.toFile(), OIDCConstants.BuiltInRSASigner.SETTINGS_FILE_NAME)
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
    }

    @AfterMethod
    override fun tearDown() {
        try {
            store?.destroy()
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

    private fun createStore(): BuiltInRSASettingsStore =
        BuiltInRSASettingsStore(serverPaths, fileWatcherFactory, settingsPersister).also { store = it }

    @Test
    fun init_missingFile_returnsDefaults() {
        val store = createStore()
        Assertions.assertThat(store.get()).isEqualTo(BuiltInRSASettings())
    }

    @Test
    fun init_existingFile_readsValues() {
        configFile.writeText(
            """<?xml version="1.0"?><oidc-jwt-builtin-rsa-settings version="1" jwsAlgorithm="PS512" rsaKeyBits="4096"/>"""
        )
        val store = createStore()
        Assertions.assertThat(store.get()).isEqualTo(BuiltInRSASettings(jwsAlgorithm = "PS512", rsaKeyBits = 4096))
    }

    @Test
    fun init_invalidAlgorithm_fallsBackToDefault() {
        configFile.writeText(
            """<?xml version="1.0"?><oidc-jwt-builtin-rsa-settings version="1" jwsAlgorithm="garbage" rsaKeyBits="3072"/>"""
        )
        val store = createStore()
        Assertions.assertThat(store.get().jwsAlgorithm).isEqualTo("RS256")
    }

    @Test
    fun init_disallowedKeyBits_fallsBackToDefault() {
        configFile.writeText(
            """<?xml version="1.0"?><oidc-jwt-builtin-rsa-settings version="1" jwsAlgorithm="RS256" rsaKeyBits="1024"/>"""
        )
        val store = createStore()
        Assertions.assertThat(store.get().rsaKeyBits).isEqualTo(3072)
    }

    @Test
    fun init_nonNumericKeyBits_fallsBackToDefault() {
        configFile.writeText(
            """<?xml version="1.0"?><oidc-jwt-builtin-rsa-settings version="1" jwsAlgorithm="RS256" rsaKeyBits="abc"/>"""
        )
        val store = createStore()
        Assertions.assertThat(store.get().rsaKeyBits).isEqualTo(3072)
    }

    @Test
    fun init_wrongRoot_returnsDefaults() {
        configFile.writeText(
            """<?xml version="1.0"?><something-else version="1" jwsAlgorithm="RS512" rsaKeyBits="4096"/>"""
        )
        val store = createStore()
        Assertions.assertThat(store.get()).isEqualTo(BuiltInRSASettings())
    }

    @Test
    fun init_malformedXml_returnsDefaults() {
        configFile.writeText("not xml")
        val store = createStore()
        Assertions.assertThat(store.get()).isEqualTo(BuiltInRSASettings())
        clearFailure()
    }

    @Test
    fun save_setsInMemorySnapshotImmediately() {
        val store = createStore()
        val newSettings = BuiltInRSASettings(jwsAlgorithm = "RS512", rsaKeyBits = 4096)

        store.save(newSettings)

        Assertions.assertThat(store.get()).isEqualTo(newSettings)
    }

    @Test
    fun save_writesAttributesToFile() {
        val store = createStore()
        store.save(BuiltInRSASettings(jwsAlgorithm = "PS384", rsaKeyBits = 2048))

        val content = configFile.readText()
        Assertions.assertThat(content).contains("oidc-jwt-builtin-rsa-settings")
        Assertions.assertThat(content).contains("""jwsAlgorithm="PS384"""")
        Assertions.assertThat(content).contains("""rsaKeyBits="2048"""")
        Assertions.assertThat(content).contains("""version="1"""")
    }

    @Test
    fun save_writtenFileRoundTrips() {
        val first = createStore()
        val newSettings = BuiltInRSASettings(jwsAlgorithm = "RS512", rsaKeyBits = 4096)
        first.save(newSettings)
        first.destroy()
        store = null

        val second = createStore()
        Assertions.assertThat(second.get()).isEqualTo(newSettings)
    }

    @Test
    fun save_firesUpdateHandlersLocally() {
        val store = createStore()
        var fired = false
        store.registerUpdateHandler { fired = true }

        store.save(BuiltInRSASettings(jwsAlgorithm = "RS512", rsaKeyBits = 4096))

        Assertions.assertThat(fired).isTrue()
    }

    @Test
    fun watcherListener_reReadsFromDisk() {
        val store = createStore()
        configFile.writeText(
            """<?xml version="1.0"?><oidc-jwt-builtin-rsa-settings version="1" jwsAlgorithm="RS384" rsaKeyBits="4096"/>"""
        )
        capturedListener!!.changeOccured("test")

        Assertions.assertThat(store.get()).isEqualTo(BuiltInRSASettings(jwsAlgorithm = "RS384", rsaKeyBits = 4096))
    }

    @Test
    fun init_startsWatcher() {
        createStore()
        verify(exactly = 1) { fileWatcher.start() }
    }

    @Test
    fun destroy_properlyClosesFileWatcher() {
        val s = createStore()
        s.destroy()
        store = null

        verify(ordering = Ordering.ORDERED) {
            fileWatcher.unregisterListener(s)
            fileWatcher.stop()
            fileWatcher.clear()
        }
    }
}
