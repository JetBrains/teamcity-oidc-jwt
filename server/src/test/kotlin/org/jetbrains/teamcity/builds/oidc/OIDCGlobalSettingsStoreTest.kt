package org.jetbrains.teamcity.builds.oidc

import io.mockk.*
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

class OIDCGlobalSettingsStoreTest : BaseTestCase() {

    private lateinit var tempDir: Path
    private lateinit var configFile: File

    private lateinit var serverPaths: ServerPaths
    private lateinit var fileWatcher: FileWatcher
    private lateinit var fileWatcherFactory: FileWatcherFactory
    private lateinit var settingsPersister: SettingsPersister

    private var capturedListener: ChangeListener? = null
    private var store: OIDCGlobalSettingsStore? = null

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        tempDir = Files.createTempDirectory("OIDCGlobalSettingsStoreTest-")
        configFile = File(tempDir.toFile(), OIDCConstants.Settings.FILE_NAME)
        capturedListener = null

        serverPaths = mockk { every { configDir } returns tempDir.toString() }

        fileWatcher = mockk(relaxed = true)
        every { fileWatcher.registerListener(any()) } answers { invocation ->
            capturedListener = invocation.invocation.args[0] as ChangeListener
        }
        every { fileWatcher.unregisterListener(any()) } returns Unit

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

    private fun createStore(): OIDCGlobalSettingsStore =
        OIDCGlobalSettingsStore(serverPaths, fileWatcherFactory, settingsPersister).also { store = it }

    @Test
    fun init_missingFile_returnsDefaults() {
        val store = createStore()
        Assertions.assertThat(store.get()).isEqualTo(OIDCGlobalSettings())
    }

    @Test
    fun init_existingFile_readsValues() {
        configFile.writeText(
            """<?xml version="1.0" encoding="UTF-8"?>
               <oidc-jwt-settings version="1" activeSignerId="builtin-ecdsa">
                 <issuer>https://issuer.example.com</issuer>
               </oidc-jwt-settings>""".trimIndent()
        )

        val store = createStore()

        Assertions.assertThat(store.get()).isEqualTo(
            OIDCGlobalSettings(activeSignerId = "builtin-ecdsa", overrideIssuer = "https://issuer.example.com")
        )
    }

    @Test
    fun init_emptyFile_returnsDefaults() {
        configFile.writeText("")
        val store = createStore()
        Assertions.assertThat(store.get()).isEqualTo(OIDCGlobalSettings())
        clearFailure()
    }

    @Test
    fun init_malformedXml_returnsDefaults() {
        configFile.writeText("not valid xml <<<>>>")
        val store = createStore()
        Assertions.assertThat(store.get()).isEqualTo(OIDCGlobalSettings())
        clearFailure()
    }

    @Test
    fun init_wrongRootElement_returnsDefaults() {
        configFile.writeText("""<?xml version="1.0"?><something-else version="1" activeSignerId="x"/>""")
        val store = createStore()
        Assertions.assertThat(store.get()).isEqualTo(OIDCGlobalSettings())
    }

    @Test
    fun init_missingActiveSignerAttribute_fillsDefault() {
        configFile.writeText("""<?xml version="1.0"?><oidc-jwt-settings version="1"/>""")
        val store = createStore()
        Assertions.assertThat(store.get().activeSignerId).isEqualTo(OIDCConstants.BuiltInRSASigner.ID)
    }

    @Test
    fun init_blankActiveSignerAttribute_fillsDefault() {
        configFile.writeText("""<?xml version="1.0"?><oidc-jwt-settings version="1" activeSignerId="   "/>""")
        val store = createStore()
        Assertions.assertThat(store.get().activeSignerId).isEqualTo(OIDCConstants.BuiltInRSASigner.ID)
    }

    @Test
    fun init_startsWatcher() {
        createStore()
        verify(exactly = 1) { fileWatcher.start() }
    }

    @Test
    fun init_registersListener() {
        createStore()
        Assertions.assertThat(capturedListener).isNotNull()
    }

    @Test
    fun save_setsInMemorySnapshotImmediately() {
        val store = createStore()
        val newSettings = OIDCGlobalSettings(activeSignerId = "builtin-ecdsa", overrideIssuer = "https://x.example.com")

        store.save(newSettings)

        Assertions.assertThat(store.get()).isEqualTo(newSettings)
    }

    @Test
    fun save_writesFile() {
        val store = createStore()
        val newSettings = OIDCGlobalSettings(activeSignerId = "builtin-ecdsa", overrideIssuer = "https://x.example.com")

        store.save(newSettings)

        Assertions.assertThat(configFile).exists()
        val content = configFile.readText()
        Assertions.assertThat(content).contains("oidc-jwt-settings")
        Assertions.assertThat(content).contains("""activeSignerId="builtin-ecdsa"""")
        Assertions.assertThat(content).contains("https://x.example.com")
    }

    @Test
    fun save_emptyOverrideIssuer_omitsIssuerChild() {
        val store = createStore()
        store.save(OIDCGlobalSettings(activeSignerId = "builtin-rsa", overrideIssuer = ""))

        Assertions.assertThat(configFile.readText()).doesNotContain("<issuer>")
    }

    @Test
    fun save_writtenFileRoundTrips() {
        val first = createStore()
        val newSettings = OIDCGlobalSettings(activeSignerId = "builtin-ecdsa", overrideIssuer = "https://x.example.com")
        first.save(newSettings)
        first.destroy()
        store = null

        val second = createStore()
        Assertions.assertThat(second.get()).isEqualTo(newSettings)
    }

    @Test
    fun save_includesVersionAttribute() {
        val store = createStore()
        store.save(OIDCGlobalSettings(activeSignerId = "x"))
        Assertions.assertThat(configFile.readText()).contains("""version="1"""")
    }

    @Test
    fun save_firesUpdateHandlersLocally() {
        val store = createStore()
        var fired = false
        store.registerUpdateHandler { fired = true }

        store.save(OIDCGlobalSettings(activeSignerId = "x"))

        Assertions.assertThat(fired).isTrue()
    }

    @Test
    fun watcherListener_reReadsFromDisk() {
        val store = createStore()
        Assertions.assertThat(store.get().activeSignerId).isEqualTo(OIDCConstants.BuiltInRSASigner.ID)

        // Write file directly, simulating another node's update
        configFile.writeText(
            """<?xml version="1.0"?>
               <oidc-jwt-settings version="1" activeSignerId="builtin-ecdsa">
                 <issuer>https://other.example.com</issuer>
               </oidc-jwt-settings>""".trimIndent()
        )

        capturedListener!!.changeOccured("test")

        Assertions.assertThat(store.get()).isEqualTo(
            OIDCGlobalSettings(activeSignerId = "builtin-ecdsa", overrideIssuer = "https://other.example.com")
        )
    }

    @Test
    fun watcherListener_firesUpdateHandlers() {
        val store = createStore()
        var fired = 0
        store.registerUpdateHandler { fired++ }

        capturedListener!!.changeOccured("test")

        Assertions.assertThat(fired).isEqualTo(1)
    }

    @Test
    fun watcherListener_handlerThatThrows_doesNotStopOtherHandlers() {
        val store = createStore()
        var secondCalled = false
        store.registerUpdateHandler { throw RuntimeException("boom") }
        store.registerUpdateHandler { secondCalled = true }

        capturedListener!!.changeOccured("test")

        Assertions.assertThat(secondCalled).isTrue()
        clearFailure()
    }

    @Test
    fun destroy_stopsAndClearsWatcher() {
        val s = createStore()
        s.destroy()
        store = null

        verify(exactly = 1) { fileWatcher.stop() }
        verify(exactly = 1) { fileWatcher.clear() }
    }

    @Test
    fun save_waitForDisk_waitsForTaskAndChecksError() {
        val task = mockk<PersistTask>(relaxed = true) {
            every { error } returns null
        }
        every { settingsPersister.scheduleSaveDocument(any(), any<FileWatcher>(), any<Document>()) } answers { invocation ->
            val document = invocation.invocation.args[2] as Document
            FileOutputStream(configFile).use { out -> XMLOutputter().output(document, out) }
            task
        }

        val store = createStore()
        store.save(OIDCGlobalSettings(activeSignerId = "x"), waitForDisk = true)

        verify { task.awaitUninterruptibly() }
        verify { task.error }
    }

    @Test
    fun save_waitForDisk_throwsWhenTaskHasError() {
        val task = mockk<PersistTask>(relaxed = true) {
            every { error } returns RuntimeException("disk failure")
        }
        every { settingsPersister.scheduleSaveDocument(any(), any<FileWatcher>(), any<Document>()) } returns task

        val store = createStore()
        Assertions.assertThatThrownBy {
            store.save(OIDCGlobalSettings(activeSignerId = "x"), waitForDisk = true)
        }.isInstanceOf(IllegalStateException::class.java)
            .hasMessageContaining(OIDCConstants.Settings.FILE_NAME)
    }

    @Test
    fun destroy_properlyClosesFileWatcher() {
        val store = createStore()

        store.destroy()
        verify(ordering = Ordering.ORDERED) {
            fileWatcher.unregisterListener(store)
            fileWatcher.stop()
            fileWatcher.clear()
        }
    }
}
