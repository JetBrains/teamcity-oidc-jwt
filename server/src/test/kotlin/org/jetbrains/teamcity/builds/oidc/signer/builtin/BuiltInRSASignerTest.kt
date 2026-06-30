package org.jetbrains.teamcity.builds.oidc.signer.builtin

import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import jetbrains.buildServer.serverSide.MultiNodeTasks
import jetbrains.buildServer.serverSide.SBuild
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.ServerResponsibility
import jetbrains.buildServer.serverSide.TeamCityNodes
import jetbrains.buildServer.serverSide.auth.Permission
import jetbrains.buildServer.serverSide.crypt.Encryption
import jetbrains.buildServer.web.openapi.PluginDescriptor
import jetbrains.buildServer.web.openapi.WebControllerManager
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.AfterMethod
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test
import io.mockk.*
import org.jetbrains.teamcity.builds.oidc.api.JWKCache
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.Comparator

class BuiltInRSASignerTest : BaseTestCase() {

    private lateinit var tempDir: Path

    private lateinit var controllerManager: WebControllerManager
    private lateinit var encryption: Encryption
    private lateinit var pluginDescriptor: PluginDescriptor
    private lateinit var settingsStore: BuiltInRSASettingsStore
    private lateinit var jwkCache: JWKCache
    private lateinit var serverPaths: ServerPaths
    private lateinit var serverResponsibility: ServerResponsibility
    private lateinit var teamCityNodes: TeamCityNodes
    private lateinit var multiNodeTasks: MultiNodeTasks
    private var currentSettings = BuiltInRSASettings()
    private val settingsUpdateHandlers = mutableListOf<() -> Unit>()
    private var signer: BuiltInRSASigner? = null

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        tempDir = Files.createTempDirectory("BuiltInRSASignerTest-")
        currentSettings = BuiltInRSASettings()
        settingsUpdateHandlers.clear()

        controllerManager = mockk(relaxed = true)

        encryption = mockk {
            every { encrypt(any()) } answers { invocation -> invocation.invocation.args[0] as String }
            every { decrypt(any()) } answers { invocation -> invocation.invocation.args[0] as String }
        }

        pluginDescriptor = mockk {
            every { getPluginResourcesPath(any()) } answers { invocation -> "/plugins/oidc-jwt/${invocation.invocation.args[0]}" }
        }

        settingsStore = mockk()
        every { settingsStore.get() } answers { currentSettings }
        every { settingsStore.save(any(), any()) } answers { invocation ->
            currentSettings = invocation.invocation.args[0] as BuiltInRSASettings
            settingsUpdateHandlers.toList().forEach { it() }
            Unit
        }
        every { settingsStore.registerUpdateHandler(any()) } answers { invocation ->
            @Suppress("UNCHECKED_CAST")
            settingsUpdateHandlers.add(invocation.invocation.args[0] as () -> Unit)
            Unit
        }

        jwkCache = mockk<JWKCache> {
            every { fetchCachedJWKs() } returns emptyMap()
            every { trackKey(any(), any(), any()) } returns Unit
            every { purge() } returns Unit
        }

        serverPaths = mockk {
            every { pluginDataDirectory } returns tempDir.resolve("pluginData").toFile()
        }

        serverResponsibility = mockk {
            every { canManageBuilds() } returns true
        }

        teamCityNodes = mockk {
            every { currentNode.id } returns "test-node-1"
        }

        multiNodeTasks = mockk(relaxed = true)
    }

    @AfterMethod
    override fun tearDown() {
        try {
            signer?.destroy()
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

    private fun createSigner(): BuiltInRSASigner {
        val s = BuiltInRSASigner(
            controllerManager,
            teamCityNodes,
            serverResponsibility,
            serverPaths,
            encryption,
            pluginDescriptor,
            multiNodeTasks,
            settingsStore,
            jwkCache
        )
        signer = s
        return s
    }

    private fun captureRotationConsumer(): MultiNodeTasks.TaskConsumer {
        val slot = slot<MultiNodeTasks.TaskConsumer>()
        verify { multiNodeTasks.subscribeOnSingletonTask(any(), capture(slot)) }
        return slot.captured
    }

    private fun rotationTask(keyID: String): MultiNodeTasks.PerformingTask =
        mockk(relaxed = true) { every { identity } returns "$keyID@test-rotation" }

    private fun driveRotationTask(consumer: MultiNodeTasks.TaskConsumer, keyID: String) {
        // Honor the framework contract: accept() runs only if beforeAccept() is true.
        val task = rotationTask(keyID)
        if (consumer.beforeAccept(task)) consumer.accept(task)
    }

    private fun makeSimpleJWT(target: BuiltInRSASigner): String {
        return target.makeJWT(
            mockk<SBuild>(),
            """{"sub":"test","iss":"https://example.com"}""".toByteArray(),
            Instant.now().plusSeconds(300)
        )
    }

    private fun parseJWT(jwt: String): JWSObject = JWSObject.parse(jwt)

    private fun extractPublicKey(target: BuiltInRSASigner): RSAKey =
        JWKSet.parse(target.getJWKS()).keys[0] as RSAKey

    private fun keyFilePath(): Path =
        tempDir.resolve("pluginData").resolve("oidc-jwt").resolve("rsa").resolve("private.key")

    private fun listKeyDirFiles(): List<Path> {
        val keyDir = tempDir.resolve("pluginData").resolve("oidc-jwt").resolve("rsa")
        return if (Files.exists(keyDir)) Files.list(keyDir).use { it.toList() } else emptyList()
    }

    private fun generateTestKey(bits: Int = 2048): RSAKey {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()
        return RSAKey.Builder(kp.public as RSAPublicKey)
            .privateKey(kp.private as RSAPrivateKey)
            .keyIDFromThumbprint()
            .build()
    }

    /*
     * Key Generation
     */

    @Test
    fun makeJWT_generatesRSAKeyWithDefaultSize() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        val pubKey = extractPublicKey(signer)
        Assertions.assertThat(pubKey.toRSAPublicKey().modulus.bitLength()).isEqualTo(3072)
    }

    @Test
    fun makeJWT_generatesRSAKeyWithConfiguredSize() {
        currentSettings = currentSettings.copy(rsaKeyBits = 4096)
        val signer = createSigner()
        makeSimpleJWT(signer)

        val pubKey = extractPublicKey(signer)
        Assertions.assertThat(pubKey.toRSAPublicKey().modulus.bitLength()).isEqualTo(4096)
    }

    @Test
    fun makeJWT_generatesRSAKeyWith2048Bits() {
        currentSettings = currentSettings.copy(rsaKeyBits = 2048)
        val signer = createSigner()
        makeSimpleJWT(signer)

        val pubKey = extractPublicKey(signer)
        Assertions.assertThat(pubKey.toRSAPublicKey().modulus.bitLength()).isEqualTo(2048)
    }

    /*
     * getConfiguredKeyBits
     */

    @Test
    fun getConfiguredKeyBits_returnsDefaultWhenNoSettingStored() {
        val signer = createSigner()
        Assertions.assertThat(signer.getConfiguredKeyBits()).isEqualTo(3072)
    }

    @Test
    fun getConfiguredKeyBits_returnsStoredValue() {
        currentSettings = currentSettings.copy(rsaKeyBits = 4096)
        val signer = createSigner()
        Assertions.assertThat(signer.getConfiguredKeyBits()).isEqualTo(4096)
    }

    /*
     * Key Persistence
     */

    @Test
    fun makeJWT_savesKeyToExpectedPath() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        Assertions.assertThat(Files.exists(keyFilePath())).isTrue()
    }

    @Test
    fun makeJWT_savedKeyIsEncrypted() {
        every { encryption.encrypt(any()) } answers { invocation -> "ENC:" + invocation.invocation.args[0] }
        every { encryption.decrypt(any()) } answers { invocation -> (invocation.invocation.args[0] as String).removePrefix("ENC:") }

        val signer = createSigner()
        makeSimpleJWT(signer)

        val fileContent = Files.readString(keyFilePath())
        Assertions.assertThat(fileContent).startsWith("ENC:")
        val decrypted = fileContent.removePrefix("ENC:")
        Assertions.assertThat(RSAKey.parse(decrypted)).isNotNull()
    }

    @Test
    fun makeJWT_secondCallReturnsSameKeyId() {
        val signer = createSigner()
        val kid1 = parseJWT(makeSimpleJWT(signer)).header.keyID
        val kid2 = parseJWT(makeSimpleJWT(signer)).header.keyID
        Assertions.assertThat(kid1).isEqualTo(kid2)
    }

    @Test
    fun getJWKS_afterMakeJWT_returnsSameKeyId() {
        val signer = createSigner()
        val jwtKid = parseJWT(makeSimpleJWT(signer)).header.keyID
        val jwksKid = extractPublicKey(signer).keyID
        Assertions.assertThat(jwtKid).isEqualTo(jwksKid)
    }

    @Test
    fun getJWKS_returnsOnlyPublicKey() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        val jwksJson = signer.getJWKS()
        val key = JWKSet.parse(jwksJson).keys[0].toJSONObject()

        Assertions.assertThat(key["d"]).isNull()
        Assertions.assertThat(key["p"]).isNull()
        Assertions.assertThat(key["q"]).isNull()
        Assertions.assertThat(key["dp"]).isNull()
        Assertions.assertThat(key["dq"]).isNull()
        Assertions.assertThat(key["qi"]).isNull()
    }

    /*
     * makeJWT Behavior
     */

    @Test
    fun makeJWT_producesValidSignedJWT() {
        val signer = createSigner()
        val jwt = makeSimpleJWT(signer)
        val jws = parseJWT(jwt)
        val pubKey = extractPublicKey(signer)

        Assertions.assertThat(jws.verify(RSASSAVerifier(pubKey))).isTrue()
    }

    @Test
    fun makeJWT_setsRS256AlgorithmInHeader() {
        val signer = createSigner()
        val jws = parseJWT(makeSimpleJWT(signer))
        Assertions.assertThat(jws.header.algorithm.name).isEqualTo("RS256")
    }

    @Test
    fun makeJWT_setsKeyIdInHeader() {
        val signer = createSigner()
        val jws = parseJWT(makeSimpleJWT(signer))
        Assertions.assertThat(jws.header.keyID).isNotNull()
        Assertions.assertThat(jws.header.keyID).isNotEmpty()
    }

    @Test
    fun makeJWT_preservesClaimsExactly() {
        // NOTE: makeJWT accepts an expiresAt parameter but does not use it.
        // The BuiltInRSASigner signs whatever claims are provided without
        // injecting or modifying the expiration.
        val claims = """{"sub":"test","iss":"https://example.com"}"""
        val signer = createSigner()
        val jwt = signer.makeJWT(mockk<SBuild>(), claims.toByteArray(), Instant.now().plusSeconds(300),)
        val jws = parseJWT(jwt)
        Assertions.assertThat(jws.payload.toString()).isEqualTo(claims)
    }

    @Test
    fun makeJWT_wrapsGenericExceptionInJWTSignerException() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate and cache a full key

        // Replace cache with a public-only key so RSASSASigner fails
        val publicOnly = extractPublicKey(signer)
        signer.cachedKey = publicOnly

        val ex = Assertions.catchThrowableOfType(
            { makeSimpleJWT(signer) },
            JWTSignerException::class.java
        )
        Assertions.assertThat(ex.message).contains("com.nimbusds.jose.JOSEException: The RSA JWK doesn't contain a private part")
    }

    @Test
    fun makeJWT_rethrowsJWTSignerExceptionFromGetKey() {
        val signer = createSigner()
        makeSimpleJWT(signer) // populate key file

        // Corrupt the key file and clear cache so getKey tries to loadKey
        Files.writeString(keyFilePath(), "corrupt data")
        every { encryption.decrypt("corrupt data") } throws RuntimeException("decryption failed")
        signer.cachedKey = null

        val ex = Assertions.catchThrowableOfType(
            { makeSimpleJWT(signer) },
            JWTSignerException::class.java
        )
        Assertions.assertThat(ex.message).contains("Failed to load or generate signing key")
        Assertions.assertThat(ex.cause).isInstanceOf(RuntimeException::class.java)
    }

    /*
     * getJWKS Behavior
     */

    @Test
    fun getJWKS_returnsValidJWKSJSON() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        val jwks = JWKSet.parse(signer.getJWKS())
        Assertions.assertThat(jwks.keys).hasSize(1)
        Assertions.assertThat(jwks.keys[0].keyType.value).isEqualTo("RSA")
    }

    @Test
    fun getJWKS_doesNotGenerateKeyIfMissing() {
        val signer = createSigner()
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()

        val jwks = signer.getJWKS()
        Assertions.assertThat(JWKSet.parse(jwks).keys).isEmpty()
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
    }

    @Test
    fun getJWKS_wrapsExceptionInJWTSignerException() {
        val signer = createSigner()
        makeSimpleJWT(signer) // populate key file

        Files.writeString(keyFilePath(), "corrupt")
        every { encryption.decrypt("corrupt") } throws RuntimeException("bad")
        signer.cachedKey = null

        val ex = Assertions.catchThrowableOfType(
            { signer.getJWKS() },
            JWTSignerException::class.java
        )
        // Exception originates from getKey, re-thrown by getJWKS
        Assertions.assertThat(ex.message).contains("Failed to load or generate signing key")
    }

    /*
     * Caching
     */

    @Test
    fun makeJWT_populatesCache() {
        val signer = createSigner()
        Assertions.assertThat(signer.cachedKey).isNull()
        makeSimpleJWT(signer)
        Assertions.assertThat(signer.cachedKey).isNotNull()
    }

    @Test
    fun makeJWT_usesCache_encryptCalledOnce() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        makeSimpleJWT(signer)

        // encrypt called once (saving generated key on first call).
        // Second makeJWT uses cache -- no additional encrypt/decrypt.
        verify(exactly = 1) { encryption.encrypt(any()) }
        verify(exactly = 0) { encryption.decrypt(any()) }
    }

    @Test
    fun cacheMiss_loadsFromDiskAndCaches() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate key, populate cache

        signer.cachedKey = null // simulate cache miss
        makeSimpleJWT(signer) // should reload from disk

        // decrypt called once (loading from file); encrypt still once (initial save)
        verify(exactly = 1) { encryption.encrypt(any()) }
        verify(exactly = 1) { encryption.decrypt(any()) }
        Assertions.assertThat(signer.cachedKey).isNotNull()
    }

    @Test
    fun cacheInvalidation_causesReloadFromDisk() {
        // Simulates FileWatcher listener: { cachedKey = null }.
        // The real watcher polls every 10s, which is impractical for unit tests.
        val signer = createSigner()
        val jwt1 = makeSimpleJWT(signer)
        val kid1 = parseJWT(jwt1).header.keyID

        // Write a different key to the key file
        val newKey = generateTestKey()
        Files.writeString(keyFilePath(), newKey.toJSONString())

        // Simulate file watcher cache invalidation
        signer.cachedKey = null

        val jwt2 = makeSimpleJWT(signer)
        val kid2 = parseJWT(jwt2).header.keyID

        Assertions.assertThat(kid1).isNotEqualTo(kid2)
        Assertions.assertThat(kid2).isEqualTo(newKey.keyID)
    }

    /*
     * getSigningAlgorithms
     */

    @Test
    fun getSigningAlgorithms_defaultsToRS256() {
        val signer = createSigner()
        Assertions.assertThat(signer.getSigningAlgorithms()).isEqualTo(listOf("RS256"))
    }

    @Test
    fun getSigningAlgorithms_reflectsConfiguredAlgorithm() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "PS512")
        val signer = createSigner()
        Assertions.assertThat(signer.getSigningAlgorithms()).isEqualTo(listOf("PS512"))
    }

    @Test
    fun makeJWT_setsConfiguredAlgorithmInHeader() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "RS512")
        val signer = createSigner()
        val jws = parseJWT(makeSimpleJWT(signer))
        Assertions.assertThat(jws.header.algorithm.name).isEqualTo("RS512")
        Assertions.assertThat(jws.verify(RSASSAVerifier(extractPublicKey(signer)))).isTrue()
    }

    @Test
    fun makeJWT_psAlgorithm_signatureVerifiesAgainstPublicKey() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "PS256")
        val signer = createSigner()
        val jws = parseJWT(makeSimpleJWT(signer))
        Assertions.assertThat(jws.header.algorithm.name).isEqualTo("PS256")
        Assertions.assertThat(jws.verify(RSASSAVerifier(extractPublicKey(signer)))).isTrue()
    }

    /*
     * fillSettingsModel
     */

    @Test
    fun fillSettingsModel_populatesExpectedKeys() {
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model).containsKey("keyFilePath")
        Assertions.assertThat(model).containsKey("keyFingerprint")
        Assertions.assertThat(model).containsKey("rsaKeyBits")
        Assertions.assertThat(model).containsKey("allowedRsaKeyBits")
        Assertions.assertThat(model).containsKey("jwsAlgorithm")
        Assertions.assertThat(model).containsKey("allowedJwsAlgorithms")
    }

    @Test
    fun fillSettingsModel_keyFilePathMatchesExpectedLocation() {
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        val path = model["keyFilePath"] as String
        Assertions.assertThat(path).endsWith("oidc-jwt/rsa/private.key")
    }

    @Test
    fun fillSettingsModel_keyFingerprintMatchesGeneratedKey() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        val jwksKid = extractPublicKey(signer).keyID
        Assertions.assertThat(model["keyFingerprint"]).isEqualTo(jwksKid)
    }

    @Test
    fun fillSettingsModel_rsaKeyBitsMatchesConfiguredValue() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate key with default 3072 bits
        currentSettings = currentSettings.copy(rsaKeyBits = 4096) // change settings after key gen

        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        // fillSettingsModel reports the configured value from settings, not the actual key size
        Assertions.assertThat(model["rsaKeyBits"]).isEqualTo(4096)
    }

    @Test
    fun fillSettingsModel_allowedRsaKeyBitsContainsExpectedValues() {
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["allowedRsaKeyBits"]).isEqualTo(listOf(2048, 3072, 4096))
    }

    @Test
    fun fillSettingsModel_jwsAlgorithmMatchesConfiguredValue() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "RS384")
        val signer = createSigner()

        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["jwsAlgorithm"]).isEqualTo("RS384")
    }

    @Test
    fun fillSettingsModel_allowedJwsAlgorithmsContainsExpectedValues() {
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["allowedJwsAlgorithms"]).isEqualTo(
            listOf("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
        )
    }

    @Test
    fun fillSettingsModel_includesRotationEndpointAndPermission() {
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["rotationEndpoint"]).isEqualTo("/app/oidc-jwt/builtin-rsa/rotate")
        Assertions.assertThat(model["rotationRequiredPermission"]).isEqualTo(Permission.CHANGE_SERVER_SETTINGS)
    }

    /*
     * Rotation controller registration
     */

    @Test
    fun init_registersRotationControllerUnderExpectedURL() {
        createSigner()
        verify(exactly = 1) { controllerManager.registerController(eq("/app/oidc-jwt/builtin-rsa/rotate"), any()) }
    }

    /*
     * validateSettings
     */

    @Test
    fun validateSettings_validKeyBits_returnsEmptyMap() {
        val signer = createSigner()
        for (bits in listOf(2048, 3072, 4096)) {
            Assertions.assertThat(
                signer.validateSettings(mapOf("rsaKeyBits" to bits.toString(), "jwsAlgorithm" to "RS256"))
            ).isEmpty()
        }
    }

    @Test
    fun validateSettings_missingRsaKeyBits_returnsError() {
        val signer = createSigner()
        val errors = signer.validateSettings(mapOf("jwsAlgorithm" to "RS256"))
        Assertions.assertThat(errors).containsKey("rsaKeyBits")
        Assertions.assertThat(errors["rsaKeyBits"]).contains("Invalid or missing")
    }

    @Test
    fun validateSettings_nonNumericRsaKeyBits_returnsError() {
        val signer = createSigner()
        val errors = signer.validateSettings(mapOf("rsaKeyBits" to "abc", "jwsAlgorithm" to "RS256"))
        Assertions.assertThat(errors).containsKey("rsaKeyBits")
        Assertions.assertThat(errors["rsaKeyBits"]).contains("Invalid or missing")
    }

    @Test
    fun validateSettings_disallowedRsaKeyBits_returnsError() {
        val signer = createSigner()
        val errors = signer.validateSettings(mapOf("rsaKeyBits" to "1024", "jwsAlgorithm" to "RS256"))
        Assertions.assertThat(errors).containsKey("rsaKeyBits")
        Assertions.assertThat(errors["rsaKeyBits"]).contains("Invalid RSA key size: 1024")
        Assertions.assertThat(errors["rsaKeyBits"]).contains("2048, 3072, 4096")
    }

    @Test
    fun validateSettings_missingJwsAlgorithm_returnsError() {
        val signer = createSigner()
        val errors = signer.validateSettings(mapOf("rsaKeyBits" to "3072"))
        Assertions.assertThat(errors).containsKey("jwsAlgorithm")
        Assertions.assertThat(errors["jwsAlgorithm"]).contains("Invalid or missing")
    }

    @Test
    fun validateSettings_disallowedJwsAlgorithm_returnsError() {
        val signer = createSigner()
        val errors = signer.validateSettings(mapOf("rsaKeyBits" to "3072", "jwsAlgorithm" to "HS256"))
        Assertions.assertThat(errors).containsKey("jwsAlgorithm")
        Assertions.assertThat(errors["jwsAlgorithm"]).contains("Invalid JWS algorithm: HS256")
        Assertions.assertThat(errors["jwsAlgorithm"]).contains("RS256, RS384, RS512, PS256, PS384, PS512")
    }

    @Test
    fun saveSettings_sameBitsSameAlgorithm_doesNotRequestRotation() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        Assertions.assertThat(signer.cachedKey).isNotNull()

        val result = signer.saveSettings(mutableMapOf("rsaKeyBits" to "3072", "jwsAlgorithm" to "RS256"))

        Assertions.assertThat(result).isEmpty()
        Assertions.assertThat(Files.exists(keyFilePath())).isTrue()
        Assertions.assertThat(signer.cachedKey).isNotNull()
        Assertions.assertThat(listKeyDirFiles()).hasSize(1) // only private.key
        verify(exactly = 0) { multiNodeTasks.submit(any()) }
    }

    @Test
    fun saveSettings_differentBits_requestsRotationAndKeepsKeyFile() {
        val signer = createSigner()
        val kid = parseJWT(makeSimpleJWT(signer)).header.keyID
        Assertions.assertThat(Files.exists(keyFilePath())).isTrue()

        signer.saveSettings(mutableMapOf("rsaKeyBits" to "4096", "jwsAlgorithm" to "RS256"))

        // Rotation is deferred to a multi-node task; the key file is untouched here.
        Assertions.assertThat(Files.exists(keyFilePath())).isTrue()
        verify(exactly = 1) {
            multiNodeTasks.submit(match { it.type == "oidc-jwt-rotate-key-rsa" && it.identity.startsWith("$kid@") })
        }
    }

    @Test
    fun saveSettings_differentBits_doesNotCreateRotatedBackupSynchronously() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        signer.saveSettings(mutableMapOf("rsaKeyBits" to "4096", "jwsAlgorithm" to "RS256"))

        val rotatedFiles = listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        Assertions.assertThat(rotatedFiles).isEmpty()
    }

    @Test
    fun saveSettings_differentBits_updatesSettingsStorage() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        signer.saveSettings(mutableMapOf("rsaKeyBits" to "4096", "jwsAlgorithm" to "RS384"))

        Assertions.assertThat(currentSettings.rsaKeyBits).isEqualTo(4096)
        Assertions.assertThat(currentSettings.jwsAlgorithm).isEqualTo("RS384")
    }

    @Test
    fun saveSettings_differentBits_afterRotationTaskRuns_makeJWTUsesNewSize() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generates 3072-bit key

        val kid = signer.cachedKey!!.keyID
        signer.saveSettings(mutableMapOf("rsaKeyBits" to "4096", "jwsAlgorithm" to "RS256"))
        // Drive the deferred rotation task: it backs up and deletes the current key.
        driveRotationTask(captureRotationConsumer(), kid)
        makeSimpleJWT(signer) // should now generate a new 4096-bit key

        val pubKey = extractPublicKey(signer)
        Assertions.assertThat(pubKey.toRSAPublicKey().modulus.bitLength()).isEqualTo(4096)
    }

    @Test
    fun saveSettings_noExistingKey_doesNotRequestRotation() {
        val signer = createSigner()
        // Do not generate a key before calling saveSettings

        signer.saveSettings(mutableMapOf("rsaKeyBits" to "4096", "jwsAlgorithm" to "RS256"))

        val rotatedFiles = listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        Assertions.assertThat(rotatedFiles).isEmpty()
        verify(exactly = 0) { multiNodeTasks.submit(any()) }
    }

    @Test
    fun saveSettings_sameBitsDifferentAlgorithm_doesNotRequestRotationButPersistsAlgorithm() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        val keyFileBefore = Files.readAllBytes(keyFilePath())
        val cachedKeyBefore = signer.cachedKey
        Assertions.assertThat(cachedKeyBefore).isNotNull()

        signer.saveSettings(mutableMapOf("rsaKeyBits" to "3072", "jwsAlgorithm" to "RS512"))

        Assertions.assertThat(Files.readAllBytes(keyFilePath())).isEqualTo(keyFileBefore)
        Assertions.assertThat(listKeyDirFiles()).hasSize(1) // no rotated backup
        Assertions.assertThat(signer.cachedKey).isSameAs(cachedKeyBefore)
        Assertions.assertThat(currentSettings.jwsAlgorithm).isEqualTo("RS512")
        verify(exactly = 0) { multiNodeTasks.submit(any()) }
    }

    @Test
    fun saveSettings_sameBitsDifferentAlgorithm_subsequentMakeJWTUsesNewAlgorithm() {
        val signer = createSigner()
        val originalKid = parseJWT(makeSimpleJWT(signer)).header.keyID

        signer.saveSettings(mutableMapOf("rsaKeyBits" to "3072", "jwsAlgorithm" to "RS384"))
        val jws = parseJWT(makeSimpleJWT(signer))

        Assertions.assertThat(jws.header.algorithm.name).isEqualTo("RS384")
        Assertions.assertThat(jws.header.keyID).isEqualTo(originalKid)
    }

    @Test
    fun saveSettings_differentBitsAndAlgorithm_requestsRotationAndPersistsAlgorithm() {
        val signer = createSigner()
        val kid = parseJWT(makeSimpleJWT(signer)).header.keyID // 3072-bit key with default RS256

        signer.saveSettings(mutableMapOf("rsaKeyBits" to "4096", "jwsAlgorithm" to "PS384"))

        Assertions.assertThat(currentSettings.jwsAlgorithm).isEqualTo("PS384")
        verify(exactly = 1) {
            multiNodeTasks.submit(match { it.type == "oidc-jwt-rotate-key-rsa" && it.identity.startsWith("$kid@") })
        }

        // After the deferred task runs, the new algorithm and key size take effect.
        driveRotationTask(captureRotationConsumer(), kid)
        val jws = parseJWT(makeSimpleJWT(signer))
        Assertions.assertThat(jws.header.algorithm.name).isEqualTo("PS384")
        Assertions.assertThat(extractPublicKey(signer).toRSAPublicKey().modulus.bitLength()).isEqualTo(4096)
    }

    @Test
    fun saveSettings_algorithmChange_invalidatesCachedAlgorithmAcrossNodes() {
        val signer = createSigner()
        Assertions.assertThat(signer.getSigningAlgorithms()).isEqualTo(listOf("RS256")) // primes the cache

        // Simulate a remote node update: settings change directly + handlers fired
        currentSettings = currentSettings.copy(jwsAlgorithm = "PS512")
        settingsUpdateHandlers.toList().forEach { it() }

        Assertions.assertThat(signer.getSigningAlgorithms()).isEqualTo(listOf("PS512"))
    }

    /*
     * Identity & Admin
     */

    @Test
    fun getId_returnsBuiltin() {
        val signer = createSigner()
        Assertions.assertThat(signer.getId()).isEqualTo("builtin-rsa")
    }

    @Test
    fun getDisplayName_returnsBuiltInRSA() {
        val signer = createSigner()
        Assertions.assertThat(signer.getDisplayName()).isEqualTo("Built-in (RSA)")
    }

    @Test
    fun getSettingsPagePath_returnsExpectedPath() {
        val signer = createSigner()
        Assertions.assertThat(signer.getSettingsPagePath()).isEqualTo("/plugins/oidc-jwt/signerSettings/builtin-rsa.jsp")
    }

    @Test
    fun getAdminSettings_returnsSelf() {
        val signer = createSigner()
        Assertions.assertThat(signer.getAdminSettings()).isSameAs(signer)
    }

    /*
     * close
     */

    @Test
    fun close_doesNotThrow() {
        val signer = createSigner()
        signer.destroy()
    }

    @Test
    fun close_subsequentMakeJWTStillWorks() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate and cache key
        signer.destroy()

        val jwt = makeSimpleJWT(signer)
        Assertions.assertThat(jwt).isNotNull()
        Assertions.assertThat(jwt).isNotEmpty()
    }

    @Test
    fun makeJWT_tracksKeyInJWKCache() {
        val signer = createSigner()
        val expectedExp = Instant.parse("2030-01-01T00:00:00Z")
        val claims = """{"sub":"test","iss":"https://example.com"}""".toByteArray()

        val jwt = signer.makeJWT(mockk<SBuild>(), claims, expectedExp)

        val kidSlot = slot<String>()
        val jwkSlot = slot<String>()
        val expSlot = slot<Instant>()
        verify(exactly = 1) { jwkCache.trackKey(capture(kidSlot), capture(jwkSlot), capture(expSlot)) }

        Assertions.assertThat(kidSlot.captured).isEqualTo(parseJWT(jwt).header.keyID)
        Assertions.assertThat(expSlot.captured).isEqualTo(expectedExp)

        val trackedJwk = RSAKey.parse(jwkSlot.captured)
        Assertions.assertThat(trackedJwk.keyID).isEqualTo(kidSlot.captured)
        val trackedJson = trackedJwk.toJSONObject()
        Assertions.assertThat(trackedJson["d"]).isNull()
        Assertions.assertThat(trackedJson["p"]).isNull()
        Assertions.assertThat(trackedJson["q"]).isNull()
        Assertions.assertThat(trackedJson["dp"]).isNull()
        Assertions.assertThat(trackedJson["dq"]).isNull()
        Assertions.assertThat(trackedJson["qi"]).isNull()
    }

    @Test
    fun makeJWT_tracksOncePerCall() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        makeSimpleJWT(signer)

        verify(exactly = 2) { jwkCache.trackKey(any(), any(), any()) }
    }

    @Test
    fun makeJWT_tracksOnlyPublicJWK() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        val jwkSlot = slot<String>()
        verify { jwkCache.trackKey(any(), capture(jwkSlot), any()) }
        for (privateField in listOf("\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"")) {
            Assertions.assertThat(jwkSlot.captured).doesNotContain(privateField)
        }
    }

    @Test
    fun makeJWT_signerFailure_doesNotTrackKey() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate and cache a full key

        // Replace cache with a public-only key so signing fails on the next call
        val publicOnly = extractPublicKey(signer)
        signer.cachedKey = publicOnly

        clearMocks(jwkCache, answers = false)

        Assertions.catchThrowableOfType(
            { makeSimpleJWT(signer) },
            JWTSignerException::class.java
        )

        verify(exactly = 0) { jwkCache.trackKey(any(), any(), any()) }
    }

    @Test
    fun getJWKS_emptyCache_returnsOnlyCurrentKey() {
        val signer = createSigner()
        val currentKid = parseJWT(makeSimpleJWT(signer)).header.keyID

        val jwks = JWKSet.parse(signer.getJWKS())

        Assertions.assertThat(jwks.keys).hasSize(1)
        Assertions.assertThat(jwks.keys[0].keyID).isEqualTo(currentKid)
    }

    @Test
    fun getJWKS_cachedKeys_returnsCurrentPlusCached() {
        val signer = createSigner()
        val currentKid = parseJWT(makeSimpleJWT(signer)).header.keyID

        val extra1 = generateTestKey()
        val extra2 = generateTestKey()
        every { jwkCache.fetchCachedJWKs() } returns mapOf(
            extra1.keyID to extra1.toPublicJWK().toJSONString(),
            extra2.keyID to extra2.toPublicJWK().toJSONString(),
        )

        val jwks = JWKSet.parse(signer.getJWKS())

        Assertions.assertThat(jwks.keys.map { it.keyID }).containsExactlyInAnyOrder(
            currentKid, extra1.keyID, extra2.keyID
        )
    }

    @Test
    fun getJWKS_cacheContainsCurrentKey_doesNotDuplicate() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        val currentKey = signer.cachedKey!!
        val currentJwkJson = currentKey.toPublicJWK().toJSONString()

        every { jwkCache.fetchCachedJWKs() } returns mapOf(currentKey.keyID to currentJwkJson)

        val jwks = JWKSet.parse(signer.getJWKS())

        Assertions.assertThat(jwks.keys).hasSize(1)
        Assertions.assertThat(jwks.keys[0].keyID).isEqualTo(currentKey.keyID)
    }

    /*
     * getCurrentKeyPublicJWK
     */

    @Test
    fun getCurrentKeyPublicJWK_doesNotGenerateKeyIfMissing_returnsEmpty() {
        val signer = createSigner()
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()

        Assertions.assertThat(signer.getCurrentKeyPublicJWK()).isEmpty()
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
    }

    @Test
    fun getCurrentKeyPublicJWK_returnsOnlyPublicComponents() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        val json = RSAKey.parse(signer.getCurrentKeyPublicJWK()).toJSONObject()

        Assertions.assertThat(json["d"]).isNull()
        Assertions.assertThat(json["p"]).isNull()
        Assertions.assertThat(json["q"]).isNull()
        Assertions.assertThat(json["dp"]).isNull()
        Assertions.assertThat(json["dq"]).isNull()
        Assertions.assertThat(json["qi"]).isNull()
    }

    @Test
    fun getCurrentKeyPublicJWK_keyIdMatchesSignedJWT() {
        val signer = createSigner()
        val jwtKid = parseJWT(makeSimpleJWT(signer)).header.keyID

        val jwk = RSAKey.parse(signer.getCurrentKeyPublicJWK())

        Assertions.assertThat(jwk.keyID).isEqualTo(jwtKid)
    }

    @Test
    fun getCurrentKeyPublicJWK_matchesJWKSCurrentKey() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        val fromMethod = RSAKey.parse(signer.getCurrentKeyPublicJWK())
        val fromJwks = JWKSet.parse(signer.getJWKS()).keys[0] as RSAKey

        Assertions.assertThat(fromMethod.toJSONObject()).isEqualTo(fromJwks.toJSONObject())
    }

    @Test
    fun getCurrentKeyPublicJWK_wrapsGenericExceptionInJWTSignerException() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        Files.writeString(keyFilePath(), "corrupt")
        every { encryption.decrypt("corrupt") } throws RuntimeException("bad")
        signer.cachedKey = null

        val ex = Assertions.catchThrowableOfType(
            { signer.getCurrentKeyPublicJWK() },
            JWTSignerException::class.java
        )
        Assertions.assertThat(ex.message).contains("Failed to load or generate signing key")
    }

    /*
     * Secondary node / build-management capability
     */

    @Test
    fun makeJWT_withoutBuildManagementCapability_throwsAndDoesNotGenerate() {
        every { serverResponsibility.canManageBuilds() } returns false
        val signer = createSigner()

        val ex = Assertions.catchThrowableOfType(
            { makeSimpleJWT(signer) },
            JWTSignerException::class.java
        )
        // getKey wraps the capability error, so the specific message lives in the cause chain.
        Assertions.assertThat(ex).hasStackTraceContaining("Cannot generate signing key on the current node")
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
        verify(exactly = 0) { jwkCache.trackKey(any(), any(), any()) }
    }

    @Test
    fun makeJWT_nullKey_throwsJWTSignerException() {
        val signer = spyk(createSigner())
        every { signer["getKey"](any<Boolean>()) } returns null

        val ex = Assertions.catchThrowableOfType(
            { makeSimpleJWT(signer) },
            JWTSignerException::class.java
        )
        Assertions.assertThat(ex.message).contains("Cannot load or generate key")
    }

    @Test
    fun getJWKS_withoutBuildManagementCapability_returnsEmptyAndDoesNotGenerate() {
        every { serverResponsibility.canManageBuilds() } returns false
        val signer = createSigner()

        val jwks = signer.getJWKS()
        Assertions.assertThat(JWKSet.parse(jwks).keys).isEmpty()
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
    }

    @Test
    fun fillSettingsModel_noKey_showsWillBeGeneratedPlaceholder() {
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["keyFingerprint"]).isEqualTo("<will be generated on first use>")
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
    }

    @Test
    fun fillSettingsModel_withoutBuildManagementCapability_doesNotThrow() {
        every { serverResponsibility.canManageBuilds() } returns false
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["keyFingerprint"]).isEqualTo("<will be generated on first use>")
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
    }

    /*
     * Multi-node rotation task
     */

    @Test
    fun init_subscribesToRotationTask() {
        createSigner()
        verify(exactly = 1) {
            multiNodeTasks.subscribeOnSingletonTask(eq("oidc-jwt-rotate-key-rsa"), any())
        }
    }

    @Test
    fun destroy_unsubscribesFromRotationTask() {
        val signer = createSigner()
        signer.destroy()
        this.signer = null // avoid a second destroy() in tearDown
        verify(exactly = 1) { multiNodeTasks.unsubscribe(eq("oidc-jwt-rotate-key-rsa")) }
    }

    @Test
    fun rotationTask_withBuildManagementCapability_rotatesKey() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate current key (capability = true)

        driveRotationTask(captureRotationConsumer(), signer.cachedKey!!.keyID)

        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
        Assertions.assertThat(
            listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        ).hasSize(1)
    }

    @Test
    fun rotationTask_savesPreviousKeyToBackupAndRemovesKeyFile() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate current key (capability = true)
        val previousKid = signer.cachedKey!!.keyID

        driveRotationTask(captureRotationConsumer(), previousKid)

        // The live key file is removed.
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()

        // Exactly one backup, named after the previous key, holding the previous key itself.
        val rotated = listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        Assertions.assertThat(rotated).hasSize(1)
        Assertions.assertThat(rotated[0].fileName.toString()).contains(previousKid)
        val backedUp = RSAKey.parse(encryption.decrypt(Files.readString(rotated[0])))
        Assertions.assertThat(backedUp.keyID).isEqualTo(previousKid)
        Assertions.assertThat(backedUp.isPrivate).isTrue()
    }

    @Test
    fun rotationTask_noCurrentKey_exitsEarlyWithoutRotating() {
        val signer = createSigner()
        // No key on disk: there is nothing to rotate.
        val consumer = captureRotationConsumer()
        val task = rotationTask("nonexistent-kid")

        consumer.accept(task)

        // Early return: no backup written, no key file created, no save attempted.
        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
        Assertions.assertThat(
            listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        ).isEmpty()
        verify(exactly = 0) { encryption.encrypt(any()) }
        // The task still completes successfully (no failure details).
        verify(exactly = 1) { task.finished() }
        verify(exactly = 0) { task.finished(any(), any()) }
    }

    @Test
    fun rotationTask_withoutBuildManagementCapability_doesNotRotate() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate key while capability = true
        val kid = signer.cachedKey!!.keyID

        every { serverResponsibility.canManageBuilds() } returns false

        driveRotationTask(captureRotationConsumer(), kid)

        Assertions.assertThat(Files.exists(keyFilePath())).isTrue()
        Assertions.assertThat(
            listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        ).isEmpty()
    }

    @Test
    fun rotationTask_successfulRotation_finishesTaskWithoutFailureDetails() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate current key (capability = true)
        val consumer = captureRotationConsumer()
        val task = rotationTask(signer.cachedKey!!.keyID)

        consumer.accept(task)

        verify(exactly = 1) { task.finished() }
        verify(exactly = 0) { task.finished(any(), any()) }
    }

    @Test
    fun rotationTask_rotationFailsWithMessage_finishesTaskWithFailureDetails() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate current key while encryption works
        val consumer = captureRotationConsumer()
        // Capture the kid before breaking encryption so the task passes the key-ID guard.
        val task = rotationTask(signer.cachedKey!!.keyID)
        // Break the backup save performed during rotation so accept() hits the failure branch.
        every { encryption.encrypt(any()) } throws RuntimeException("disk full")
        val details = slot<String>()

        consumer.accept(task)

        verify(exactly = 0) { task.finished() }
        verify(exactly = 1) { task.finished(any(), capture(details)) }
        Assertions.assertThat(details.captured)
            .isEqualTo("Failed to rotate the key due to java.lang.RuntimeException: disk full")
    }

    @Test
    fun rotationTask_rotationFailsWithoutMessage_finishesTaskWithFallbackDetails() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate current key while encryption works
        val consumer = captureRotationConsumer()
        // Capture the kid before breaking encryption so the task passes the key-ID guard.
        val task = rotationTask(signer.cachedKey!!.keyID)
        // Exception without a message: the details fall back to "${e} (no message)".
        every { encryption.encrypt(any()) } throws RuntimeException()
        val details = slot<String>()

        consumer.accept(task)

        verify(exactly = 0) { task.finished() }
        verify(exactly = 1) { task.finished(any(), capture(details)) }
        Assertions.assertThat(details.captured)
            .isEqualTo("Failed to rotate the key due to java.lang.RuntimeException: java.lang.RuntimeException (no message)")
    }

    private fun taskWithIdentity(identity: String): MultiNodeTasks.SubmittedTask =
        mockk { every { this@mockk.identity } returns identity }

    /*
     * isKeyRotationInProgress
     */

    @Test
    fun isKeyRotationInProgress_pendingTaskWithMatchingIdentity_returnsTrue() {
        val signer = createSigner()
        every { multiNodeTasks.findPendingTasks(any()) } returns listOf(taskWithIdentity("kid-1"))

        Assertions.assertThat(signer.isKeyRotationInProgress("kid-1")).isTrue()
    }

    @Test
    fun isKeyRotationInProgress_noTasks_returnsFalse() {
        val signer = createSigner()
        // relaxed multiNodeTasks returns empty lists for all find* calls
        Assertions.assertThat(signer.isKeyRotationInProgress("kid-1")).isFalse()
    }

    @Test
    fun isKeyRotationInProgress_inProgressTaskWithMatchingIdentity_returnsTrue() {
        val signer = createSigner()
        every { multiNodeTasks.findInProgressTasks(any()) } returns listOf(taskWithIdentity("kid-1"))

        Assertions.assertThat(signer.isKeyRotationInProgress("kid-1")).isTrue()
    }

    @Test
    fun isKeyRotationInProgress_recentlyFinishedTaskWithMatchingIdentity_returnsTrueUsingThreshold() {
        val signer = createSigner()
        every { multiNodeTasks.findFinishedTasks(any(), 10000L) } returns listOf(taskWithIdentity("kid-1"))

        Assertions.assertThat(signer.isKeyRotationInProgress("kid-1")).isTrue()
        verify { multiNodeTasks.findFinishedTasks(any(), 10000L) }
    }

    /*
     * requestKeyRotation
     */

    @Test
    fun requestKeyRotation_reloadsFreshKeyIdFromDisk() {
        val signer = createSigner()
        val kid1 = parseJWT(makeSimpleJWT(signer)).header.keyID // generate & cache key

        // Replace the on-disk key without invalidating the in-memory cache
        val newKey = generateTestKey()
        Files.writeString(keyFilePath(), newKey.toJSONString())

        signer.requestKeyRotation()

        val submitted = slot<MultiNodeTasks.Task>()
        verify(exactly = 1) { multiNodeTasks.submit(capture(submitted)) }
        // Identity is "${keyID}@${random UUID}", so the prefix is the fresh key ID, not the cached one.
        Assertions.assertThat(submitted.captured.identity).startsWith("${newKey.keyID}@")
        Assertions.assertThat(submitted.captured.identity).doesNotStartWith(kid1)
    }

    @Test
    fun requestKeyRotation_noKey_doesNotSubmit() {
        val signer = createSigner()
        // No key on disk

        signer.requestKeyRotation()

        verify(exactly = 0) { multiNodeTasks.submit(any()) }
    }

    @Test
    fun requestKeyRotation_rotationAlreadyInProgress_throwsAndDoesNotSubmit() {
        val signer = createSigner()
        val kid = parseJWT(makeSimpleJWT(signer)).header.keyID
        every { multiNodeTasks.findPendingTasks(any()) } returns listOf(taskWithIdentity(kid))

        Assertions.catchThrowableOfType(
            { signer.requestKeyRotation() },
            JWTSignerException::class.java
        )

        verify(exactly = 0) { multiNodeTasks.submit(any()) }
    }

    @Test
    fun requestKeyRotation_keyPresent_submitsTaskWithKeyIdentity() {
        val signer = createSigner()
        val kid = parseJWT(makeSimpleJWT(signer)).header.keyID

        signer.requestKeyRotation()

        verify(exactly = 1) {
            multiNodeTasks.submit(match { it.type == "oidc-jwt-rotate-key-rsa" && it.identity.startsWith("$kid@") })
        }
    }

    @Test
    fun requestKeyRotation_keyPresent_returnsSubmittedTaskID() {
        val signer = createSigner()
        val kid = parseJWT(makeSimpleJWT(signer)).header.keyID

        val taskID = signer.requestKeyRotation()

        verify(exactly = 1) { multiNodeTasks.submit(match { it.identity == taskID }) }
        Assertions.assertThat(taskID).startsWith("$kid@")
    }

    /*
     * fillSettingsModel rotation-in-progress suffix
     */

    @Test
    fun fillSettingsModel_pendingRotationTask_appendsRotationSuffix() {
        val signer = createSigner()
        val kid = parseJWT(makeSimpleJWT(signer)).header.keyID
        every { multiNodeTasks.findPendingTasks(any()) } returns listOf(taskWithIdentity(kid))

        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["keyFingerprint"]).isEqualTo("$kid (rotation in progress)")
    }

    @Test
    fun fillSettingsModel_inProgressRotationTask_appendsRotationSuffix() {
        val signer = createSigner()
        val kid = parseJWT(makeSimpleJWT(signer)).header.keyID
        every { multiNodeTasks.findInProgressTasks(any()) } returns listOf(taskWithIdentity(kid))

        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["keyFingerprint"]).isEqualTo("$kid (rotation in progress)")
    }

    @Test
    fun fillSettingsModel_recentlyFinishedRotationTask_appendsRotationSuffix() {
        val signer = createSigner()
        val kid = parseJWT(makeSimpleJWT(signer)).header.keyID
        every { multiNodeTasks.findFinishedTasks(any(), 10000L) } returns listOf(taskWithIdentity(kid))

        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["keyFingerprint"]).isEqualTo("$kid (rotation in progress)")
    }

    @Test
    fun fillSettingsModel_noKey_doesNotAppendRotationSuffix() {
        val signer = createSigner()
        // No key, yet a rotation task exists for some identity: the placeholder must stay.
        every { multiNodeTasks.findPendingTasks(any()) } returns listOf(taskWithIdentity("whatever"))

        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["keyFingerprint"]).isEqualTo("<will be generated on first use>")
    }
}
