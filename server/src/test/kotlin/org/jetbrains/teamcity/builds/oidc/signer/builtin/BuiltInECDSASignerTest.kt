package org.jetbrains.teamcity.builds.oidc.signer.builtin

import org.jetbrains.teamcity.builds.oidc.api.JWTSignerException
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
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
import java.time.Instant
import java.util.Comparator

class BuiltInECDSASignerTest : BaseTestCase() {

    private lateinit var tempDir: Path

    private lateinit var controllerManager: WebControllerManager
    private lateinit var encryption: Encryption
    private lateinit var pluginDescriptor: PluginDescriptor
    private lateinit var settingsStore: BuiltInECDSASettingsStore
    private lateinit var jwkCache: JWKCache
    private lateinit var serverPaths: ServerPaths
    private lateinit var serverResponsibility: ServerResponsibility
    private lateinit var teamCityNodes: TeamCityNodes
    private var currentSettings = BuiltInECDSASettings()
    private val settingsUpdateHandlers = mutableListOf<() -> Unit>()
    private var signer: BuiltInECDSASigner? = null

    @BeforeMethod
    override fun setUp() {
        super.setUp()
        tempDir = Files.createTempDirectory("BuiltInECDSASignerTest-")
        currentSettings = BuiltInECDSASettings()
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
            currentSettings = invocation.invocation.args[0] as BuiltInECDSASettings
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

    private fun createSigner(): BuiltInECDSASigner {
        val s = BuiltInECDSASigner(
            controllerManager,
            teamCityNodes,
            serverResponsibility,
            serverPaths,
            encryption,
            pluginDescriptor,
            settingsStore,
            jwkCache
        )
        signer = s
        return s
    }

    private fun makeSimpleJWT(target: BuiltInECDSASigner): String {
        return target.makeJWT(
            mockk<SBuild>(),
            """{"sub":"test","iss":"https://example.com"}""".toByteArray(),
            Instant.now().plusSeconds(300)
        )
    }

    private fun parseJWT(jwt: String): JWSObject = JWSObject.parse(jwt)

    private fun extractPublicKey(target: BuiltInECDSASigner): ECKey =
        JWKSet.parse(target.getJWKS()).keys[0] as ECKey

    private fun keyFilePath(): Path =
        tempDir.resolve("pluginData").resolve("oidc-jwt").resolve("ecdsa").resolve("private.key")

    private fun listKeyDirFiles(): List<Path> {
        val keyDir = tempDir.resolve("pluginData").resolve("oidc-jwt").resolve("ecdsa")
        return if (Files.exists(keyDir)) Files.list(keyDir).use { it.toList() } else emptyList()
    }

    private fun generateTestKey(curve: Curve = Curve.P_256): ECKey =
        ECKeyGenerator(curve).keyIDFromThumbprint(true).generate()

    /*
     * Key Generation
     */

    @Test
    fun makeJWT_generatesP256KeyByDefault() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        val pubKey = extractPublicKey(signer)
        Assertions.assertThat(pubKey.curve).isEqualTo(Curve.P_256)
    }

    @Test
    fun makeJWT_es384_generatesP384Key() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "ES384")
        val signer = createSigner()
        makeSimpleJWT(signer)

        val pubKey = extractPublicKey(signer)
        Assertions.assertThat(pubKey.curve).isEqualTo(Curve.P_384)
    }

    @Test
    fun makeJWT_es512_generatesP521Key() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "ES512")
        val signer = createSigner()
        makeSimpleJWT(signer)

        val pubKey = extractPublicKey(signer)
        Assertions.assertThat(pubKey.curve).isEqualTo(Curve.P_521)
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
        Assertions.assertThat(ECKey.parse(decrypted)).isNotNull()
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

        Assertions.assertThat(jws.verify(ECDSAVerifier(pubKey))).isTrue()
    }

    @Test
    fun makeJWT_setsES256AlgorithmInHeaderByDefault() {
        val signer = createSigner()
        val jws = parseJWT(makeSimpleJWT(signer))
        Assertions.assertThat(jws.header.algorithm.name).isEqualTo("ES256")
    }

    @Test
    fun makeJWT_es384_setsAlgorithmInHeaderAndVerifies() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "ES384")
        val signer = createSigner()
        val jws = parseJWT(makeSimpleJWT(signer))
        Assertions.assertThat(jws.header.algorithm.name).isEqualTo("ES384")
        Assertions.assertThat(jws.verify(ECDSAVerifier(extractPublicKey(signer)))).isTrue()
    }

    @Test
    fun makeJWT_es512_setsAlgorithmInHeaderAndVerifies() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "ES512")
        val signer = createSigner()
        val jws = parseJWT(makeSimpleJWT(signer))
        Assertions.assertThat(jws.header.algorithm.name).isEqualTo("ES512")
        Assertions.assertThat(jws.verify(ECDSAVerifier(extractPublicKey(signer)))).isTrue()
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
        // The signer signs whatever claims are provided without
        // injecting or modifying the expiration.
        val claims = """{"sub":"test","iss":"https://example.com"}"""
        val signer = createSigner()
        val jwt = signer.makeJWT(mockk<SBuild>(), claims.toByteArray(), Instant.now().plusSeconds(300))
        val jws = parseJWT(jwt)
        Assertions.assertThat(jws.payload.toString()).isEqualTo(claims)
    }

    @Test
    fun makeJWT_wrapsGenericExceptionInJWTSignerException() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generate and cache a full key

        // Replace cache with a public-only key so ECDSASigner fails
        val publicOnly = extractPublicKey(signer)
        signer.cachedKey = publicOnly

        val ex = Assertions.catchThrowableOfType(
            { makeSimpleJWT(signer) },
            JWTSignerException::class.java
        )
        Assertions.assertThat(ex.message).contains("com.nimbusds.jose.JOSEException: The EC JWK doesn't contain a private part")
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
        Assertions.assertThat(jwks.keys[0].keyType.value).isEqualTo("EC")
        Assertions.assertThat((jwks.keys[0] as ECKey).curve).isEqualTo(Curve.P_256)
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
    fun getSigningAlgorithms_defaultsToES256() {
        val signer = createSigner()
        Assertions.assertThat(signer.getSigningAlgorithms()).isEqualTo(listOf("ES256"))
    }

    @Test
    fun getSigningAlgorithms_reflectsConfiguredAlgorithm() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "ES384")
        val signer = createSigner()
        Assertions.assertThat(signer.getSigningAlgorithms()).isEqualTo(listOf("ES384"))
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
        Assertions.assertThat(model).containsKey("jwsAlgorithm")
        Assertions.assertThat(model).containsKey("allowedJwsAlgorithms")
    }

    @Test
    fun fillSettingsModel_keyFilePathMatchesExpectedLocation() {
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        val path = model["keyFilePath"] as String
        Assertions.assertThat(path).endsWith("oidc-jwt/ecdsa/private.key")
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
    fun fillSettingsModel_jwsAlgorithmMatchesConfiguredValue() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "ES384")
        val signer = createSigner()

        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["jwsAlgorithm"]).isEqualTo("ES384")
    }

    @Test
    fun fillSettingsModel_allowedJwsAlgorithmsContainsExpectedValues() {
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["allowedJwsAlgorithms"]).isEqualTo(listOf("ES256", "ES384", "ES512"))
    }

    @Test
    fun fillSettingsModel_includesRotationEndpointAndPermission() {
        val signer = createSigner()
        val model = mutableMapOf<String, Any>()
        signer.fillSettingsModel(model)

        Assertions.assertThat(model["rotationEndpoint"]).isEqualTo("/app/oidc-jwt/builtin-ecdsa/rotate")
        Assertions.assertThat(model["rotationRequiredPermission"]).isEqualTo(Permission.CHANGE_SERVER_SETTINGS)
    }

    /*
     * Rotation controller registration
     */

    @Test
    fun init_registersRotationControllerUnderExpectedURL() {
        createSigner()
        verify(exactly = 1) { controllerManager.registerController(eq("/app/oidc-jwt/builtin-ecdsa/rotate"), any()) }
    }

    /*
     * validateSettings
     */

    @Test
    fun validateSettings_validAlgorithm_returnsEmptyMap() {
        val signer = createSigner()
        for (alg in listOf("ES256", "ES384", "ES512")) {
            Assertions.assertThat(signer.validateSettings(mapOf("jwsAlgorithm" to alg))).isEmpty()
        }
    }

    @Test
    fun validateSettings_missingJwsAlgorithm_returnsError() {
        val signer = createSigner()
        val errors = signer.validateSettings(emptyMap())
        Assertions.assertThat(errors).containsKey("jwsAlgorithm")
        Assertions.assertThat(errors["jwsAlgorithm"]).contains("Invalid or missing")
    }

    @Test
    fun validateSettings_emptyJwsAlgorithm_returnsError() {
        val signer = createSigner()
        val errors = signer.validateSettings(mapOf("jwsAlgorithm" to ""))
        Assertions.assertThat(errors).containsKey("jwsAlgorithm")
        Assertions.assertThat(errors["jwsAlgorithm"]).contains("Invalid or missing")
    }

    @Test
    fun validateSettings_disallowedJwsAlgorithm_returnsError() {
        val signer = createSigner()
        for (bad in listOf("RS256", "ES256K", "HS256", "garbage")) {
            val errors = signer.validateSettings(mapOf("jwsAlgorithm" to bad))
            Assertions.assertThat(errors).containsKey("jwsAlgorithm")
            Assertions.assertThat(errors["jwsAlgorithm"]).contains("Invalid JWS algorithm: $bad")
            Assertions.assertThat(errors["jwsAlgorithm"]).contains("ES256, ES384, ES512")
        }
    }

    /*
     * saveSettings
     */

    @Test
    fun saveSettings_sameAlgorithm_doesNotRotate() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        val cachedKeyBefore = signer.cachedKey
        Assertions.assertThat(cachedKeyBefore).isNotNull()

        val result = signer.saveSettings(mutableMapOf("jwsAlgorithm" to "ES256"))

        Assertions.assertThat(result).isEmpty()
        Assertions.assertThat(Files.exists(keyFilePath())).isTrue()
        Assertions.assertThat(signer.cachedKey).isSameAs(cachedKeyBefore)
        Assertions.assertThat(listKeyDirFiles()).hasSize(1) // only private.key
    }

    @Test
    fun saveSettings_differentAlgorithm_deletesCurrentKeyFile() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        Assertions.assertThat(Files.exists(keyFilePath())).isTrue()

        signer.saveSettings(mutableMapOf("jwsAlgorithm" to "ES384"))

        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
    }

    @Test
    fun saveSettings_differentAlgorithm_savesRotatedKeyFileNamedWithOldCurve() {
        val signer = createSigner()
        val kid = parseJWT(makeSimpleJWT(signer)).header.keyID

        signer.saveSettings(mutableMapOf("jwsAlgorithm" to "ES512"))

        val rotatedFiles = listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        Assertions.assertThat(rotatedFiles).hasSize(1)

        val name = rotatedFiles[0].fileName.toString()
        Assertions.assertThat(name).startsWith("private.P-256.")
        Assertions.assertThat(name).contains(kid)
        Assertions.assertThat(name).matches("private\\.P-256\\..*\\.rotated-on-\\d+")
    }

    @Test
    fun saveSettings_differentAlgorithm_clearsCache() {
        val signer = createSigner()
        makeSimpleJWT(signer)
        Assertions.assertThat(signer.cachedKey).isNotNull()

        signer.saveSettings(mutableMapOf("jwsAlgorithm" to "ES384"))

        Assertions.assertThat(signer.cachedKey).isNull()
    }

    @Test
    fun saveSettings_differentAlgorithm_updatesSettingsStorage() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        signer.saveSettings(mutableMapOf("jwsAlgorithm" to "ES384"))

        Assertions.assertThat(currentSettings.jwsAlgorithm).isEqualTo("ES384")
    }

    @Test
    fun saveSettings_differentAlgorithm_subsequentMakeJWTUsesNewCurveAndAlg() {
        val signer = createSigner()
        makeSimpleJWT(signer) // generates ES256/P-256 key

        signer.saveSettings(mutableMapOf("jwsAlgorithm" to "ES384"))
        val jws = parseJWT(makeSimpleJWT(signer))

        Assertions.assertThat(jws.header.algorithm.name).isEqualTo("ES384")
        Assertions.assertThat(extractPublicKey(signer).curve).isEqualTo(Curve.P_384)
    }

    @Test
    fun saveSettings_noExistingKey_doesNotCreateRotatedFile() {
        val signer = createSigner()
        // Do not generate a key before calling saveSettings

        signer.saveSettings(mutableMapOf("jwsAlgorithm" to "ES384"))

        val rotatedFiles = listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        Assertions.assertThat(rotatedFiles).isEmpty()
    }

    @Test
    fun saveSettings_rotateFromES384_backupNamedWithP384() {
        currentSettings = currentSettings.copy(jwsAlgorithm = "ES384")
        val signer = createSigner()
        makeSimpleJWT(signer) // generates ES384/P-384 key

        signer.saveSettings(mutableMapOf("jwsAlgorithm" to "ES256"))

        val rotatedFiles = listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        Assertions.assertThat(rotatedFiles).hasSize(1)
        Assertions.assertThat(rotatedFiles[0].fileName.toString()).startsWith("private.P-384.")
    }

    @Test
    fun saveSettings_algorithmChange_invalidatesCachedAlgorithmAcrossNodes() {
        val signer = createSigner()
        Assertions.assertThat(signer.getSigningAlgorithms()).isEqualTo(listOf("ES256")) // primes the cache

        // Simulate a remote node update: settings change directly + handlers fired
        currentSettings = currentSettings.copy(jwsAlgorithm = "ES512")
        settingsUpdateHandlers.toList().forEach { it() }

        Assertions.assertThat(signer.getSigningAlgorithms()).isEqualTo(listOf("ES512"))
    }

    /*
     * Identity & Admin
     */

    @Test
    fun getId_returnsBuiltinEcdsa() {
        val signer = createSigner()
        Assertions.assertThat(signer.getId()).isEqualTo("builtin-ecdsa")
    }

    @Test
    fun getDisplayName_returnsBuiltInECDSA() {
        val signer = createSigner()
        Assertions.assertThat(signer.getDisplayName()).isEqualTo("Built-in (ECDSA)")
    }

    @Test
    fun getSettingsPagePath_returnsExpectedPath() {
        val signer = createSigner()
        Assertions.assertThat(signer.getSettingsPagePath()).isEqualTo("/plugins/oidc-jwt/signerSettings/builtin-ecdsa.jsp")
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

        val trackedJwk = ECKey.parse(jwkSlot.captured)
        Assertions.assertThat(trackedJwk.keyID).isEqualTo(kidSlot.captured)
        Assertions.assertThat(trackedJwk.toJSONObject()["d"]).isNull()
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
        Assertions.assertThat(jwkSlot.captured).doesNotContain("\"d\"")
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
        val json = ECKey.parse(signer.getCurrentKeyPublicJWK()).toJSONObject()

        Assertions.assertThat(json["d"]).isNull()
    }

    @Test
    fun getCurrentKeyPublicJWK_keyIdMatchesSignedJWT() {
        val signer = createSigner()
        val jwtKid = parseJWT(makeSimpleJWT(signer)).header.keyID

        val jwk = ECKey.parse(signer.getCurrentKeyPublicJWK())

        Assertions.assertThat(jwk.keyID).isEqualTo(jwtKid)
    }

    @Test
    fun getCurrentKeyPublicJWK_matchesJWKSCurrentKey() {
        val signer = createSigner()
        makeSimpleJWT(signer)

        val fromMethod = ECKey.parse(signer.getCurrentKeyPublicJWK())
        val fromJwks = JWKSet.parse(signer.getJWKS()).keys[0] as ECKey

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

    @Test
    fun rotateKey_withoutBuildManagementCapability_stillRotates() {
        // Generate a key while the node can still manage builds.
        val signer = createSigner()
        makeSimpleJWT(signer)

        // Drop the capability: rotation must still proceed (it only backs up and
        // deletes the current key; it does not generate a new one).
        every { serverResponsibility.canManageBuilds() } returns false

        signer.saveSettings(mutableMapOf("jwsAlgorithm" to "ES384"))

        Assertions.assertThat(Files.exists(keyFilePath())).isFalse()
        val rotatedFiles = listKeyDirFiles().filter { it.fileName.toString().contains("rotated-on") }
        Assertions.assertThat(rotatedFiles).hasSize(1)
    }
}
