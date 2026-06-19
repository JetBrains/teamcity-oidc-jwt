package org.jetbrains.teamcity.builds.oidc.signer.builtin

import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.ALLOWED_JWS_ALGORITHMS
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.ALLOWED_RSA_KEY_BITS
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.DEFAULT_JWS_ALGORITHM
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.DEFAULT_RSA_KEY_BITS
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.SETTINGS_JWS_ALGORITHM_ATTR
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.SETTINGS_RSA_KEY_BITS_ATTR
import org.jetbrains.teamcity.builds.oidc.util.XmlSettingsStore
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.SettingsPersister
import jetbrains.buildServer.serverSide.impl.FileWatcherFactory
import org.jdom.Document
import org.jdom.Element
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.SETTINGS_ROOT_ELEMENT
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInRSASigner.SETTINGS_VERSION_ATTR

data class BuiltInRSASettings(
    val jwsAlgorithm: String = DEFAULT_JWS_ALGORITHM,
    val rsaKeyBits: Int = DEFAULT_RSA_KEY_BITS,
)

class BuiltInRSASettingsStore(
    serverPaths: ServerPaths,
    fileWatcherFactory: FileWatcherFactory,
    settingsPersister: SettingsPersister,
) : XmlSettingsStore<BuiltInRSASettings>(
    fileName = OIDCConstants.BuiltInRSASigner.SETTINGS_FILE_NAME,
    description = OIDCConstants.BuiltInRSASigner.SETTINGS_PERSIST_DESCRIPTION,
    default = BuiltInRSASettings(),
    serverPaths = serverPaths,
    fileWatcherFactory = fileWatcherFactory,
    settingsPersister = settingsPersister,
) {

    override fun parseRoot(root: Element): BuiltInRSASettings? {
        if (root.name != SETTINGS_ROOT_ELEMENT) return null

        val storedAlg = root.getAttributeValue(SETTINGS_JWS_ALGORITHM_ATTR)
        val jwsAlgorithm = if (storedAlg != null && storedAlg in ALLOWED_JWS_ALGORITHMS) storedAlg else DEFAULT_JWS_ALGORITHM

        val storedBits = root.getAttributeValue(SETTINGS_RSA_KEY_BITS_ATTR)?.toIntOrNull()
        val rsaKeyBits = if (storedBits != null && storedBits in ALLOWED_RSA_KEY_BITS) storedBits else DEFAULT_RSA_KEY_BITS

        return BuiltInRSASettings(jwsAlgorithm = jwsAlgorithm, rsaKeyBits = rsaKeyBits)
    }

    override fun toDocument(value: BuiltInRSASettings): Document {
        val root = Element(SETTINGS_ROOT_ELEMENT).apply {
            setAttribute(SETTINGS_VERSION_ATTR, OIDCConstants.BuiltInRSASigner.SETTINGS_FILE_VERSION)
            setAttribute(SETTINGS_JWS_ALGORITHM_ATTR, value.jwsAlgorithm)
            setAttribute(SETTINGS_RSA_KEY_BITS_ATTR, value.rsaKeyBits.toString())
        }
        return Document(root)
    }
}
