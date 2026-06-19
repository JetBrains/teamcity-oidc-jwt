package org.jetbrains.teamcity.builds.oidc.signer.builtin

import org.jetbrains.teamcity.builds.oidc.OIDCConstants
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.ALLOWED_JWS_ALGORITHMS
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.DEFAULT_JWS_ALGORITHM
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.SETTINGS_JWS_ALGORITHM_ATTR
import org.jetbrains.teamcity.builds.oidc.util.XmlSettingsStore
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.SettingsPersister
import jetbrains.buildServer.serverSide.impl.FileWatcherFactory
import org.jdom.Document
import org.jdom.Element
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.SETTINGS_FILE_VERSION
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.SETTINGS_ROOT_ELEMENT
import org.jetbrains.teamcity.builds.oidc.OIDCConstants.BuiltInECDSASigner.SETTINGS_VERSION_ATTR

data class BuiltInECDSASettings(
    val jwsAlgorithm: String = DEFAULT_JWS_ALGORITHM,
)

class BuiltInECDSASettingsStore(
    serverPaths: ServerPaths,
    fileWatcherFactory: FileWatcherFactory,
    settingsPersister: SettingsPersister,
) : XmlSettingsStore<BuiltInECDSASettings>(
    fileName = OIDCConstants.BuiltInECDSASigner.SETTINGS_FILE_NAME,
    description = OIDCConstants.BuiltInECDSASigner.SETTINGS_PERSIST_DESCRIPTION,
    default = BuiltInECDSASettings(),
    serverPaths = serverPaths,
    fileWatcherFactory = fileWatcherFactory,
    settingsPersister = settingsPersister,
) {

    override fun parseRoot(root: Element): BuiltInECDSASettings? {
        if (root.name != SETTINGS_ROOT_ELEMENT) return null

        val storedAlg = root.getAttributeValue(SETTINGS_JWS_ALGORITHM_ATTR)
        val jwsAlgorithm = if (storedAlg != null && storedAlg in ALLOWED_JWS_ALGORITHMS) storedAlg else DEFAULT_JWS_ALGORITHM

        return BuiltInECDSASettings(jwsAlgorithm = jwsAlgorithm)
    }

    override fun toDocument(value: BuiltInECDSASettings): Document {
        val root = Element(SETTINGS_ROOT_ELEMENT).apply {
            setAttribute(SETTINGS_VERSION_ATTR, SETTINGS_FILE_VERSION)
            setAttribute(SETTINGS_JWS_ALGORITHM_ATTR, value.jwsAlgorithm)
        }
        return Document(root)
    }
}
