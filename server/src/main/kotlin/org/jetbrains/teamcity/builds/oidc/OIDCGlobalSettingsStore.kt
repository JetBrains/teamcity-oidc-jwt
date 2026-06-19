package org.jetbrains.teamcity.builds.oidc

import org.jetbrains.teamcity.builds.oidc.util.XmlSettingsStore
import jetbrains.buildServer.serverSide.ServerPaths
import jetbrains.buildServer.serverSide.SettingsPersister
import jetbrains.buildServer.serverSide.impl.FileWatcherFactory
import org.jdom.Document
import org.jdom.Element

data class OIDCGlobalSettings(
    val activeSignerId: String = OIDCConstants.BuiltInRSASigner.ID,
    val overrideIssuer: String = "",
)

class OIDCGlobalSettingsStore(
    serverPaths: ServerPaths,
    fileWatcherFactory: FileWatcherFactory,
    settingsPersister: SettingsPersister,
) : XmlSettingsStore<OIDCGlobalSettings>(
    fileName = OIDCConstants.Settings.FILE_NAME,
    description = OIDCConstants.Settings.PERSIST_DESCRIPTION,
    default = OIDCGlobalSettings(),
    serverPaths = serverPaths,
    fileWatcherFactory = fileWatcherFactory,
    settingsPersister = settingsPersister,
) {

    override fun parseRoot(root: Element): OIDCGlobalSettings? {
        if (root.name != OIDCConstants.Settings.ROOT_ELEMENT) return null

        val activeSignerId = root.getAttributeValue(OIDCConstants.Settings.ACTIVE_SIGNER_ID_ATTR)
            ?.takeIf { it.isNotBlank() }
            ?: OIDCConstants.BuiltInRSASigner.ID

        val overrideIssuer = root.getChildTextTrim(OIDCConstants.Settings.OVERRIDE_ISSUER_ELEMENT) ?: ""

        return OIDCGlobalSettings(
            activeSignerId = activeSignerId,
            overrideIssuer = overrideIssuer,
        )
    }

    override fun toDocument(value: OIDCGlobalSettings): Document {
        val root = Element(OIDCConstants.Settings.ROOT_ELEMENT).apply {
            setAttribute(OIDCConstants.Settings.VERSION_ATTR, OIDCConstants.Settings.FILE_VERSION)
            setAttribute(OIDCConstants.Settings.ACTIVE_SIGNER_ID_ATTR, value.activeSignerId)
            if (value.overrideIssuer.isNotEmpty()) {
                addContent(Element(OIDCConstants.Settings.OVERRIDE_ISSUER_ELEMENT).setText(value.overrideIssuer))
            }
        }
        return Document(root)
    }
}
