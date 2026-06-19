package org.jetbrains.teamcity.builds.oidc.signer.gcp.client.util

import org.jetbrains.teamcity.builds.oidc.signer.gcp.CloudKMSConstants.Settings.KMS_RESOURCE_NAME_REGEX
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSInvalidResourceNameException
import org.jetbrains.teamcity.builds.oidc.signer.gcp.exception.CloudKMSNoResourceNameException

private val kmsResourceNameRegex = Regex(KMS_RESOURCE_NAME_REGEX)

fun validateKeyResourceName(resourceName: String) {
    if (resourceName.isBlank()) {
        throw CloudKMSNoResourceNameException()
    } else if (!kmsResourceNameRegex.matches(resourceName)) {
        throw CloudKMSInvalidResourceNameException(resourceName)
    }
}
