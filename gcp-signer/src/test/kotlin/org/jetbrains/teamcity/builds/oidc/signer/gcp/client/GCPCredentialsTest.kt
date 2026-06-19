package org.jetbrains.teamcity.builds.oidc.signer.gcp.client

import com.google.auth.oauth2.GoogleCredentials
import com.google.auth.oauth2.ImpersonatedCredentials
import com.google.auth.oauth2.ServiceAccountCredentials
import jetbrains.buildServer.BaseTestCase
import org.assertj.core.api.Assertions
import org.testng.annotations.Test
import io.mockk.*

private const val SA_CLIENT_EMAIL = "tc-oidc-hsm-test-igor-brov-520@test-sandbox-please-ignore.iam.gserviceaccount.com"
private const val AUTH_SCOPE = "https://www.googleapis.com/auth/cloudkms"

private val SA_KEY_JSON = """
{
  "type": "service_account",
  "project_id": "test-sandbox-please-ignore",
  "private_key_id": "7af98a184f1fe98976b7281cead67a66bf9154c1",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwoqsqo1mQo+Ew\npXR0+KfZpPkBhZnTSPd6ms24ovGsv2GQmtcnERzInUualKqBXrBdkEaeiSapiqc5\nWekIRtsxs/USQAi7ZBN15C1on1Zk6ZBN01Z3ah9dKlu0AHiWEgkjf6XqZckRav5H\n9fqNpJCg3j/myW33nXEnKPelop3vxNv0Oj+H0XSvK6ne8hmtqRwfA6NlnEejKLCg\nOSN25zCMgVNmMjbiKA+UQVwKoVHoJ+3b7p0+lNOhx2sHmYfUfpj4pkpL0SBrwEFk\nj55rWA8fYNBbmpnhYwMitP9xW7H83wGLGQtpYSsJo6jOAuP9odj7jUyrAaBIH5V9\nJt3sbK4XAgMBAAECggEABHx1LXWNoktPPl2NaiUgmjoC6wN6JzAcvPvuiqh0y+bm\ncvZDzaW1HfFEyM3K0NNXVmECMieYmEjBu4apkQC/s3D3IfoHXr8JcX6UmqolVxXJ\niPh7ozfKSSL4xkcWyPT3T3QAAkaIh0043RoFvZA27icG53UpOldA1vZG5+mL6lmC\nQ3cfETDoff4kHIEFq/sulg+bGEhb5xc13T5N20BTHcANuXbTpv2WpyO3Zii5FiyS\ng1r6qr4i+BLFw/CSyLtUTvzY3cSfvPVXgoMrS/OpRyN82QWO4hy8xI3mAX/lqJRi\nSTxI/mIGxiaKsgWwnmgBLKF5QD592A+q4x17s3C+iQKBgQDrFBbx29zKsWt9C3JH\nmbk71Dcl8Ju3mEIJ2yQBSwJMpxyIhRe2/MJzGe+xgoBQSX27g57ABMSRp2Uvuas4\no2eHStSwWT5lBlRzxrnLaYScgSv4+kWguRTJXZksPjg0f7bqroxBLs5qR96pn0pn\npGqnkQSb67TvgA84n7CBE/jAzwKBgQDAWwqwv2pK9UVtPvwkDX/58H0a9x/Ba4v+\nSgRG687+fe/oj1nY5b6P/CVxVlsa29pOp8A2Kjunh9euxojrtpIuAZ2jsjWa7oV+\nH9h33LCTo4xut8gvHXGx63TJ/MkIEPOqB5pdsnULoViXb0HiYUVoOZpRlqi57Kqh\nzQaUEkpAOQKBgQDOZpc2yDp15Y1g/1nZsAlJlKzPLREsBA2HpddZI0jjkJ6m52TJ\nD+iTMySXkOOkmsJAj/Ik2orU8EsRuk2xrxdJXNSd+d2kyggAl22uQfljiK7ZLrVP\nxvGPVBUXGZIz1ib+qz8ORFCMVIoWGHw1v9C9S8DmPfBhkOjMaLmKu8RfVQKBgBXu\nS1m7eTLyo+fAtp6lq2GjuZ/JbSVwTZXAepxbZk49rYymS2gfSYrBBMPXRKvbRRiS\np6eFSSfgpQaYPCQjvKbiKEbxmor/htjKaLPBxaAPlYNKENjOUpgmcDpXR9RTmnRY\nSZFFN3MMAj3BwZE95dvsNVv4AWSxRwMLjSR0sWKBAoGAPcy+mogm4F7xrA7gCPVX\nzQ+gMjJM9lFCLN9WmeuoqisfppI3fkxchE9V16UNB4AyGDLBgFJGchsFmoi6VBXU\nuuGS/Gr0kzqGdyx+vUAhp8P8x7n101v6H6bGHHIFfCytFCkYbkUmC/3BFoZTdkmf\n6LauLe1fBTx5QrBUJ4KOERU=\n-----END PRIVATE KEY-----\n",
  "client_email": "$SA_CLIENT_EMAIL",
  "client_id": "115413607050253529298",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/tc-oidc-hsm-test-igor-brov-520%40test-sandbox-please-ignore.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
""".trimIndent()

class GCPCredentialsTest : BaseTestCase() {

    private inline fun <T> withMockedAdc(block: () -> T): T {
        val adc = ServiceAccountCredentials.fromStream(SA_KEY_JSON.byteInputStream())
        mockkStatic(GoogleCredentials::class)
        try {
            every { GoogleCredentials.getApplicationDefault() } returns adc
            return block()
        } finally {
            unmockkStatic(GoogleCredentials::class)
        }
    }

    private fun assertImpersonated(
        creds: ImpersonatedCredentials,
        targetPrincipal: String,
        delegates: List<String>,
    ) {
        Assertions.assertThat(creds.account).isEqualTo(targetPrincipal)
        val source = creds.sourceCredentials
        Assertions.assertThat(source).isInstanceOf(ServiceAccountCredentials::class.java)
        val sa = source as ServiceAccountCredentials
        Assertions.assertThat(sa.clientEmail).isEqualTo(SA_CLIENT_EMAIL)

        val asString = creds.toString()
        Assertions.assertThat(asString).contains("delegates=$delegates")
        Assertions.assertThat(asString).contains("scopes=[$AUTH_SCOPE]")
        Assertions.assertThat(asString).contains("lifetime=300")
    }

    @Test
    fun serviceAccount_typeName_isServiceAccountKey() {
        Assertions.assertThat(GCPCredentials.ServiceAccount(SA_KEY_JSON).typeName).isEqualTo("SERVICE_ACCOUNT_KEY")
    }

    @Test
    fun environment_typeName_isEnvironment() {
        Assertions.assertThat(GCPCredentials.Environment().typeName).isEqualTo("ENVIRONMENT")
    }

    @Test
    fun serviceAccount_noImpersonation_returnsScopedServiceAccountCredentials() {
        val result = GCPCredentials.ServiceAccount(SA_KEY_JSON).asGoogleCredentials()

        Assertions.assertThat(result).isInstanceOf(ServiceAccountCredentials::class.java)
        val sa = result as ServiceAccountCredentials
        Assertions.assertThat(sa.clientEmail).isEqualTo(SA_CLIENT_EMAIL)
        Assertions.assertThat(sa.scopes.toList()).isEqualTo(listOf(AUTH_SCOPE))
    }

    @Test
    fun environment_noImpersonation_returnsScopedAdcCredentials() {
        val result = withMockedAdc { GCPCredentials.Environment().asGoogleCredentials() }

        Assertions.assertThat(result).isInstanceOf(ServiceAccountCredentials::class.java)
        val sa = result as ServiceAccountCredentials
        Assertions.assertThat(sa.clientEmail).isEqualTo(SA_CLIENT_EMAIL)
        Assertions.assertThat(sa.scopes.toList()).isEqualTo(listOf(AUTH_SCOPE))
    }

    @Test
    fun serviceAccount_blankImpersonationChain_isTreatedAsNoImpersonation() {
        val result = GCPCredentials.ServiceAccount(SA_KEY_JSON, "   ").asGoogleCredentials()

        Assertions.assertThat(result).isInstanceOf(ServiceAccountCredentials::class.java)
    }

    @Test
    fun serviceAccount_singleImpersonatedAccount_returnsImpersonatedCredentialsWithEmptyDelegates() {
        val target = "impersonated@x.iam.gserviceaccount.com"

        val result = GCPCredentials.ServiceAccount(SA_KEY_JSON, target).asGoogleCredentials()

        Assertions.assertThat(result).isInstanceOf(ImpersonatedCredentials::class.java)
        assertImpersonated(
            result as ImpersonatedCredentials,
            targetPrincipal = target,
            delegates = emptyList(),
        )
    }

    @Test
    fun environment_singleImpersonatedAccount_returnsImpersonatedCredentialsWithEmptyDelegates() {
        val target = "impersonated@x.iam.gserviceaccount.com"

        val result = withMockedAdc { GCPCredentials.Environment(target).asGoogleCredentials() }

        Assertions.assertThat(result).isInstanceOf(ImpersonatedCredentials::class.java)
        assertImpersonated(
            result as ImpersonatedCredentials,
            targetPrincipal = target,
            delegates = emptyList(),
        )
    }

    @Test
    fun serviceAccount_multiAccountChain_returnsImpersonatedCredentialsWithDelegates() {
        val result = GCPCredentials.ServiceAccount(SA_KEY_JSON, "a@x.iam|b@x.iam|target@x.iam").asGoogleCredentials()

        Assertions.assertThat(result).isInstanceOf(ImpersonatedCredentials::class.java)
        assertImpersonated(
            result as ImpersonatedCredentials,
            targetPrincipal = "target@x.iam",
            delegates = listOf("a@x.iam", "b@x.iam"),
        )
    }

    @Test
    fun environment_multiAccountChain_returnsImpersonatedCredentialsWithDelegates() {
        val result = withMockedAdc {
            GCPCredentials.Environment("a@x.iam|b@x.iam|target@x.iam").asGoogleCredentials()
        }

        Assertions.assertThat(result).isInstanceOf(ImpersonatedCredentials::class.java)
        assertImpersonated(
            result as ImpersonatedCredentials,
            targetPrincipal = "target@x.iam",
            delegates = listOf("a@x.iam", "b@x.iam"),
        )
    }

    @Test
    fun serviceAccount_chainWithBlankSegments_filtersThemOut() {
        val result = GCPCredentials.ServiceAccount(SA_KEY_JSON, "||a@x.iam||target@x.iam|").asGoogleCredentials()

        Assertions.assertThat(result).isInstanceOf(ImpersonatedCredentials::class.java)
        assertImpersonated(
            result as ImpersonatedCredentials,
            targetPrincipal = "target@x.iam",
            delegates = listOf("a@x.iam"),
        )
    }
}
