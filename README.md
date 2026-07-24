# TeamCity OIDC JWT plugin

It generates OpenID Connect JWT tokens for TeamCity builds for credential-less authentication in
- [AWS IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html) ([setup guide](./docs/aws/README.md))
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [Azure / Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [Oracle Cloud Infrastructure](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm)
- [Kubernetes v1.34+](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
- and any other OIDC token consumer.

Requires Java 17. Supports TeamCity 2025.11.1 and later.

## Features
- Two ways to provide JWTs:
  - on build start via build parameters
  - on demand during the build via HTTP request
- Support for a wide range of JWS algorithms: 
  - RS256, RS384, RS512
  - PS256, PS384, PS512
  - ES256, ES384, ES512
- Selectable RSA key size (2048, 3072, or 4096 bits)
- `.well-known` OIDC endpoints for token consumers
  - Configurable `iss` claim for installations inaccessible from the internet
- Private key rotation support (including JWK cache)
- Extensible architecture that allows implementing custom JWT signers
- Kotlin DSL bindings

## Quick Start
Download the latest release or [build from source](#Build),
[install it](https://www.jetbrains.com/help/teamcity/installing-additional-plugins.html), then use one of the following build features:

- `OIDC Token (in build parameters)` to pass the generated token via build parameters (or environment variables) on build start.
- `OIDC Token (on demand via HTTP request)` to issue one or many tokens via HTTP requests during the build.

If your server is not accessible from the internet, see [Support for installations inaccessible from the internet](#Support-for-installations-inaccessible-from-the-internet) 
section for additional required configuration steps.

Additional configuration of the token consumer may be required for builds to authenticate using OIDC tokens. 
Refer to the official documentation or the [AWS IAM setup guide](./docs/aws/README.md) to learn more.

## Usage

### OIDC token (in build parameters)

When this build feature is enabled, the plugin will generate a JWT on build start and pass it to the build
using the specified build parameter (`env.TEAMCITY_BUILD_OIDC_TOKEN` by default).

The token's `aud` claim is set to the `iss` by default, but can be specified in the build feature settings.

The default JWT lifetime is `(build configuration timeout + 10 minutes)`, or just 10 minutes
if the timeout is not set.

### OIDC Token (on demand via HTTP request)

Build configurations with this build feature can generate short-lived JWTs during the build
by sending a request to `%teamcity.serverUrl%/app/oidc-jwt/issue?aud=...`.
The caller is expected to use [build-level authentication credentials](https://www.jetbrains.com/help/teamcity/artifact-dependencies.html#build-level-auth)
like so:

```sh
curl -u "%system.teamcity.auth.userId%:%system.teamcity.auth.password%" "%teamcity.serverUrl%/app/oidc-jwt/issue" --get --data-urlencode="aud=https://teamcity.example.com/app/oidc-jwt"
```

The requester can issue tokens for multiple audiences by providing multiple `aud` query parameters.
The list of allowed `aud` claims can be specified in the build feature settings.

When no `aud` query parameter is provided, the issued token will contain all allowed audiences.

Tokens generated this way are valid for 5 minutes.

## Configuration

All settings related to token generation and signing are available under `Administration -> Integrations -> OIDC Tokens`
and require `Change server settings` permission to be edited.

### Support for installations inaccessible from the internet

Usually, OIDC token consumers expect the `iss` claim to point to a URL they can reach.
To validate the token signature, they append `/.well-known/openid-configuration` to 
the `iss` claim value and make an HTTP request there, expecting it to return a valid 
OIDC configuration JSON with a link to a JWKS endpoint. Public keys listed in the JWKS
response are used to verify the token signature.

Out of the box, the plugin provides such endpoints under `/app/oidc-jwt/.well-known/(jwks|openid-configuration)`.
These are publicly accessible with no authentication required. This does not work for TeamCity installations
that are not accessible from the internet (or to the token consumer in general).

Some consumers, such as GCP's Workload Identity Federation, allow you to upload a static JWKS file for token validation, 
but not all consumers support this. To address this, you can host `openid-configuration` and `jwks` externally 
(e.g., in an S3 bucket) and set up a custom `iss` claim with `Issuer URL` setting that will point to externally hosted files.

> [!NOTE]
> Remember, consumers will append `/.well-known/(jwks|openid-configuration)` to the `iss` claim value.
> 
> If you host `openid-configuration` under `https://oidc.example.com/random/path/.well-known/openid-configuration`,
> the issuer URL should be set to `https://oidc.example.com/random/path`. 

> [!NOTE]
> Most OIDC token consumers only support HTTPS when retrieving `openid-configuration` and JWKS.

### Signer configuration

The `Active Signer` dropdown controls which JWT signer will be used to sign the JWT. This setting applies to all
tokens generated by the server. Different signers will have different settings that will appear in the UI when 
a signer is chosen.

The plugin comes with two signers, `Built-in (ECDSA)` and `Built-in (RSA)`. Both will generate a private key stored
in the TeamCity data directory, encrypted with the server's secret key. The key can be regenerated at any time using
the manual key rotation button in the signer settings or by making an authorized POST request.

Regenerated keys are stored in the same directory as the current key so that you can revert accidental key rotation.

#### Built-in (RSA) signer

By default, the plugin uses a `Built-in (RSA)` JWT signer with a default key size of 3072 bits and the `RS256` algorithm
for wider compatibility.

The default key size was chosen to match the [minimal key size expected by NIST by 2030 at the time of writing](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)
and can be changed by picking a different key size from the `RSA key size` dropdown. Supported key sizes are 2048, 3072, and 4096 bits.
Changing the key size will rotate the key, storing the old one in the same directory. 

> [!WARNING]
> Key rotation does not invalidate existing tokens by default, unless you host JWKS externally. 
> See the [Key rotation](#Key-rotation) section for more details. 

You can also choose a different algorithm from the `JWT signature algorithm` dropdown. The signer supports 
all RSA-based algorithms defined by the [JWA specification](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1).
Changing the signing algorithm will not regenerate the key.

#### Built-in (ECDSA) signer

This signer is similar to the `Built-in (RSA)` signer, but uses ECDSA instead of RSA. 
By default, it uses the `ES256` algorithm (with `P-256` curve), but it can be changed to `ES384` or `ES512`
using the `JWT signature algorithm` dropdown.

> [!WARNING]
> Unlike RSA, changing the signing algorithm will rotate the key, because different ECDSA algorithms
> require different curves.

### Key rotation

Both built-in signers support key rotation via HTTP requests authorized with `Change server settings` permission.

> [!WARNING]
> Rotating the key in any way will NOT invalidate existing tokens due to JWK caching. Use the "Purge JWK cache" button
> in the signer settings (or make a `POST /app/oidc-jwt/jwk-cache/purge`) to clear the cache and invalidate all tokens
> signed with old keys.

> [!NOTE]
> Remember that installations that host their JWKS elsewhere (as described in the
> [Support for installations inaccessible from the internet](#Support-for-installations-inaccessible-from-the-internet) section)
> will need to have their externally hosted JWKS JSON files updated as well for new tokens to be valid.

#### Manual rotation

For manual rotation, use the "Rotate key now" button on the signer settings page. This will schedule a rotation task.
If the task fails for some reason, an error message will be displayed on the settings page on reload.

#### Programmatic rotation

To schedule a rotation task programmatically, make a request with valid credentials to one of the following endpoints:
- `/app/oidc-jwt/builtin-rsa/rotate` (for `Built-in (RSA)` signer)
- `/app/oidc-jwt/builtin-ecdsa/rotate` (for `Built-in (ECDSA)` signer)

Just like with the manual rotation, the requester must be authorized with `Change server settings` permission.

When the task is scheduled successfully, both endpoints will return a response with a task ID:
```
$ curl -H "Authorization: Bearer $TC_TOKEN" -X POST "$TC_HOST/app/oidc-jwt/builtin-rsa/rotate"
<response><task id="214617" /></response>%
```

You can use said ID to check the task status with a `GET` request to the same endpoint:
```
$ curl -H "Authorization: Bearer $TC_TOKEN" "$TC_HOST/app/oidc-jwt/builtin-rsa/rotate?taskID=214617"
<response><task id="214617" status="Success" /></response>%
```

Possible states:
- `Pending`: key rotation task is yet to be assigned to an executor
- `In progress on {node ID}`: a node currently processes the key rotation task
- `Success`: key successfully rotated
- `Failed: {error message}`: key rotation failed
- `Cancelled`: key rotation was canceled. Normally, this state should not be seen.

## Support for additional JWT signers

For improved security, it might be desirable to use an external JWT signer, such as an external HSM.
One example of such a signer is [Google Cloud JWT signer](/gcp-signer/README.md) that allows you to
sign JWTs using a private key stored in Google Cloud KMS.

To make your own signer, you need to implement the [`JWTSigner` interface](/api/src/main/java/org/jetbrains/teamcity/builds/api/JWTSigner.java)

## Example JWT content

Header:
```json
{
  "kid": "n3MborOUzTf3a_gXmcupHwwJXW4k85rJ5FSuAxdY9fw",
  "alg": "RS256"
}
```

Payload:
```json
{
  "iss": "https://teamcity.example.com/app/oidc-jwt",
  "sub": "_Root:project31:project32:bt32",
  "aud": "https://oidc.example.com/example-audience",
  "exp": 1777884506,
  "nbf": 1777883906,
  "iat": 1777883906,
  "jti": "10164325-813c-45ad-87b1-5f3574110f79",
  "build_type_id": "bt32",
  "build_type_external_id": "OidcTest_Subproject_LoginToAws",
  "project_id": "project32",
  "project_external_id": "OidcTest_Subproject",
  "build_id": 9001,
  "build_number": "14",
  "vcs_roots": [
    {
      "id": 4,
      "name": "https://github.com/brigaccess/empty.git#refs/heads/main",
      "revision": "a47e9e15ce37c74bea6a84bf7f5ebc58494cf945"
    }
  ],
  "triggered_by_user_id": 1,
  "triggered_by_user_name": "admin",
  "triggered_by_snapshot": false,
  "branch_name": "<default>",
  "branch_display_name": "main",
  "branch_is_default": true,
  "agent_id": 11,
  "agent_name": "ip_192.168.1.1",
  "agent_hostname": "192.168.1.1",
  "agent_pool": "Default",
  "agent_is_cloud": false,
  "agent_version": "207998",
  "agentless": false,
  "is_personal": false
}
```

`sub` claim contains the path to the build configuration in TeamCity project hierarchy. This allows you to 
authorize all build configurations from a certain project by using wildcard string matches. For example,
children of `project32` can be authorized by using `*:project32:*`.

> [!NOTE]
> For personal builds, each `sub` claim component will be prefixed with `user{id}_`, 
> where `{id}` is the user ID (`triggered_by_user_id`).
>
> In this particular example, `sub` claim for a personal build would be 
> `user1__Root:user1_project31:user1_project32:user1_bt32`.

## Build

- Clone the repository
- Run `mvn clean package`
- Upload the resulting `target/oidc-jwt.zip` file to TeamCity

## Core plugin current status

The plugin is currently in a stage between alpha and beta: we already use it on some of our internal production 
installations, but it hasn't been approved by the TeamCity team yet. It also hasn't been tested in multi-node environments.
