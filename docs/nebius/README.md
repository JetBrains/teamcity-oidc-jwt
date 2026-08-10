# Nebius AI Cloud Configuration Guide

This document describes the steps required to set up [Nebius AI Cloud](https://docs.nebius.com/) access
from TeamCity builds.

Nebius does not have a separate identity pool resource. Instead, you create a
[federated credential](https://docs.nebius.com/cli/reference/iam/federated-credentials/index) that binds one external
OIDC identity — a single TeamCity build configuration — to one service account. A build then exchanges its OIDC token
for a Nebius IAM access token and uses that token like any other IAM token.

> [!TIP]
> A Terraform configuration example for steps 2-4 is provided in [`main.tf`](./main.tf).

The examples below use the [Nebius CLI](https://docs.nebius.com/cli). Every step can also be performed in the
[Nebius console](https://console.nebius.com/) or through the API.

## Step 1. Set up OIDC for a TeamCity build

### Using the UI

1. Go to the build configuration settings.
2. Switch to the **Build Features** tab.
3. Click the **Add build feature** button.
4. Look for **OIDC Token (in build parameters)** or **OIDC Token (on demand via HTTP request)**, depending on
   how you want to obtain the token during the build.
5. Leave the default audience. Nebius does not check the `aud` claim, see
   [How Nebius validates the token](#how-nebius-validates-the-token).
6. Configure the remaining parameters as needed.
7. Copy the values of the **Issuer** and **`sub` claim** fields.
8. Save your changes using the **Save** button.

### Using Kotlin DSL

1. Add either `oidcTokenInParams` or `oidcTokenOnDemand` to the build features block of your build type definition.
2. Apply the DSL changes.
3. Obtain the values of the **Issuer** and **`sub` claim** fields from the UI as described in the
   [`Using the UI` section](#using-the-ui) or programmatically:
    - The **Issuer** value can be fetched from the `issuer` field of the
      `%teamcity.serverUrl%/app/oidc-jwt/.well-known/openid-configuration` JSON.
    - The default `sub` claim follows the root-to-child hierarchy of internal IDs (for example,
      `_Root:project123:project4567:bt31337`). To fetch these IDs via the REST API, query
      `%teamcity.serverUrl%/app/rest/buildTypes?locator=id:{BUILD_TYPE_ID}&fields=buildType(internalId,project(internalId,parentProject(internalId,parentProject(internalId,name))))`.
      Depending on the depth of the project hierarchy, you might need to nest `parentProject(internalId,name)` multiple
      times until you reach the `_Root` project.

> [!WARNING]
> The `sub` value can change with DSL updates if the [`uuid` parameter](https://teamcity.jetbrains.com/app/dsl-documentation/root/build-type-settings/uuid.html)
> is not specified and the [`Id` parameter](https://teamcity.jetbrains.com/app/dsl-documentation/root/id/index.html)
> is changed for the build type.

Because a federated credential matches the `sub` claim exactly, a build configuration loses access when it is moved
within the project hierarchy. See [Granting access to several build configurations](#granting-access-to-several-build-configurations).

## Step 2. Create a service account

Builds authenticate as a Nebius service account. Create one in the project that holds the resources
the build needs:

```bash
export NEBIUS_PROJECT_ID="project-e00example"

nebius iam service-account create \
    --parent-id "$NEBIUS_PROJECT_ID" \
    --name teamcity-ci \
    --description "Impersonated by TeamCity builds via OIDC federation"
```

Take note of the returned `metadata.id` value (`serviceaccount-e00…`):

```bash
export NEBIUS_SERVICE_ACCOUNT_ID="serviceaccount-e00example"
```

> [!TIP]
> Create a separate service account per trust boundary rather than one shared account for the whole server.
> Permissions are granted to the service account, so every build configuration mapped to it gets all of its
> permissions.

## Step 3. Create a federated credential

The federated credential maps the `sub` claim of the TeamCity token to the service account:

```bash
nebius iam federated-credentials create \
    --parent-id "$NEBIUS_PROJECT_ID" \
    --name teamcity-bt31337 \
    --oidc-provider-issuer-url "https://teamcity.example.com/app/oidc-jwt" \
    --federated-subject-id "_Root:project123:project4567:bt31337" \
    --subject-id "$NEBIUS_SERVICE_ACCOUNT_ID"
```

- `--oidc-provider-issuer-url` is the **Issuer** value from [Step 1](#step-1-set-up-oidc-for-a-teamcity-build).
  Nebius appends `/.well-known/openid-configuration` to it and follows `jwks_uri` to fetch the signing keys, so this URL
  must be reachable from Nebius.
- `--federated-subject-id` is the **`sub` claim** value from [Step 1](#step-1-set-up-oidc-for-a-teamcity-build).
- `--subject-id` is the service account that the build impersonates.

If your TeamCity server is not reachable from the internet, either host the discovery documents externally as described
in the [main README](../../README.md#support-for-installations-inaccessible-from-the-internet), or pass the key set
inline:

```bash
nebius iam federated-credentials create \
    --parent-id "$NEBIUS_PROJECT_ID" \
    --name teamcity-bt31337 \
    --oidc-provider-issuer-url "https://teamcity.example.com/app/oidc-jwt" \
    --oidc-provider-jwk-set-json "$(curl -sS https://teamcity.example.com/app/oidc-jwt/.well-known/jwks)" \
    --federated-subject-id "_Root:project123:project4567:bt31337" \
    --subject-id "$NEBIUS_SERVICE_ACCOUNT_ID"
```

> [!WARNING]
> An inline key set is a copy, not a reference. You must update the federated credential with
> `nebius iam federated-credentials update` every time you rotate the signing key, or builds will stop authenticating.
> The issuer URL is still required in this case.

> [!NOTE]
> Nebius reads at most 50 keys from a key set, and limits the discovery and JWKS responses to 100 KB each.

## Step 4. Grant the service account access

A fresh service account has no permissions. Grant it a role on the resources the build needs — this example uses a
[Container Registry](https://docs.nebius.com/container-registry) registry:

```bash
nebius registry create \
    --parent-id "$NEBIUS_PROJECT_ID" \
    --name teamcity-images

# Take metadata.id from the output of the command above.
export NEBIUS_REGISTRY_ID="<registry id>"

nebius iam access-permit create \
    --parent-id "$NEBIUS_SERVICE_ACCOUNT_ID" \
    --resource-id "$NEBIUS_REGISTRY_ID" \
    --role editor
```

For Container Registry, `viewer` allows listing and pulling images, while `editor` also allows pushing and modifying
them. See the [Nebius roles reference](https://docs.nebius.com/iam/authorization/roles) for the full list.

## Step 5. Push an image to Container Registry from a build

This is the most common use case: building an image and pushing it without storing any Docker credentials on the agent.

First, look up the registry FQDN in the `status` section of the registry — it already includes both the regional
host and the registry path segment used in image tags:

```bash
nebius registry get --id "$NEBIUS_REGISTRY_ID" --format yaml
# status:
#   registry_fqdn: cr.eu-north1.nebius.cloud/e00example
```

Then add a command line build step that uses [`docker-login.sh`](./docker-login.sh):

```bash
#!/bin/bash
set -euo pipefail

export NEBIUS_REGISTRY_FQDN="cr.eu-north1.nebius.cloud/e00example"

# Exchanges %env.TEAMCITY_BUILD_OIDC_TOKEN% for a Nebius IAM access token and
# runs `docker login`. Must be sourced: it points DOCKER_CONFIG at a temporary
# directory that is wiped when the build step ends.
. ./docker-login.sh

docker build -t "$NEBIUS_REGISTRY_FQDN/my-image:%build.number%" .
docker push "$NEBIUS_REGISTRY_FQDN/my-image:%build.number%"
```

The script works with either build feature. With **OIDC Token (in build parameters)** it picks up
`TEAMCITY_BUILD_OIDC_TOKEN` automatically. To use **OIDC Token (on demand via HTTP request)** instead, leave that
parameter unset and export the build-level credentials so the script can request a token itself:

```bash
export TC_BUILD_CREDENTIALS="%system.teamcity.auth.userId%:%system.teamcity.auth.password%"
export TC_SERVER_URL="%teamcity.serverUrl%"
```

> [!WARNING]
> `docker login` stores the access token in `$DOCKER_CONFIG/config.json` in plain text (base64, not encrypted).
> On a shared or non-ephemeral agent, keep the `DOCKER_CONFIG` override from the script so the token does not
> land in the agent user's `~/.docker/config.json` and outlive the build.

### Doing the exchange by hand

The exchange is a plain [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) token exchange:

```bash
curl -sS -X POST "https://auth.eu.nebius.com/oauth2/token/exchange" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
    --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
    --data-urlencode "subject_token=$TEAMCITY_BUILD_OIDC_TOKEN" \
    | jq -r '.access_token'
```

> [!NOTE]
> The endpoint only accepts `application/x-www-form-urlencoded`; sending JSON returns HTTP 415.

The response is a standard token exchange response:

```json
{
  "access_token": "...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 43200
}
```

The access token is valid for 12 hours and can be passed to the Nebius API as a `Bearer` token or to any tool that
accepts an IAM token, for example via the `NEBIUS_IAM_TOKEN` environment variable.

> [!CAUTION]
> Prefer the file-based form used in [`docker-login.sh`](./docker-login.sh)
> (`--data-urlencode "subject_token@FILE"`) over passing the token on the command line: arguments are visible to
> every user on the agent through the process list.

## Step 6. Use other Nebius services

### Using the Nebius CLI

The CLI can perform the exchange itself. Point a profile at a file containing the OIDC token, and the CLI re-reads
that file and exchanges it whenever it needs a token:

```bash
#!/bin/bash
set -euo pipefail

export NEBIUS_SERVICE_ACCOUNT_ID="serviceaccount-e00example"
export NEBIUS_PROJECT_ID="project-e00example"

# Keep the profile and the cached IAM token inside the build's working directory.
export HOME="$(pwd)/.nebius-home"
mkdir -p "$HOME"

umask 077
printf '%s' "$TEAMCITY_BUILD_OIDC_TOKEN" > "$HOME/oidc-token.jwt"

nebius profile create teamcity \
    --endpoint api.nebius.cloud \
    --parent-id "$NEBIUS_PROJECT_ID" \
    --service-account-id "$NEBIUS_SERVICE_ACCOUNT_ID" \
    --federated-subject-credentials-file-path "$HOME/oidc-token.jwt" \
    --skip-auth

# You can now use the CLI
nebius compute instance list --parent-id "$NEBIUS_PROJECT_ID"
```

> [!NOTE]
> The CLI caches the exchanged IAM token in `$HOME/.nebius/credentials.yaml`. Overriding `HOME` as shown above keeps
> that cache out of the agent user's home directory, which matters on non-ephemeral agents.

Because the CLI reads the token file lazily, this also works with the **OIDC Token (on demand via HTTP request)**
build feature — refresh the file before a long-running command if the OIDC token may have expired.

### Using the token directly

The CLI also picks up a pre-issued token from the `NEBIUS_IAM_TOKEN` environment variable, which takes precedence over
the profile's own authentication. A profile is still required — the CLI reads the API endpoint from it — but it does
not need any credentials, so it can simply be written out:

```bash
nebius_config="$(pwd)/.nebius-config.yaml"

cat > "$nebius_config" <<EOF
default: teamcity
profiles:
    teamcity:
        endpoint: api.nebius.cloud
        parent-id: $NEBIUS_PROJECT_ID
EOF

# See "Doing the exchange by hand" above.
NEBIUS_IAM_TOKEN=$(./exchange.sh)
export NEBIUS_IAM_TOKEN

nebius --config "$nebius_config" storage bucket list --parent-id "$NEBIUS_PROJECT_ID"
```

The same token works with anything that talks to the Nebius API directly:

```bash
curl -sS -H "Authorization: Bearer $NEBIUS_IAM_TOKEN" ...
```

## How Nebius validates the token

A federated credential accepts a token when **all** of the following hold:

- the signature verifies against the key set published by (or configured for) the issuer;
- the `iss` claim matches `--oidc-provider-issuer-url` exactly;
- the `sub` claim matches `--federated-subject-id` exactly;
- the token is within its `nbf`/`exp` window.

> [!CAUTION]
> Nebius federated credentials have **no audience field** — the `aud` claim is not checked. Any valid, unexpired token
> from the configured issuer with a matching `sub` is accepted, whatever audience it was minted for.
>
> In practice this means a token your build obtained for a *different* consumer (AWS, GCP, an internal service) is also
> valid against Nebius. If that matters to you, do not reuse one TeamCity issuer across trust boundaries you want to
> keep separate, and treat every issued token as equivalent to the service account's credentials.

The exact `sub` match is the real control, and it is a tight one: one federated credential authorizes exactly one build
configuration, at exactly one place in the project hierarchy. There are no wildcards.

Personal builds are excluded by default: the plugin prefixes every component of the `sub` claim for personal builds
(see the [note in the main README](../../README.md#example-jwt-content)), so they will not match a federated credential
created for regular builds. Create a separate federated credential with the prefixed `sub` if you want to allow them.

## Granting access to several build configurations

Because matching is exact and wildcard-free, each build configuration needs its own federated credential. Several
credentials can point at the same service account:

```bash
for sub in \
    "_Root:project123:project4567:bt31337" \
    "_Root:project123:project4567:bt31338" \
    "_Root:project831:project842:bt93754"
do
    nebius iam federated-credentials create \
        --parent-id "$NEBIUS_PROJECT_ID" \
        --name "teamcity-${sub##*:}" \
        --oidc-provider-issuer-url "https://teamcity.example.com/app/oidc-jwt" \
        --federated-subject-id "$sub" \
        --subject-id "$NEBIUS_SERVICE_ACCOUNT_ID"
done
```

To review what is currently trusted (`--all` is needed because the listing is paginated at 10 items by default):

```bash
nebius iam federated-credentials list --parent-id "$NEBIUS_PROJECT_ID" --all --format yaml
```

Remember to delete the federated credential when a build configuration is deleted or moved, and to grant permissions
to a service account rather than to individual credentials — every build configuration mapped to a service account
shares its permissions.

## Troubleshooting

Errors from the exchange endpoint include `requestId` and `traceId`. Quote them when contacting
[Nebius support](https://docs.nebius.com/support).

| Error | Likely cause |
| --- | --- |
| `Unable to parse token as JWT` | The `subject_token` is empty or truncated. Check that the build feature is enabled and that the parameter reached the build step. |
| `Content-Type 'application/json' is not supported` (HTTP 415) | The request body must be `application/x-www-form-urlencoded`. |
| Signature or key errors | Nebius cannot reach `<issuer>/.well-known/openid-configuration`, or the signing key was rotated after an inline `jwk_set_json` was configured. |
| `PERMISSION_DENIED` on an API call after a successful exchange | The exchange worked and the service account was impersonated, but it has no role on the resource. Revisit [Step 4](#step-4-grant-the-service-account-access). |
| Exchange fails only for personal builds | The `sub` claim of a personal build is prefixed and does not match the federated credential. |

To see which identity a token actually maps to, decode the payload of the TeamCity token and compare its `iss` and
`sub` with the federated credential:

```bash
jq -R 'split(".") | .[1] | @base64d | fromjson | {iss, sub, aud, exp}' <<<"$TEAMCITY_BUILD_OIDC_TOKEN"
```
