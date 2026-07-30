# Google Cloud Platform Configuration Guide

This document describes the steps required to set up Google Cloud Platform (GCP) access from TeamCity builds.

## Step 1. Set up a GCP Workload Identity Federation (WIF) pool and provider

> [!NOTE]
> This step briefly summarizes the following official GCP documentation pages:
> - [Creating a WIF pool](https://docs.cloud.google.com/iam/docs/manage-workload-identity-pools-providers#create-pools)
> - [Creating a WIF provider](https://docs.cloud.google.com/iam/docs/manage-workload-identity-pools-providers#create-provider)
> - [Configuring a third-party OIDC IdP](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)
>
> These pages describe additional ways to configure WIF using the CLI or REST API, as well as technical limitations
> imposed on identity providers.

### GCP prerequisites

To configure Workload Identity Federation, you will need a GCP project with billing enabled.
You will also need to enable the following APIs in your project:
- Identity and Access Management (IAM)
- Resource Manager
- Service Account Credentials
- Security Token Service (STS)

These APIs can be enabled using [this link](https://console.cloud.google.com/apis/enableflow?apiid=iam.googleapis.com,cloudresourcemanager.googleapis.com,iamcredentials.googleapis.com,sts.googleapis.com&redirect=https%3A//console.cloud.google.com).
Make sure you select the correct project.

### Step 1.1. Find the TeamCity issuer URL

Before you configure WIF, you need the issuer URL for your TeamCity installation. There are multiple ways to obtain it.

#### Get the issuer URL from the UI

1. Choose any build configuration you can edit.
2. Go to its settings page and switch to the **Build Features** tab.
3. Click **Add build feature**, then select either of the **OIDC Token** build features.
4. Copy the value of the **Issuer** field from the build feature configuration dialog.
5. Click **Cancel** to close the build feature settings.

#### Get the issuer URL from the `openid-configuration` JSON

1. Fetch the `%teamcity.serverUrl%/app/oidc-jwt/.well-known/openid-configuration` JSON.
2. Copy the value of the `issuer` field.

### Step 1.2. Create a WIF pool and provider

> [!TIP]
> A Terraform configuration example for this step is provided in [`main.tf`](./main.tf).

In GCP WIF, identity providers (including OIDC) are grouped into identity pools. A provider cannot exist without a pool,
so you will need to create one first. At the time of writing (2026-07-29), the pool creation wizard also creates
a provider, so we will use it to configure both the pool and the provider.

> [!WARNING]
> We strongly recommend creating a separate pool for each TeamCity installation to avoid misconfigurations
> that could lead to unintended privilege escalation. See the [Google Cloud WIF best practices guide](https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation#avoid-subject-collisions)
> to learn more.

1. Go to the [**IAM & Admin -> Workload Identity Federation**](https://console.cloud.google.com/iam-admin/workload-identity-pools)
   page in the GCP console. Make sure you are on the **Workload Identity Federation** page, not the **Work*force* Identity Federation** page.
2. At the top of the page, click **Create pool**.
3. Enter a name for the pool. The pool ID will be derived automatically, but can be changed using the **Edit** button.
   Optionally, fill in the **Description** field. Click **Continue** to proceed to provider configuration.
4. Select **OpenID Connect (OIDC)** as the provider type. A **Provider details** section will appear.
5. Enter the name for the provider. Paste the issuer URL into the **Issuer (URL)** field.
6. *(Optional)* If the issuer URL is not available from the internet, upload the JWKS file. The most up-to-date file
   can be fetched from `%teamcity.serverUrl%/app/oidc-jwt/.well-known/jwks`.
7. Configure the list of accepted audiences:
   - Choose the **Allowed audiences** option and specify the issuer URL to match the default audience used by build features.
   - If the issuer URL is longer than 256 characters, you can either pick an arbitrary audience string
     or choose the **Default audience** option. You will then need to provide the audience value when configuring
     build features.
8. Click **Continue** to configure the provider attributes.
9. Enter `assertion.sub` into the **OIDC 1** field to the right of `google.subject`.
10. Click the **Add mapping** button, then enter `google.groups` into the **Google 2** field
    and `assertion.sub.split(':')` into the **OIDC 2** field.
11. *(Optional)* Configure additional attributes and attribute conditions.
    Refer to the [Principal references](#principal-references) for more details.
12. Click **Save**. The pool and provider are created.

## Step 2. Set up OIDC for a TeamCity build

### Using the UI
1. Go to the build configuration settings.
2. Switch to the **Build Features** tab.
3. Click the **Add build feature** button.
4. Look for **OIDC Token (in build parameters)** or **OIDC Token (on demand via HTTP request)**, depending on
   how you want to obtain the token in the build. If you intend to use the `gcloud` CLI, choose the latter.
5. Specify the audience configured in step 7 of [Step 1.2 Create a WIF pool and provider](#step-12-create-a-wif-pool-and-provider).
6. Configure the remaining parameters as needed.
7. Copy the **`sub` claim** value and save your changes.

### Using Kotlin DSL
1. Add either `oidcTokenInParams` or `oidcTokenOnDemand` to the build features block of your build type definition.
   If you intend to use the `gcloud` CLI, choose the latter.
2. Specify the audience configured in step 7 of [Step 1.2 Create a WIF pool and provider](#step-12-create-a-wif-pool-and-provider)
   using the `audiences` parameter.
3. Apply the DSL changes.
4. Obtain the **`sub` claim** value from the UI as described in the [`Using the UI` section](#using-the-ui) or programmatically:
    - The default value follows the root-to-child hierarchy of internal IDs (for example, `_Root:project123:project4567:bt31337`).
      To fetch these IDs via the REST API, query
      `%teamcity.serverUrl%/app/rest/buildTypes?locator=id:{BUILD_TYPE_ID}&fields=buildType(internalId,project(internalId,parentProject(internalId,parentProject(internalId,name))))`.
      Depending on the depth of the project hierarchy, you might need to nest `parentProject(internalId,name)`
      multiple times until you reach the `_Root` project.

> [!WARNING]
> The `sub` value can change with DSL updates if the [`uuid` parameter](https://teamcity.jetbrains.com/app/dsl-documentation/root/build-type-settings/uuid.html)
> is not specified and the [`Id` parameter](https://teamcity.jetbrains.com/app/dsl-documentation/root/id/index.html)
> is changed for the build type.

## Step 3. Configure GCP IAM

Now that the Workload Identity Federation pool and provider are set up, you can configure IAM to assign roles
to the pool's principals.

1. Go to the desired IAM configuration page:
    - [**IAM & Admin -> IAM**](https://console.cloud.google.com/iam-admin/iam) for project-wide roles.
    - **IAM & Admin -> Service Accounts -> [click the desired Service Account] -> Principals with access**
      to grant access to a specific service account.
    - **Cloud Storage -> [click the desired bucket] -> Permissions** to grant access to a specific bucket.
    - Any other permissions page where you can add principals.
2. Click the **Grant access** button.
3. Select the required role from the **Select a role** dropdown. Repeat this step to add more roles.
4. *(Optional)* Specify the IAM conditions for the role assignment.
5. Specify IAM principals using the build's **`sub` claim** value that you copied in [Step 2](#step-2-set-up-oidc-for-a-teamcity-build)
   (replace `PROJECT_NUMBER` with the GCP project number and `POOL_ID` with the pool ID from [Step 1.2](#step-12-create-a-wif-pool-and-provider)):
     - Use `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/bt31337`
       to grant access to a build configuration with a `sub` claim of `_Root:project123:project4567:bt31337`.
     - Use `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/project4567`
       to grant access to all build configurations in the `project4567` project and its subprojects.
     - See the [Principal references](#principal-references) and [Example principal IDs](#example-principal-ids)
       sections for more examples.
6. Click **Save** to apply the changes.

## Step 4. Access GCP resources

### Using the `gcloud` CLI

The `gcloud` CLI can retrieve tokens from an HTTP endpoint. The following example accesses GCP resources
using tokens issued through the **OIDC Token (on demand via HTTP request)** build feature:

```bash
#!/bin/bash
set -euo pipefail

export GCP_PROJECT_NUMBER="PROJECT_NUMBER"
export GCP_WIF_POOL_ID="POOL_ID"
export GCP_WIF_PROVIDER_ID="PROVIDER_ID"

export CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=$(mktemp)
chmod 600 "$CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"
trap 'rm -f "$CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"' EXIT

gcloud iam workload-identity-pools create-cred-config \
    "projects/$GCP_PROJECT_NUMBER/locations/global/workloadIdentityPools/$GCP_WIF_POOL_ID/providers/$GCP_WIF_PROVIDER_ID" \
    --output-file="$CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE" \
    --credential-source-url="%teamcity.serverUrl%/app/oidc-jwt/issue" \
    --credential-source-headers="Authorization=Basic $(echo '%system.teamcity.auth.userId%:%system.teamcity.auth.password%' | base64 -w 0 -)"

# You can now use the CLI
gcloud compute instances list
```

### Using Application Default Credentials without the `gcloud` CLI

Some GCP-related applications use [Application Default Credentials (ADC)](https://docs.cloud.google.com/docs/authentication/application-default-credentials)
to authenticate with GCP. For these applications, you can create a credential configuration file without using `gcloud`.
The following script uses the **OIDC Token (on demand via HTTP request)** build feature to obtain a token:

```bash
#!/bin/bash
set -euo pipefail

export GCP_PROJECT_NUMBER="PROJECT_NUMBER"
export GCP_WIF_POOL_ID="POOL_ID"
export GCP_WIF_PROVIDER_ID="PROVIDER_ID"

export CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=$(mktemp)
trap 'rm -f "$CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"' EXIT

cat > "$CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE" <<EOF
{
  "universe_domain": "googleapis.com",
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/$GCP_PROJECT_NUMBER/locations/global/workloadIdentityPools/$GCP_WIF_POOL_ID/providers/$GCP_WIF_PROVIDER_ID",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "url": "%teamcity.serverUrl%/app/oidc-jwt/issue",
    "headers": {
      "Authorization": "Basic $(echo '%system.teamcity.auth.userId%:%system.teamcity.auth.password%' | base64 -w 0 -)"
    }
  },
  "token_info_url": "https://sts.googleapis.com/v1/introspect"
}
EOF
export GOOGLE_APPLICATION_CREDENTIALS="$CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"

# You can now use any GCP-related software
terraform apply
```

### Exchange tokens manually

As a last resort, you can manually exchange the issued token by sending a series of HTTP requests.
See [`manual-token-exchange.sh`](manual-token-exchange.sh) for an example.

## Principal references

Workload Identity Federation pools map the claims in provider tokens to IAM principals using the attribute mapping rules.
These rules are written in [Common Expression Language (CEL)](https://github.com/cel-expr/cel-spec/blob/master/doc/intro.md#introduction).

Each provider can have three types of rules:
- A mandatory `google.subject` rule that should evaluate to a single value
- An optional `google.groups` rule that should evaluate to a (potentially empty) list
- Optional `attribute.*` rules that evaluate to a single value

For OIDC, every token claim can be referenced in a rule using the `assertion.<claim_name>` syntax.

IAM can then use the resulting values in the following principal IDs:

### `google.subject` reference
```
principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/VALUE
```

This principal matches token bearers for which a CEL expression specified in the `google.subject` attribute mapping
returns `VALUE`.

In the example configuration, the CEL expression is simply `assertion.sub`. Therefore, this principal matches any valid 
token that has a `sub` claim equal to `VALUE` and was issued by one of the providers in the pool.

### `google.groups` reference
```
principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/VALUE
```

This principal matches valid tokens for which the `google.groups` mapping expression returns a list containing `VALUE`.

The `assertion.sub.split(':')` expression used for the example `google.groups` mapping splits the `sub` claim
at each colon and returns a list. If the `sub` claim is `_Root:project123:project4567:bt31337`, it returns
`['_Root', 'project123', 'project4567', 'bt31337']`.

The following principals are therefore granted access:
- `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/_Root`
- `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/project123`
- `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/project4567`
- `principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/bt31337`

### Custom attributes reference
```
principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.ATTRIBUTE_NAME/ATTRIBUTE_VALUE
```

This principal matches valid tokens for which the CEL mapping expression for `attribute.ATTRIBUTE_NAME`
evaluates to `ATTRIBUTE_VALUE`. You can specify [up to 50 custom attributes](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers#WorkloadIdentityPoolProvider.FIELDS.attribute_mapping).

These mappings can be simple JWT claim references:
```
attribute.bt_external_id = assertion.build_type_external_id
```
They can also use more complex expressions:
```
attribute.sub_with_branch = assertion.branch_name == null ? assertion.sub : assertion.sub+":"+string(assertion.branch_name)
```
```
attribute.sub_with_user_ids = assertion.triggered_by_user_id == null ? assertion.sub : assertion.sub.split(":").map(x, x+":u"+string(assertion.triggered_by_user_id) + "_").join(':')
```

This works around IAM's inability to check multiple conditions at once.
Define an attribute expression that combines the required conditions and then check its value in the IAM configuration.

You can find more examples of CEL rules [in the official documentation](https://docs.cloud.google.com/iam/docs/workload-identity-federation#mapping).
An example JWT issued by the plugin can be found [here](https://github.com/JetBrains/teamcity-oidc-jwt#example-jwt-content).

### Wildcard reference
```
principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/*
```

This principal matches all tokens from all providers in the pool. Every bearer of a valid token accepted by a provider
in this pool is granted access, regardless of the attribute mapping rules.

## Example principal IDs

These examples assume that:
- you have configured the suggested `google.subject` and `google.groups` attribute mapping rules in [Step 1.2](#step-12-create-a-wif-pool-and-provider).
- the `sub` claim of the build is `_Root:project123:project4567:bt31337`.

Replace `PROJECT_NUMBER` with the GCP project number and `POOL_ID` with the WIF pool ID.

### Assign permissions to a single build type
Specify the following principal ID string:
```
principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/bt31337
```

To revoke permissions from a build type when it is moved within the project hierarchy, use the entire `sub` claim:
```
principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/_Root:project123:project4567:bt31337
```

### Assign permissions to multiple build types
Specify multiple principal IDs as described in [Assign permissions to a single build type](#assign-permissions-to-a-single-build-type).

### Assign permissions to all build types of a project and its subprojects
Assign permissions to all build configurations in a specific project _and its subprojects_ using this principal:
```
principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/project123
```

### Personal builds
The `sub` claim for a personal build differs from the claim for a regular build to prevent abuse.

To grant permissions to a single user's builds:
1. Find the user's numeric ID on the TeamCity server.
2. Select one of the examples above.
3. Insert the `u{ID}_` prefix immediately after `group/`, like this:
```
principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/group/u42_bt31337
```

For principal IDs that contain `subject/`, insert the prefix immediately after `subject/` and after every colon:
```
principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/subject/u42__Root:u42_project123:u42_project4567:u42_bt31337
```
