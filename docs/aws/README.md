# AWS Configuration Guide

This document describes the steps required to set up AWS access from TeamCity builds.

## Step 1. Set up OIDC for a TeamCity build

### Using the UI

1. Go to the build configuration settings.
2. Switch to the **Build Features** tab.
3. Click the **Add build feature** button.
4. Look for **OIDC Token (in build parameters)** or **OIDC Token (on demand via HTTP request)**, depending on
   how you want to obtain the token during the build.
5. Choose an audience for the token: the default value is suitable in most cases, but you can specify any unique string
   consisting of up to 255 alphanumeric or `:_.-/` characters. **AWS does not support multiple audiences in a single token.**
6. Configure the remaining parameters as needed.
7. Copy the values of the **Audience**, **Issuer**, and **`sub` claim** fields.
8. Save your changes using the **Save** button.

### Using Kotlin DSL

1. Add either `oidcTokenInParams` or `oidcTokenOnDemand` to the build features block of your build type definition.
2. Choose an audience for the token using the `audiences` parameter. When not specified, the default value (issuer URL)
   is used. AWS requires the audience to consist of up to 255 alphanumeric or `:_.-/` characters and
   **does not support multiple audiences in a single token**.
3. Apply the DSL changes.
4. Obtain the values of **Issuer** and  **`sub` claim** fields from the UI as described in the [`Using the UI` section](#using-the-ui) or programmatically:
    - The **Issuer** value can be fetched from the `issuer` field of the `%teamcity.serverUrl%/app/oidc-jwt/.well-known/openid-configuration` JSON.
    - The default `sub` claim follows the root-to-child hierarchy of internal IDs (for example, `_Root:project123:project4567:bt31337`).
      To fetch these IDs via the REST API, query
      `%teamcity.serverUrl%/app/rest/buildTypes?locator=id:{BUILD_TYPE_ID}&fields=buildType(internalId,project(internalId,parentProject(internalId,parentProject(internalId,name))))`.
      Depending on the depth of the project hierarchy, you might need to nest `parentProject(internalId,name)` multiple
      times until you reach the `_Root` project.

> [!WARNING]
> The `sub` value can change with DSL updates if the [`uuid` parameter](https://teamcity.jetbrains.com/app/dsl-documentation/root/build-type-settings/uuid.html)
> is not specified and the [`Id` parameter](https://teamcity.jetbrains.com/app/dsl-documentation/root/id/index.html) is changed for the build type.

## Step 2. Configure AWS IAM

To perform this step, you will need sufficient permissions to change identity provider settings.

> [!NOTE]
> This step briefly summarizes [the official AWS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
> on how to create an OIDC identity provider. Refer to the linked documentation page for more detailed instructions
> on creating an OIDC identity provider using the AWS Management Console, the AWS CLI, or API.

> [!TIP]
> A Terraform configuration example for this step is provided in [`main.tf`](./main.tf).

### Step 2.1. Create an identity provider

1. Open the AWS Management Console for the desired AWS account.
2. Go to the [**Identity providers**](https://console.aws.amazon.com/iam/home#/identity_providers) list.
3. Click the **Add provider** button in the top-right corner of the console.
4. In the **Add Identity provider** wizard, select the **OpenID Connect** provider type.
5. Paste the **Issuer** value you copied into the **Provider URL** field.
6. Paste the **Audience** value into the **Audience** field.
7. Optionally, specify the desired tags in the **Add tags** section of the wizard.
8. Click the **Add provider** button and wait for the provider to be created.

### Step 2.2. Assign roles to the identity provider

#### Create a new role

1. In the list, click the name of the provider you created to open the details page.
2. Click the **Assign role** button in the top-right corner.
3. Select **Create a new role** and click **Next**.
4. On the **Select trusted entity** page, select the previously specified audience in the **Audience** picker.
5. In the **Conditions** block, specify one or more conditions on the `sub` claim as described in the [Trust policy configuration](#trust-policy-configuration) section.
   Alternatively, create the role without any `sub` conditions and then proceed to the [Use an existing role](#use-an-existing-role) section.
6. Select the permissions policies to attach to the role or create an inline one.
7. Specify a role name and description, then save the role.
8. If you did not specify any `sub` conditions in step 5, follow the [Use an existing role](#use-an-existing-role) section starting at step 3.

#### Use an existing role

1. In the list, click the name of the provider you created to open the details page.
2. Copy the ARN of the provider.
3. Go to the [roles list](https://console.aws.amazon.com/iam/home#/roles), find the desired role, and click its name to open the details page.
4. Switch to the **Trust relationships** tab.
5. Click the **Edit trust policy** button.
6. See the [Trust policy configuration](#trust-policy-configuration) section for examples of `Statement`s and conditions
   to add to the existing trust policy.

## Step 3. Assume the role during a build

Once you have configured the identity provider and a role in AWS, you can assume the role in your build.

### Using the AWS CLI

The AWS CLI client (`aws`) expects an OIDC token to be in a file. The path to the file can be specified
using the `AWS_WEB_IDENTITY_TOKEN_FILE` environment variable.

The following example assumes the role using the **OIDC Token (in build parameters)** build feature:

```bash
#!/bin/bash
set -euo pipefail

export AWS_REGION="eu-west-1"
export AWS_ROLE_ARN="arn:aws:iam::XXXXXXXXXXXX:role/your-role"

AWS_WEB_IDENTITY_TOKEN_FILE=$(mktemp)
trap 'rm -f "$AWS_WEB_IDENTITY_TOKEN_FILE"' EXIT
chmod 600 "$AWS_WEB_IDENTITY_TOKEN_FILE"
export AWS_WEB_IDENTITY_TOKEN_FILE
echo "$TEAMCITY_BUILD_OIDC_TOKEN" > "$AWS_WEB_IDENTITY_TOKEN_FILE"

# You can now use the AWS CLI
aws sts get-caller-identity
```

### Without the AWS CLI

To assume the role without using the AWS CLI, you will need to exchange the OIDC token directly.
See [`aws_assume_role.py`](./aws_assume_role.py) for an example script that uses the **OIDC Token (in build parameters)**
build feature to exchange the token.

```bash
#!/bin/bash
set -euo pipefail

export AWS_REGION="eu-west-1"
export AWS_ROLE_ARN="arn:aws:iam::XXXXXXXXXXXX:role/your-role"

# This will export `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` environment variables
eval "$(./aws_assume_role.py)"

# You can now use any AWS-related software that uses these environment variables
terraform plan

# The AWS CLI works too
aws sts get-caller-identity
```

## Trust policy configuration

By default, the trust policy for a role created by the identity provider wizard looks like this:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {
                "Federated": "arn:aws:iam::XXXXXXXXXXXX:oidc-provider/teamcity.example.com/app/oidc-jwt"
            },
            "Condition": {
                "StringEquals": {
                    "teamcity.example.com/app/oidc-jwt:aud": [
                        "https://teamcity.example.com/app/oidc-jwt"
                    ]
                }
            }
        }
    ]
}
```

> [!CAUTION]
> The default policy allows **all** builds to assume the role using an OIDC token.
> In production, you should add conditions on the `sub` claim to allow only specific projects
> or build configurations to assume the role.

> [!WARNING]
> When copying examples from this section, please remember to keep the `StringEquals` condition on the `:aud` claim.
> Otherwise, tokens with any audience value will be accepted, posing a security risk.

The examples assume that the build's **`sub` claim** is `_Root:project123:project4567:bt31337`.
For more information on trust policy conditions, refer to the
[official AWS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).

### Allow a single build type to assume the role

Use the following condition to allow a single build type to assume the role regardless of its place in the project hierarchy:
```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:bt31337"
    ]
}
```

To prevent a build type from assuming the role when it is moved within the project hierarchy, use the entire `sub` claim with `StringEquals`:
```json
"StringEquals": {
    "teamcity.example.com/app/oidc-jwt:aud": [
        "https://teamcity.example.com/app/oidc-jwt"
    ],
    "teamcity.example.com/app/oidc-jwt:sub": [
        "_Root:project123:project4567:bt31337"
    ]
}
```

### Allow multiple build types to assume the role

You can extend the examples above to allow multiple build types to assume the role:
```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:bt31337",
        "*:bt93754"
    ]
}
```

```json
"StringEquals": {
    "teamcity.example.com/app/oidc-jwt:aud": [
        "https://teamcity.example.com/app/oidc-jwt"
    ],
    "teamcity.example.com/app/oidc-jwt:sub": [
        "_Root:project123:project4567:bt31337",
        "_Root:project831:project842:bt93754"
    ]
}
```

For details on how IAM evaluates these conditions, see
[the official AWS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html).

### Allow all build types of a project to assume the role

With the following condition, all build configurations in a specific project _and its subprojects_ will be able to assume the role:
```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:project123:*"
    ]
}
```

### Allow a specific direct child of a project to assume the role

To allow a build configuration to assume the role only when it is a direct child of a specific project,
find the desired project's internal ID and use the following condition:
```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:project4567:bt31337"
    ]
}
```

### Personal builds

For security reasons, personal builds are not allowed to assume the role by default and must be allowed explicitly.

To allow a single user's builds to assume the role:

1. Find their numeric ID on the TeamCity server.
2. Choose any of the examples above.
3. Prepend the `u{ID}_` prefix to each component of the `sub` claim (separated by colons).

The following examples allow regular builds and personal builds belonging to the user with ID `42`:

```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:bt31337",
        "*:u42_bt31337"
    ]
}
```

```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:project123:*",
        "*:u42_project123:*"
    ]
}
```

You can also replace the numeric ID with a wildcard to allow personal builds belonging to any user to assume the role:
```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:bt31337",
        "*:u*_bt31337"
    ]
}
```

```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:project123:*",
        "*:u*_project123:*"
    ]
}
```

> [!WARNING]
> Do not omit the trailing `:` for `projectXXXXX` components when using wildcards,
> since `project123*` also matches projects `project1234`, `project12345`, and so on.

### A complete trust policy example

Consider the following requirements for a given role:
- Build type `bt392` should be able to assume the role unless it is moved elsewhere in the project hierarchy.
- All build configurations in `project423` and its subprojects should be allowed to assume the role.
- Personal builds belonging to the user with ID `927` should be allowed to assume the role when their build configurations
  are in `project230` or its subprojects.
- Build type `bt31337` should assume the role regardless of its place in the project hierarchy.

The following trust policy implements these requirements:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {
                "Federated": "arn:aws:iam::XXXXXXXXXXXX:oidc-provider/teamcity.example.com/app/oidc-jwt"
            },
            "Condition": {
                "StringEquals": {
                    "teamcity.example.com/app/oidc-jwt:aud": [
                        "https://teamcity.example.com/app/oidc-jwt"
                    ],
                    "teamcity.example.com/app/oidc-jwt:sub": [
                        "_Root:project160:bt392"
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {
                "Federated": "arn:aws:iam::XXXXXXXXXXXX:oidc-provider/teamcity.example.com/app/oidc-jwt"
            },
            "Condition": {
                "StringEquals": {
                    "teamcity.example.com/app/oidc-jwt:aud": [
                        "https://teamcity.example.com/app/oidc-jwt"
                    ]
                },
                "StringLike": {
                    "teamcity.example.com/app/oidc-jwt:sub": [
                        "*:project423:*",
                        "*:u927_project230:*",
                        "*:bt31337"
                    ]
                }
            }
        }
    ]
}
```
