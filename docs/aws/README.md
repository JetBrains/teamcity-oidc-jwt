# AWS Configuration Guide

This document describes the steps required to set up AWS access from TeamCity builds.

## Step 1. Set Up OIDC for a TeamCity Build

### Using the UI
1. Go to the build configuration settings.
2. Switch to the `Build Features` tab.
3. Click the `Add build feature` button.
4. Look for `OIDC Token (in build parameters)` or `OIDC Token (on demand via HTTP request)`, depending on the preferred way of obtaining the token from the build.
5. Choose an audience for the token: the default value should be fine, but you can pick any arbitrary unique string. AWS only supports tokens with a single audience consisting of up to 255 alphanumeric or `:_.-/` characters.
6. Configure the remaining parameters as needed.
7. Copy the `Audience`,  `Issuer`, and `sub claim` values and save your changes.

### Using Kotlin DSL
1. Add either `oidcTokenInParams` or `oidcTokenOnDemand` to the build features block of your build type definition.
2. Choose an audience for the token using the `audiences` parameter. If not specified, the default value is the issuer URL. AWS supports audiences consisting of up to 255 alphanumeric or `:_.-/` characters.
3. Apply your DSL.
4. Collect the `Issuer` and `sub claim` values from the UI as described in the [`Using the UI` section](#using-the-ui) or programmatically:
    - The `Issuer` value can be fetched from the `issuer` field of the `%teamcity.serverUrl%/app/oidc-jwt/.well-known/openid-configuration` JSON.
    - The default `sub` claim follows the root-to-child hierarchy of internal IDs (for example, `_Root:project123:project4567:bt31337`).
      To fetch these IDs via the REST API, query 
`%teamcity.serverUrl%/app/rest/buildTypes?locator=id:{BUILD_TYPE_ID}&fields=buildType(internalId,project(internalId,parentProject(internalId,parentProject(internalId,name))))`. Depending on the project hierarchy depth, you might need to nest `parentProject(internalId,name)` multiple times until you reach the `_Root` project.

> [!WARNING]
> The `sub` value can change with DSL updates if the [`uuid` parameter](https://teamcity.jetbrains.com/app/dsl-documentation/root/build-type-settings/uuid.html) 
> is not specified and the [`Id` parameter](https://teamcity.jetbrains.com/app/dsl-documentation/root/id/index.html) is changed for the build type.

## Step 2. Configure AWS IAM
To perform this step, you will need sufficient permissions to change identity provider settings.

> [!NOTE]
> This step is a short summary of [the official AWS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
> on how to create an OIDC identity provider. There you can find more detailed instructions on creating an OIDC identity provider using the AWS Console, CLI, or API.

> [!TIP]
> A Terraform configuration example for this step is provided in [`main.tf`](./main.tf).

### Step 2.1. Create an Identity Provider
1. Open the AWS Management Console for the desired AWS account.
2. Go to the [`Identity providers`](https://console.aws.amazon.com/iam/home#/identity_providers) list.
3. Click the `Add provider` button in the top-right corner of the console.
4. In the `Add Identity provider` wizard, select the `OpenID Connect` provider type.
5. Paste the `Issuer` value you copied into the `Provider URL` field.
6. Paste your chosen `Audience` into the `Audience` field.
7. Optionally, specify the desired tags in the `Add tags` section of the wizard.
8. Click the `Add provider` button and wait for the provider to be created.

> [!WARNING]
> Even though identity providers support multiple audiences, 
> AWS only accepts tokens with a single `aud` claim.
>
> Please make sure **you specified only a single audience** in the previous step. 
> You can add multiple token-issuing build features when necessary.

### Step 2.2. Assign Roles to the Identity Provider

#### Create a New Role
1. Select your newly created provider in the list and click its name to open the details page.
2. Click the `Assign role` button in the top-right corner.
3. Select `Create a new role` and click `Next`.
4. On the `Select trusted entity` page, select the previously specified audience in the `Audience` picker.
5. In the `Conditions` block, specify one or more conditions on the `sub` claim as described in the [Trust Policy Configuration](#trust-policy-configuration) section.
   Alternatively, skip this step and finish creating this role, then proceed to the [Use an existing role](#use-an-existing-role) section.
6. Select the permissions policies to be assigned to the build or create an inline one.
7. Specify a role name and description, then save the role.
8. If you haven't specified any conditions in step 5, follow the [Use an existing role](#use-an-existing-role) section starting at step 3.

#### Use an Existing Role
1. Select your newly created provider in the list and click its name to open the details page.
2. Copy the ARN of the provider.
3. Go to the [roles list](https://console.aws.amazon.com/iam/home#/roles), find the desired role, and click its name to open the details page.
4. Switch to the `Trust relationships` tab.
5. Click the `Edit trust policy` button.
6. Proceed to the [Trust Policy Configuration](#trust-policy-configuration) section for examples of `Statement` block objects you could add to the existing trust policy.


## Step 3. Assume the Role During a Build
Once you've configured the identity provider and a role on the AWS side, you can assume the role in your build.

### Using the AWS CLI

The official AWS CLI client `aws` will exchange the token stored in a file specified by 
the `AWS_WEB_IDENTITY_TOKEN_FILE` environment variable. To use it, save the OIDC token 
issued by TeamCity to a file before running the command.

Here's an example of assuming the role this way using the `OIDC Token (in build parameters)` build feature:

```bash
#!/bin/bash
set -euo pipefail

export AWS_REGION="eu-west-1"
export AWS_ROLE_ARN="arn:aws:iam::XXXXXXXXXXXX:role/your-role"

AWS_WEB_IDENTITY_TOKEN_FILE=$(mktemp)
trap 'rm -f "$AWS_WEB_IDENTITY_TOKEN_FILE"' EXIT
chown 600 "$AWS_WEB_IDENTITY_TOKEN_FILE"
export AWS_WEB_IDENTITY_TOKEN_FILE
echo "$TEAMCITY_BUILD_OIDC_TOKEN" > "$AWS_WEB_IDENTITY_TOKEN_FILE"

# You can now use AWS CLI
aws sts get-caller-identity
```

### Without the AWS CLI

To assume the role without using the AWS CLI, you will need to exchange the OIDC token yourself.
For an example script that assumes a role using the `OIDC Token (in build parameters)`
build feature, see [`aws_assume_role.py`](./aws_assume_role.py), which can be used as follows:

```bash
#!/bin/bash
set -euo pipefail

export AWS_REGION="eu-west-1"
export AWS_ROLE_ARN="arn:aws:iam::XXXXXXXXXXXX:role/your-role"

# This will export `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` envvars
eval "$(./aws_assume_role.py)"

# You can now use any AWS-related software that uses these environment variables
terraform plan

# AWS CLI works too
aws sts get-caller-identity
```


## Trust Policy Configuration
By default, the trust policy for a newly generated role without any conditions looks like this:
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
> In production, you should add `sub` claim conditions to allow only specific projects 
> or build configurations to assume the role.

> [!WARNING]
> When copying examples from this section, please remember to keep the `StringEquals` condition for the `:aud` parameter. 
> Otherwise, tokens with any `aud` claim will be accepted from your issuer.

All the examples assume the `sub claim` of the build to be `_Root:project123:project4567:bt31337`.
For more information on trust policy conditions, refer to the 
[official AWS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).

### Allow a Single Build Type to Assume the Role
Use the following condition allow a single build type to assume the role regardless of its place in the project hierarchy:
```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:bt31337"
    ]
}
```

To prevent a build type from assuming the role when it is moved around the project hierarchy, use the entire `sub` claim with `StringEquals`:
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

### Allow multiple Build Types to Assume the Role
The examples above can be extended to assume the role from multiple specific build types:
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

### Allow All Build Types of a Certain Project to Assume the Role
With the following condition, all build configurations of a certain project _and its subprojects_ will be able to assume the role:
```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:project123:*"
    ]
}
```

### Allow a Specific Direct Child of a Project to Assume the Role
If you want the role to be assumable from a build configuration only when it is a direct child of a specific project, 
find the desired project's internal ID and use the following condition:
```json
"StringLike": {
    "teamcity.example.com/app/oidc-jwt:sub": [
        "*:project4567:bt31337"
    ]
}
```

### Personal Builds
Personal builds cannot assume the role by default and must be specified explicitly to prevent abuse.

To allow a single user's builds to assume the role, find their numeric ID on the TeamCity server, 
take any of the examples above and prepend the `u{ID}_` prefix to each component of the `sub` claim
(separated by colons). Here are a few examples allowing personal builds for a user 
with ID `42` alongside non-personal ones:

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

You can also replace the numeric ID with a wildcard so that all users can assume the role from personal builds:
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
> It is not recommended to omit the trailing `:` for `projectXXXXX` components when using wildcards, 
> since `project1234*` also matches projects `project12345`, `project123456`, and so on.


### A Complete Trust Policy Example
Consider the following requirements for a given role:
- Build type `bt392` can assume the role unless it is moved elsewhere in the project hierarchy.
- `project423` and all its build types (including children) should be allowed to assume the role.
- User `u927` should be able to assume the role from their personal builds in `project230` and its children.
- Build type `bt31337` should assume the role regardless of its place in the project hierarchy.

Here's a trust policy that matches the restrictions above:
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
