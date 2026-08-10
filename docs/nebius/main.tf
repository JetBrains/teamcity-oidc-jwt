terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    nebius = {
      source  = "nebius/nebius"
      version = "~> 0.6"
    }
  }
}

provider "nebius" {}

# -----------------------------------------------------------------------------
# Step 1. Set up OIDC for a TeamCity build
# -----------------------------------------------------------------------------

# The `iss` claim of the tokens issued by the plugin. See Step 1 of the guide.
#
# This URL must be served on the public internet over HTTPS with a publicly
# trusted certificate: Nebius fetches the discovery document and the key set
# from its own infrastructure. If the server is internal, either host the
# discovery documents externally or set `jwk_set_json` below.
variable "teamcity_oidc_issuer" {
  type    = string
  default = "https://teamcity.example.com/app/oidc-jwt"
}

# The `sub` claim of the build configuration that should get access.
# Federated credentials match this value exactly, so every build configuration
# needs its own `nebius_iam_v1_federated_credentials` resource.
variable "teamcity_build_subject" {
  type    = string
  default = "_Root:project123:project4567:bt31337"
}

# The Nebius project that will hold the service account and the registry.
variable "nebius_project_id" {
  type    = string
  default = "project-e00example"
}

# -----------------------------------------------------------------------------
# Step 2. Create a service account
# -----------------------------------------------------------------------------

resource "nebius_iam_v1_service_account" "teamcity" {
  parent_id   = var.nebius_project_id
  name        = "teamcity-ci"
  description = "Impersonated by TeamCity builds via OIDC federation"
}

# -----------------------------------------------------------------------------
# Step 3. Create a federated credential
# -----------------------------------------------------------------------------

# Maps the `sub` claim of a TeamCity build to the service account above.
# Note: Nebius matches on `iss` + `sub` only — there is no audience field.
# See the "How Nebius validates the token" section of the guide.
resource "nebius_iam_v1_federated_credentials" "teamcity_bt31337" {
  parent_id            = var.nebius_project_id
  name                 = "teamcity-bt31337"
  subject_id           = nebius_iam_v1_service_account.teamcity.id
  federated_subject_id = var.teamcity_build_subject

  oidc_provider = {
    issuer_url = var.teamcity_oidc_issuer

    # Uncomment for TeamCity installations that are not reachable from the
    # public internet. The key set is then resolved locally and Nebius makes no
    # outbound request, so `issuer_url` becomes just an identifier matched
    # against the token's `iss` claim.
    #
    # The value can be fetched from
    # `%teamcity.serverUrl%/app/oidc-jwt/.well-known/jwks` and must be updated
    # whenever the signing key changes.
    #
    # jwk_set_json = file("${path.module}/jwks.json")
  }
}

# -----------------------------------------------------------------------------
# Step 4. Grant the service account access
# -----------------------------------------------------------------------------

resource "nebius_registry_v1_registry" "images" {
  parent_id   = var.nebius_project_id
  name        = "teamcity-images"
  description = "Images built by TeamCity"
}

# `editor` allows listing, pulling, pushing, and modifying images.
# Use `viewer` for builds that only need to pull.
resource "nebius_iam_v1_access_permit" "teamcity_registry_editor" {
  parent_id   = nebius_iam_v1_service_account.teamcity.id
  resource_id = nebius_registry_v1_registry.images.id
  role        = "editor"
}

# -----------------------------------------------------------------------------
# Outputs consumed by the build script
# -----------------------------------------------------------------------------

output "nebius_service_account_id" {
  description = "Pass to the build as NEBIUS_SERVICE_ACCOUNT_ID."
  value       = nebius_iam_v1_service_account.teamcity.id
}

output "nebius_registry_fqdn" {
  description = "Pass to the build as NEBIUS_REGISTRY_FQDN."
  value       = nebius_registry_v1_registry.images.status.registry_fqdn
}
