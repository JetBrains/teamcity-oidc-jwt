# Note: Terraform needs the Service Usage and Cloud Resource Manager APIs before it
# can discover the project and enable the remaining APIs. Bootstrap them once:
#
#   gcloud services enable serviceusage.googleapis.com cloudresourcemanager.googleapis.com --project="$GOOGLE_PROJECT"

terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.42"
    }
  }
}

provider "google" {}

# -----------------------------------------------------------------------------
# GCP prerequisites
# -----------------------------------------------------------------------------

data "google_project" "project" {}

# Identity and Access Management (IAM)
resource "google_project_service" "iam" {
  project = data.google_project.project.project_id
  service = "iam.googleapis.com"

  disable_on_destroy = false
}

# Resource Manager
resource "google_project_service" "cloud_resource_manager" {
  project = data.google_project.project.project_id
  service = "cloudresourcemanager.googleapis.com"

  disable_on_destroy = false
}

# Service Account Credentials
resource "google_project_service" "iam_credentials" {
  project = data.google_project.project.project_id
  service = "iamcredentials.googleapis.com"

  disable_on_destroy = false
}

# Security Token Service (STS)
resource "google_project_service" "sts" {
  project = data.google_project.project.project_id
  service = "sts.googleapis.com"

  disable_on_destroy = false
}

# -----------------------------------------------------------------------------
# Step 1.1. Find the TeamCity issuer URL
# -----------------------------------------------------------------------------

variable "teamcity_oidc_issuer" {
  type    = string
  default = "https://teamcity.example.com/app/oidc-jwt"
}

# -----------------------------------------------------------------------------
# Step 1.2. Create a WIF pool and provider
# -----------------------------------------------------------------------------

# Create a separate pool for each TeamCity installation
resource "google_iam_workload_identity_pool" "teamcity" {
  project                   = data.google_project.project.project_id
  workload_identity_pool_id = "teamcity-example-com"
  display_name              = "teamcity.example.com"

  depends_on = [google_project_service.iam]
}

# Configure TeamCity as an OIDC provider in the pool.
resource "google_iam_workload_identity_pool_provider" "teamcity" {
  project                            = data.google_project.project.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.teamcity.workload_identity_pool_id
  workload_identity_pool_provider_id = "teamcity-example-com"
  display_name                       = "teamcity.example.com"

  # Step 1.2, items 9-10: map the complete sub claim to google.subject and
  # every colon-separated TeamCity hierarchy component to google.groups.
  attribute_mapping = {
    "google.subject" = "assertion.sub"
    "google.groups"  = "assertion.sub.split(':')"

    # See "Custom attributes reference" section of the guide
    "attribute.bt_external_id" = "assertion.build_type_external_id"
  }

  oidc {
    issuer_uri = var.teamcity_oidc_issuer

    # Step 1.2, item 7: specify the accepted audiences list.
    # This one uses the default TC plugin audience (issuer URL).
    allowed_audiences = [var.teamcity_oidc_issuer]
  }

  depends_on = [
    google_project_service.iam,
    google_project_service.iam_credentials,
    google_project_service.sts,
  ]
}

# -----------------------------------------------------------------------------
# Step 3. Configure GCP IAM
# -----------------------------------------------------------------------------

locals {
  wip_principal_set = "principalSet://iam.googleapis.com/projects/${data.google_project.project.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.teamcity.workload_identity_pool_id}"
  wip_principal     = "principal://iam.googleapis.com/projects/${data.google_project.project.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.teamcity.workload_identity_pool_id}"
}

# Note: All examples use the project-level Viewer role.
# Replace "roles/viewer" with the role required by the TeamCity build.

# Assign permissions to a single build type, regardless of its position in the
# TeamCity project hierarchy.
resource "google_project_iam_member" "teamcity_build_bt31337" {
  project = data.google_project.project.project_id
  role    = "roles/viewer"
  member  = "${local.wip_principal_set}/group/bt31337"

  depends_on = [google_iam_workload_identity_pool_provider.teamcity]
}

# Assign permissions to the same build type only while its complete `sub` claim
# remains unchanged. Moving the build configuration revokes its access.
resource "google_project_iam_member" "teamcity_build_bt31337_exact_subject" {
  project = data.google_project.project.project_id
  role    = "roles/viewer"
  member  = "${local.wip_principal}/subject/_Root:project123:project4567:bt31337"

  depends_on = [google_iam_workload_identity_pool_provider.teamcity]
}

# Together with teamcity_build_bt31337, this demonstrates assigning the same
# role to multiple build types.
resource "google_project_iam_member" "teamcity_build_bt93754" {
  project = data.google_project.project.project_id
  role    = "roles/viewer"
  member  = "${local.wip_principal_set}/group/bt93754"

  depends_on = [google_iam_workload_identity_pool_provider.teamcity]
}

# Assign permissions to all build types in project123 and its subprojects.
resource "google_project_iam_member" "teamcity_project123" {
  project = data.google_project.project.project_id
  role    = "roles/viewer"
  member  = "${local.wip_principal_set}/group/project123"

  depends_on = [google_iam_workload_identity_pool_provider.teamcity]
}

# The equivalent project-hierarchy example used directly in Step 3 of the
# guide, for project4567 and its subprojects.
resource "google_project_iam_member" "teamcity_project4567" {
  project = data.google_project.project.project_id
  role    = "roles/viewer"
  member  = "${local.wip_principal_set}/group/project4567"

  depends_on = [google_iam_workload_identity_pool_provider.teamcity]
}

# Assign permissions to personal builds of user 42 for build type bt31337.
resource "google_project_iam_member" "teamcity_user42_build_bt31337" {
  project = data.google_project.project.project_id
  role    = "roles/viewer"
  member  = "${local.wip_principal_set}/group/u42_bt31337"

  depends_on = [google_iam_workload_identity_pool_provider.teamcity]
}

# Assign permissions to the same personal build only while its complete
# hierarchy remains unchanged.
resource "google_project_iam_member" "teamcity_user42_build_bt31337_exact_subject" {
  project = data.google_project.project.project_id
  role    = "roles/viewer"
  member  = "${local.wip_principal}/subject/u42__Root:u42_project123:u42_project4567:u42_bt31337"

  depends_on = [google_iam_workload_identity_pool_provider.teamcity]
}

# Assign permissions using the build configuration's external ID with a custom attribute mapping
resource "google_project_iam_member" "teamcity_build_by_external_id" {
  project = data.google_project.project.project_id
  role    = "roles/viewer"
  member  = "${local.wip_principal_set}/attribute.bt_external_id/MyProject_MyBuild"

  depends_on = [google_iam_workload_identity_pool_provider.teamcity]
}
