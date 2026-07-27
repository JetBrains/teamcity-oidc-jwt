terraform {
  required_version = "~> 1.1"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.30.0"
    }
  }
}

provider "aws" {
    ...
}

variable "oidc_provider_issuer" {
  description = "TeamCity OIDC provider issuer"
  type        = string
  default     = "https://teamcity.example.com/app/oidc-jwt"
}

#
# Set up the Identity provider
#
resource "aws_iam_openid_connect_provider" "teamcity" {
  url = var.oidc_provider_issuer

  client_id_list = [
    var.oidc_provider_issuer,
    "another-allowed-audience"
  ]
}

#
# Prepare Trust Policy
#
locals {
  aws_oidc_provider_issuer = trimprefix(var.oidc_provider_issuer, "https://")
}

data "aws_iam_policy_document" "oidc_assume_policy" {

  #
  # Allow a single build type to assume the role anywhere in project hierarchy
  #
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      identifiers = [aws_iam_openid_connect_provider.teamcity.arn]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      variable = "${local.aws_oidc_provider_issuer}:aud"
      values   = ["another-allowed-audience"]
    }

    condition {
      test     = "StringLike"
      variable = "${local.aws_oidc_provider_issuer}:sub"
      values   = ["*:bt31337"]
    }
  }

  #
  # Allow a single build type to assume the role when it's in a specific point
  # of the project hierarchy
  #
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      identifiers = [aws_iam_openid_connect_provider.teamcity.arn]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      variable = "${local.aws_oidc_provider_issuer}:aud"
      values   = ["another-allowed-audience"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.aws_oidc_provider_issuer}:sub"
      values   = ["_Root:project123:project4567:bt31337"]
    }
  }

  #
  # Allow all build types of a certain project to assume the role
  #
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      identifiers = [aws_iam_openid_connect_provider.teamcity.arn]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      variable = "${local.aws_oidc_provider_issuer}:aud"
      values   = ["another-allowed-audience"]
    }

    condition {
      test     = "StringLike"
      variable = "${local.aws_oidc_provider_issuer}:sub"
      values   = ["*:project123:*"]
    }
  }

  #
  # Personal builds
  #
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      identifiers = [aws_iam_openid_connect_provider.teamcity.arn]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      variable = "${local.aws_oidc_provider_issuer}:aud"
      values   = ["another-allowed-audience"]
    }

    condition {
      test     = "StringLike"
      variable = "${local.aws_oidc_provider_issuer}:sub"
      values   = [
        "*:project123:*", 
        "*:u42_project123:*"
      ]
    }
  }
}

resource "aws_iam_role" "example-role" {
  name               = "example-role"
  assume_role_policy = data.aws_iam_policy_document.oidc_assume_policy.json
}