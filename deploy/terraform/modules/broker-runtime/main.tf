# Broker runtime role (Ch. 64): the IAM half of the double allowlist (Ch. 22).
#
# The broker may assume ONLY the enumerated target roles, and an explicit Deny on everything
# else makes that hold even if a broader policy is attached later. Every other grant is the
# minimum the code calls: anchor writes to S3 Object Lock, CloudTrail lookups for the issuance
# reconciler (R6) and the revocation read-back (Ch. 26). iam:PutRolePolicy is not granted here:
# each target role opts in through the target-role module's flag (default off).

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "RuntimeAssumes"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = [var.runtime_service_principal]
    }
  }
}

resource "aws_iam_role" "broker" {
  name                 = var.name
  description          = "Keystone credential broker runtime (no static keys)"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = var.tags
}

data "aws_iam_policy_document" "broker" {
  statement {
    sid       = "AssumeEnumeratedTargetsOnly"
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = var.target_role_arns
  }

  statement {
    sid           = "DenyAnyOtherRole"
    effect        = "Deny"
    actions       = ["sts:AssumeRole", "sts:TagSession"]
    not_resources = var.target_role_arns
  }

  statement {
    sid       = "AnchorMirrorWrite"
    actions   = ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject"]
    resources = ["${var.anchor_bucket_arn}/${var.anchor_prefix}*"]
  }

  statement {
    sid       = "IssuanceReconcilerLookup"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"] # LookupEvents supports no resource-level permissions
  }

  statement {
    sid       = "RevocationReadBack"
    actions   = ["iam:GetRolePolicy"]
    resources = var.target_role_arns
  }
}

resource "aws_iam_role_policy" "broker" {
  name   = "keystone-broker"
  role   = aws_iam_role.broker.id
  policy = data.aws_iam_policy_document.broker.json
}

resource "aws_iam_instance_profile" "broker" {
  count = var.runtime_service_principal == "ec2.amazonaws.com" ? 1 : 0
  name  = var.name
  role  = aws_iam_role.broker.name
  tags  = var.tags
}
