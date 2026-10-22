# A role Keystone may mint for (Ch. 64). Adding one is a PR-reviewed IAM change, never something
# Keystone can do itself; the broker-runtime allowlist must list its ARN too (double allowlist).
#
# Trust: only the broker runtime role, only with the attribution session tags Keystone always
# sets (keystone:decision_id ...) and only with Keystone's `ks-` session names, so a session
# that did not go through a chained, audited decision cannot assume the role.

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
    sid     = "KeystoneBrokerOnly"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.broker_role_arn]
    }
    condition {
      test     = "StringLike"
      variable = "sts:RoleSessionName"
      values   = ["ks-*"]
    }
    condition {
      test     = "Null"
      variable = "aws:RequestTag/keystone:decision_id"
      values   = ["false"]
    }
    dynamic "condition" {
      for_each = var.external_id == null ? [] : [var.external_id]
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [condition.value]
      }
    }
  }

  statement {
    sid     = "KeystoneAttributionTags"
    actions = ["sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = [var.broker_role_arn]
    }
    condition {
      test     = "ForAllValues:StringLike"
      variable = "aws:TagKeys"
      values   = ["keystone:*"]
    }
  }
}

resource "aws_iam_role" "target" {
  name                 = var.name
  description          = var.description
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_duration
  tags                 = var.tags
}

resource "aws_iam_role_policy" "permissions" {
  name   = "${var.name}-permissions"
  role   = aws_iam_role.target.id
  policy = var.permissions_policy_json
}

# Ch. 26 mechanism 3 (default OFF): lets the broker attach the time-bounded deny policy to THIS
# role on `keystone revoke role`. Without it, revocation renders the runbook document instead.
data "aws_iam_policy_document" "revocation" {
  statement {
    sid       = "KeystoneRevocationDenyPolicy"
    actions   = ["iam:PutRolePolicy"]
    resources = [aws_iam_role.target.arn]
  }
}

resource "aws_iam_role_policy" "broker_may_revoke" {
  count  = var.allow_broker_put_role_policy ? 1 : 0
  name   = "keystone-revoke-${var.name}"
  role   = var.broker_role_name
  policy = data.aws_iam_policy_document.revocation.json
}
