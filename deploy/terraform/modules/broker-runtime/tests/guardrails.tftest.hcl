# Offline guardrail tests (mock provider): `terraform test` in this module directory.
mock_provider "aws" {
  # Mocked data sources return random strings; IAM resources validate that policies are JSON.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  anchor_bucket_arn = "arn:aws:s3:::keystone-anchors"
}

run "exact_target_arns_are_accepted" {
  command = plan
  variables {
    target_role_arns = ["arn:aws:iam::123456789012:role/keystone-deploy-prod"]
  }
  assert {
    condition     = length(aws_iam_instance_profile.broker) == 1
    error_message = "an EC2 runtime gets an instance profile"
  }
}

run "wildcard_targets_are_refused" {
  command = plan
  variables {
    target_role_arns = ["arn:aws:iam::123456789012:role/*"]
  }
  expect_failures = [var.target_role_arns]
}

run "an_empty_allowlist_is_refused" {
  command = plan
  variables {
    target_role_arns = []
  }
  expect_failures = [var.target_role_arns]
}

run "ecs_runtime_has_no_instance_profile" {
  command = plan
  variables {
    target_role_arns          = ["arn:aws:iam::123456789012:role/keystone-deploy-prod"]
    runtime_service_principal = "ecs-tasks.amazonaws.com"
  }
  assert {
    condition     = length(aws_iam_instance_profile.broker) == 0
    error_message = "an ECS task role needs no instance profile"
  }
}
