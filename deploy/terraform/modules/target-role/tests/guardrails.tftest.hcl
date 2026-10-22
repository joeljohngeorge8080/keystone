mock_provider "aws" {
  # Mocked data sources return random strings; IAM resources validate that policies are JSON.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name                    = "keystone-deploy-prod"
  broker_role_arn         = "arn:aws:iam::123456789012:role/keystone-broker"
  broker_role_name        = "keystone-broker"
  permissions_policy_json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
}

run "revocation_put_role_policy_is_off_by_default" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.broker_may_revoke) == 0
    error_message = "Ch. 26 mechanism 3 must default to off"
  }
}

run "revocation_put_role_policy_is_opt_in" {
  command = plan
  variables {
    allow_broker_put_role_policy = true
  }
  assert {
    condition     = length(aws_iam_role_policy.broker_may_revoke) == 1
    error_message = "opting in grants the broker PutRolePolicy on this role"
  }
}

run "sessions_longer_than_the_ttl_ceiling_are_refused" {
  command = plan
  variables {
    max_session_duration = 43200
  }
  expect_failures = [var.max_session_duration]
}
