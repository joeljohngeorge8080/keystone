mock_provider "aws" {
  # Mocked data sources return random strings; IAM resources validate that policies are JSON.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

run "compliance_mode_for_the_audit_retention" {
  command = plan
  variables {
    bucket_name = "keystone-anchors"
  }
  assert {
    condition     = aws_s3_bucket_object_lock_configuration.anchors.rule[0].default_retention[0].mode == "COMPLIANCE"
    error_message = "anchors must be locked in COMPLIANCE mode"
  }
  assert {
    condition     = aws_s3_bucket.anchors.force_destroy == false
    error_message = "the anchor bucket must never be force-destroyed"
  }
}

run "retention_shorter_than_the_audit_retention_is_refused" {
  command = plan
  variables {
    bucket_name    = "keystone-anchors"
    retention_days = 30
  }
  expect_failures = [var.retention_days]
}
