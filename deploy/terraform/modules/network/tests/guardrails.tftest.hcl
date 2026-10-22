mock_provider "aws" {}

variables {
  vpc_id                          = "vpc-0123456789abcdef0"
  load_balancer_security_group_id = "sg-0123456789abcdef0"
}

run "admin_plane_from_the_vpn_only" {
  command = plan
  variables {
    admin_ingress_cidrs = ["10.8.0.0/24"]
  }
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.admin_plane) == 1
    error_message = "one admin rule per operator CIDR"
  }
}

run "admin_plane_open_to_the_internet_is_refused" {
  command = plan
  variables {
    admin_ingress_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [var.admin_ingress_cidrs]
}
