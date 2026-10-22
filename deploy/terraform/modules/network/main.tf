# Listener-plane separation at the network layer (Ch. 39, 62): the public plane is reachable
# only from the TLS-terminating load balancer, the admin plane only from the operator network
# (VPN). Nothing else is opened inbound. Outbound stays open: GitHub JWKS, STS, S3, CloudTrail.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

resource "aws_security_group" "broker" {
  name        = "${var.name}-broker"
  description = "Keystone broker host: public plane from the LB, admin plane from the VPN"
  vpc_id      = var.vpc_id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "public_plane" {
  security_group_id            = aws_security_group.broker.id
  description                  = "Public plane (POST /v1/credentials) from the load balancer"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = var.load_balancer_security_group_id
}

resource "aws_vpc_security_group_ingress_rule" "admin_plane" {
  for_each          = toset(var.admin_ingress_cidrs)
  security_group_id = aws_security_group.broker.id
  description       = "Admin plane from the operator network"
  ip_protocol       = "tcp"
  from_port         = 8081
  to_port           = 8081
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "outbound" {
  security_group_id = aws_security_group.broker.id
  description       = "GitHub JWKS, AWS STS/S3/CloudTrail/IAM"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
