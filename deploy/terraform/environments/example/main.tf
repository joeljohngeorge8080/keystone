# Example per-environment root (Ch. 64). Copy per environment; state lives in S3 with locking:
#
#   terraform init -backend-config="bucket=<state-bucket>" \
#     -backend-config="key=keystone/<env>.tfstate" -backend-config="region=<region>" \
#     -backend-config="use_lockfile=true"
#
# Adding a grant = adding a target-role block AND its ARN to `target_role_names`, in one
# reviewed PR, then `keystone roles create` for the registry half.

terraform {
  required_version = ">= 1.10"
  backend "s3" {}
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  # Target role ARNs are built from names, not module outputs: the broker allowlist and the
  # target roles' trust (which names the broker) would otherwise depend on each other.
  target_role_names = ["keystone-deploy-prod"]
  target_role_arns = [
    for name in local.target_role_names :
    "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${name}"
  ]
}

module "anchor_bucket" {
  source      = "../../modules/anchor-bucket"
  bucket_name = var.anchor_bucket_name
}

module "broker_runtime" {
  source            = "../../modules/broker-runtime"
  target_role_arns  = local.target_role_arns
  anchor_bucket_arn = module.anchor_bucket.bucket_arn
}

module "deploy_prod" {
  source           = "../../modules/target-role"
  name             = "keystone-deploy-prod"
  broker_role_arn  = module.broker_runtime.role_arn
  broker_role_name = module.broker_runtime.role_name
  permissions_policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DeployArtifacts"
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = "arn:${data.aws_partition.current.partition}:s3:::${var.deploy_bucket_name}/releases/*"
    }]
  })
}

module "network" {
  source                          = "../../modules/network"
  vpc_id                          = var.vpc_id
  load_balancer_security_group_id = var.load_balancer_security_group_id
  admin_ingress_cidrs             = var.admin_ingress_cidrs
}

variable "region" {
  type = string
}

variable "anchor_bucket_name" {
  type = string
}

variable "deploy_bucket_name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "load_balancer_security_group_id" {
  type = string
}

variable "admin_ingress_cidrs" {
  type = list(string)
}

output "broker_role_arn" {
  value = module.broker_runtime.role_arn
}

output "broker_instance_profile" {
  value = module.broker_runtime.instance_profile_name
}

output "anchor_bucket" {
  value = module.anchor_bucket.bucket_name
}
