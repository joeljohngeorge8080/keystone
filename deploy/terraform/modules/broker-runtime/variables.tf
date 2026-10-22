variable "name" {
  description = "Name of the broker runtime role."
  type        = string
  default     = "keystone-broker"
}

variable "runtime_service_principal" {
  description = "Where the broker runs: EC2 instance profile or ECS task role."
  type        = string
  default     = "ec2.amazonaws.com"
  validation {
    condition     = contains(["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"], var.runtime_service_principal)
    error_message = "runtime_service_principal must be ec2.amazonaws.com or ecs-tasks.amazonaws.com."
  }
}

variable "target_role_arns" {
  description = "Exact ARNs of every role the broker may mint for (IAM half of the double allowlist). No wildcards."
  type        = list(string)
  validation {
    condition = length(var.target_role_arns) > 0 && alltrue([
      for arn in var.target_role_arns :
      can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", arn)) && !strcontains(arn, "*")
    ])
    error_message = "target_role_arns must be a non-empty list of exact IAM role ARNs without wildcards."
  }
}

variable "anchor_bucket_arn" {
  description = "ARN of the S3 Object Lock bucket (anchor-bucket module output)."
  type        = string
}

variable "anchor_prefix" {
  description = "Key prefix the anchor worker writes under (S3ObjectLockAnchorStore default)."
  type        = string
  default     = "anchors/"
}

variable "tags" {
  type    = map(string)
  default = {}
}
