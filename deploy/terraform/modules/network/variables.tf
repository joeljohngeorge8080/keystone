variable "name" {
  type    = string
  default = "keystone"
}

variable "vpc_id" {
  type = string
}

variable "load_balancer_security_group_id" {
  description = "Security group of the TLS-terminating load balancer in front of the public plane."
  type        = string
}

variable "admin_ingress_cidrs" {
  description = "Operator/VPN CIDRs allowed to reach the admin plane. Never 0.0.0.0/0."
  type        = list(string)
  validation {
    condition = alltrue([
      for cidr in var.admin_ingress_cidrs : can(cidrhost(cidr, 0)) && cidr != "0.0.0.0/0"
    ])
    error_message = "admin_ingress_cidrs must be valid CIDRs and must not include 0.0.0.0/0."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
