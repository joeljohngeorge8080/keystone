variable "name" {
  description = "Role name; register the same ARN in Keystone (`keystone roles create`)."
  type        = string
}

variable "description" {
  type    = string
  default = "Assumed only through Keystone"
}

variable "broker_role_arn" {
  description = "broker-runtime module output role_arn."
  type        = string
}

variable "broker_role_name" {
  description = "broker-runtime module output role_name (used only when allow_broker_put_role_policy)."
  type        = string
}

variable "external_id" {
  description = "Optional sts:ExternalId; must match the role's external_id in the Keystone registry."
  type        = string
  default     = null
}

variable "max_session_duration" {
  description = "Upper bound on minted sessions; Keystone's TTL ceiling is 3600 s (Ch. 25)."
  type        = number
  default     = 3600
  validation {
    condition     = var.max_session_duration >= 900 && var.max_session_duration <= 3600
    error_message = "max_session_duration must be between 900 and 3600 seconds."
  }
}

variable "permissions_policy_json" {
  description = "What the minted credentials may do (an IAM policy document)."
  type        = string
}

variable "allow_broker_put_role_policy" {
  description = "Ch. 26 mechanism 3: allow the broker to attach the revocation deny policy. Default off."
  type        = bool
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
