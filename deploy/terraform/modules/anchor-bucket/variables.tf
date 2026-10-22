variable "bucket_name" {
  description = "Globally unique bucket name (KEYSTONE_ANCHOR_BUCKET)."
  type        = string
}

variable "retention_days" {
  description = "COMPLIANCE retention; product-owner default is the 400-day audit retention."
  type        = number
  default     = 400
  validation {
    condition     = var.retention_days >= 400
    error_message = "Anchors must outlive the 400-day audit retention."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
