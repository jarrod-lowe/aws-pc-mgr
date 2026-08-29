variable "bucket_name" {
  description = "Globally unique S3 bucket for Terraform state. Supply via untracked terraform.tfvars."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name)) && !can(regex("--", var.bucket_name))
    error_message = "3-63 chars: lowercase letters, digits, hyphens; no leading/trailing/double hyphen."
  }
}
