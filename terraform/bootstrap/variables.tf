variable "bucket_name" {
  description = "Globally unique S3 bucket for Terraform state. Supply via untracked terraform.tfvars."
  type        = string

  validation {
    condition = alltrue([
      can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name)),
      !can(regex("--", var.bucket_name)),
      # S3 reserves these forms; CreateBucket rejects them, so they must
      # fail at input validation instead of at first apply.
      !can(regex("^sthree-", var.bucket_name)),
      !can(regex("^amzn-s3-demo-", var.bucket_name)),
      !can(regex("-s3alias$", var.bucket_name)),
    ])
    error_message = "3-63 chars: lowercase letters, digits, hyphens; no leading/trailing/double hyphen; no reserved sthree-/amzn-s3-demo- prefix or -s3alias suffix."
  }
}
