output "state_bucket_name" {
  description = "S3 bucket holding Terraform state; used to configure the S3 backends."
  value       = aws_s3_bucket.state.bucket
}
