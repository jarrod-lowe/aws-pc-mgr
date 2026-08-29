resource "aws_s3_bucket" "state" {
  bucket = var.bucket_name

  # The state bucket must never be destroyed through a routine
  # `terraform destroy` of this stack.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}
