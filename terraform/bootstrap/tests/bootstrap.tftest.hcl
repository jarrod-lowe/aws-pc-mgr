mock_provider "aws" {
}

run "invalid_bucket_name_rejected" {
  command = plan

  variables {
    bucket_name = "Invalid_Bucket_Name"
  }

  expect_failures = [
    var.bucket_name,
  ]
}

run "bucket_from_variable" {
  command = apply

  variables {
    bucket_name = "win11-ssm-tfstate-replaceme"
  }

  assert {
    condition     = aws_s3_bucket.state.bucket == "win11-ssm-tfstate-replaceme"
    error_message = "bucket name must come from var.bucket_name"
  }

  assert {
    condition     = output.state_bucket_name == "win11-ssm-tfstate-replaceme"
    error_message = "state_bucket_name output must expose the bucket"
  }
}
