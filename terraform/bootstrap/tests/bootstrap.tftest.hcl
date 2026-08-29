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

run "versioning_enabled" {
  command = apply

  variables {
    bucket_name = "win11-ssm-tfstate-replaceme"
  }

  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "state bucket versioning must be Enabled so state history is recoverable"
  }
}

run "public_access_blocked" {
  command = apply

  variables {
    bucket_name = "win11-ssm-tfstate-replaceme"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.state.block_public_acls
    error_message = "block_public_acls must be true"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.state.block_public_policy
    error_message = "block_public_policy must be true"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.state.ignore_public_acls
    error_message = "ignore_public_acls must be true"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.state.restrict_public_buckets
    error_message = "restrict_public_buckets must be true"
  }
}
