terraform {
  backend "s3" {
    # bucket / key / region / use_lockfile are supplied to `terraform init`
    # via -backend-config, never committed here.
  }
}
