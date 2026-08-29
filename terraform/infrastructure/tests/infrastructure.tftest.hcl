mock_provider "aws" {
}

# Placeholder until the first real resources land (T2.2): asserts the
# skeleton initializes and plans against the mocked provider.
run "skeleton" {
  command = plan
}
