mock_provider "aws" {
}

# Placeholder until the first real resources land (T2.2): asserts the
# skeleton initializes and plans against the mocked provider.
run "skeleton" {
  command = plan
}

run "iam_role_for_hybrid_node" {
  command = apply

  assert {
    condition     = aws_iam_role.ssm_hybrid_node.name == "win11-ssm-hybrid-node"
    error_message = "role must have the fixed generic name win11-ssm-hybrid-node"
  }

  assert {
    condition     = jsondecode(aws_iam_role.ssm_hybrid_node.assume_role_policy).Statement[0].Principal.Service == "ssm.amazonaws.com"
    error_message = "trust policy must allow the SSM service principal to assume the role"
  }

  assert {
    condition     = jsondecode(aws_iam_role.ssm_hybrid_node.assume_role_policy).Statement[0].Action == "sts:AssumeRole"
    error_message = "trust policy must grant sts:AssumeRole"
  }

  assert {
    condition     = aws_iam_role_policy_attachment.ssm_core.policy_arn == "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    error_message = "role must carry exactly the AmazonSSMManagedInstanceCore managed policy"
  }

  assert {
    condition     = aws_iam_role_policy_attachment.ssm_core.role == aws_iam_role.ssm_hybrid_node.name
    error_message = "attachment must target the hybrid-node role"
  }
}
