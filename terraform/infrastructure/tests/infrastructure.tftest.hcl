mock_provider "aws" {
  # expiration_date is Optional+Computed: when the config deliberately leaves
  # it unset the mock would invent a value, so pin it to the unset (null)
  # state the configuration actually specifies.
  override_resource {
    target = aws_ssm_activation.node
    values = {
      expiration_date = null
    }
  }
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

run "single_registration_activation" {
  command = apply

  assert {
    condition     = aws_ssm_activation.node.registration_limit == 1
    error_message = "activation must allow exactly one registration"
  }

  assert {
    condition     = aws_ssm_activation.node.description == "Windows hybrid managed node"
    error_message = "activation description must stay generic and non-identifying"
  }

  assert {
    condition     = aws_ssm_activation.node.iam_role == aws_iam_role.ssm_hybrid_node.name
    error_message = "activation must use the hybrid-node role"
  }

  assert {
    condition     = aws_ssm_activation.node.expiration_date == null
    error_message = "expiration_date must be unset (AWS default 24h) to avoid ForceNew churn"
  }
}
