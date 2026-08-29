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

  # The AmazonSSMManagedInstanceCore ARN is partition-relative and iam.tf
  # derives it from data.aws_partition.current (SPEC 17). The mock would
  # invent a random partition string that fails ARN validation in every run
  # (including the plain-plan skeleton run), so pin the data source here for
  # all runs in this file. Pinned to the commercial partition, the iam run
  # asserts the attachment ARN is the standard arn:aws:... shape; the
  # GovCloud partition flows through the same interpolation.
  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws"
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
    error_message = "role must carry exactly the AmazonSSMManagedInstanceCore managed policy, with the ARN partition derived from data.aws_partition.current"
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

run "outputs" {
  command = apply

  assert {
    condition     = output.managed_node_role_name == "win11-ssm-hybrid-node"
    error_message = "managed_node_role_name output must expose the role name"
  }

  assert {
    # The provider exposes the activation ID as the resource id.
    condition     = output.activation_id == aws_ssm_activation.node.id
    error_message = "activation_id output must mirror the activation resource"
  }

  assert {
    condition     = output.activation_code == aws_ssm_activation.node.activation_code
    error_message = "activation_code output must mirror the activation resource"
  }
}
