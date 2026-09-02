# China-partition counterpart of the iam asserts in infrastructure.tftest.hcl.
#
# mock_provider blocks are file-scoped in .tftest.hcl (a run block cannot
# carry its own), and the commercial pin in the other file cannot tell a
# derived trust principal from a hard-coded "ssm.amazonaws.com" literal — the
# two coincide. This file pins the aws-cn partition instead, where they do
# not: in the China partition the SSM service principal is
# ssm.amazonaws.com.cn, so these asserts fail against any trust policy that
# hard-codes the commercial principal and pass only when iam.tf derives the
# principal from data.aws_partition.current.dns_suffix. The policy-attachment
# ARN is asserted on the same run so both partition-derived values are seen
# flowing through the aws-cn shapes together.
mock_provider "aws" {
  # Both attributes are pinned: an unpinned partition would be a random mock
  # string that fails ARN validation before the asserts run.
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-cn"
      dns_suffix = "amazonaws.com.cn"
    }
  }
}

run "china_partition_derives_cn_principal" {
  command = apply

  assert {
    condition     = jsondecode(aws_iam_role.ssm_hybrid_node.assume_role_policy).Statement[0].Principal.Service == "ssm.amazonaws.com.cn"
    error_message = "in the China partition the trust principal must be ssm.amazonaws.com.cn, derived from data.aws_partition.current.dns_suffix, not the hard-coded commercial ssm.amazonaws.com"
  }

  assert {
    condition     = aws_iam_role_policy_attachment.ssm_core.policy_arn == "arn:aws-cn:iam::aws:policy/AmazonSSMManagedInstanceCore"
    error_message = "the managed-policy ARN must derive the aws-cn partition from data.aws_partition.current.partition"
  }
}
