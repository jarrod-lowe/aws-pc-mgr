# Registration mechanism only (SPEC section 40): once the one allowed
# registration is consumed the activation is useless, but that must not cause
# drift or replacement. expiration_date is deliberately unset: AWS defaults it
# to 24h, and pinning a timestamp here would make every later apply plan a
# replacement. No tags: they would propagate to the managed node.
resource "aws_ssm_activation" "node" {
  name               = "win11-ssm-hybrid-node"
  description        = "Windows hybrid managed node"
  iam_role           = aws_iam_role.ssm_hybrid_node.name
  registration_limit = 1

  # The iam_role reference only orders creation after the role itself;
  # CreateActivation must also wait for the policy attachment so the role
  # already carries AmazonSSMManagedInstanceCore when it becomes usable.
  depends_on = [aws_iam_role_policy_attachment.ssm_core]
}
