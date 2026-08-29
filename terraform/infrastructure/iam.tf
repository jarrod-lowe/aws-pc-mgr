resource "aws_iam_role" "ssm_hybrid_node" {
  name = "win11-ssm-hybrid-node"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  # No aws:SourceAccount/aws:SourceArn conditions: the mi-... identity does not
  # exist until registration, so SourceArn is unknowable at create time and the
  # hybrid-activation role guidance uses the plain service principal.
}

# SPEC 17 asks for dynamic discovery of AWS values: the managed-policy ARN
# is partition-relative (arn:aws vs arn:aws-us-gov for GovCloud regions the
# region validator accepts), so derive the partition instead of hard-coding
# the commercial one.
data "aws_partition" "current" {}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_hybrid_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
