output "managed_node_role_name" {
  description = "IAM role assumed by the Windows hybrid managed node."
  value       = aws_iam_role.ssm_hybrid_node.name
}

# Bootstrap-sensitive values (SPEC section 19): retrieve on demand with
# `terraform output -raw <name>`; never record them anywhere.
output "activation_id" {
  description = "SSM activation ID for initial Windows enrollment. (The provider exposes it as the resource id.)"
  value       = aws_ssm_activation.node.id
  sensitive   = true
}

output "activation_code" {
  description = "SSM activation code for initial Windows enrollment."
  value       = aws_ssm_activation.node.activation_code
  sensitive   = true
}
