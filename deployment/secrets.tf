# AWS Secrets Manager Secret to house gateway environment variables securely
resource "aws_secretsmanager_secret" "gateway" {
  name        = "${var.environment}-mcp-gateway-secrets"
  description = "Sensitive configuration secrets for the MCP API Gateway"

  # Allow simple deletion for PoC, best practice is to have recovery window in production
  recovery_window_in_days = var.environment == "dev" ? 0 : 30
}

# Generate strong random secrets at apply time. Never commit real secret
# material to version control.
resource "random_password" "jwt_secret" {
  length  = 48
  special = false
}

resource "random_password" "gateway_token" {
  length  = 48
  special = false
}

# Seed the secret with generated values. `ignore_changes` ensures secrets rotated
# out-of-band (console / rotation lambda) are not clobbered on subsequent applies.
resource "aws_secretsmanager_secret_version" "gateway" {
  secret_id = aws_secretsmanager_secret.gateway.id
  secret_string = jsonencode({
    jwt-secret    = random_password.jwt_secret.result
    gateway-token = random_password.gateway_token.result
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# IAM Policy for secrets resolution
resource "aws_iam_policy" "secrets_read" {
  name        = "${var.environment}-mcp-secrets-policy"
  description = "Allows EKS pods to read vault keys and gateway tokens from Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.gateway.arn
        ]
      }
    ]
  })
}

# EKS Service Account IAM Role (IRSA) for Pod Identity Federation
resource "aws_iam_role" "gateway_sa" {
  name = "${var.environment}-mcp-gateway-sa-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:default:mcp-api-gateway-sa"
            "${module.eks.oidc_provider}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Attach secrets access policy to the IRSA role
resource "aws_iam_role_policy_attachment" "gateway_sa_secrets" {
  role       = aws_iam_role.gateway_sa.name
  policy_arn = aws_iam_policy.secrets_read.arn
}
