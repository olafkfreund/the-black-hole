# GitHub OIDC → AWS deploy (account 796973489124) — IMPLEMENTED

The `janus` deploy uses GitHub OIDC (no static keys). This is **already provisioned**;
this file documents the setup so it can be audited or recreated.

Repo: `olafkfreund/janus` · Region: `eu-west-2` · Cluster: `sarc-aws` · ECR repo: `janus`

## What exists

- **IAM role**: `arn:aws:iam::796973489124:role/janus-github-deploy`
  - Trust: GitHub OIDC provider, `aud=sts.amazonaws.com`, `sub` like `repo:olafkfreund/janus:*`
  - Inline policy `janus-deploy-ecr-eks`: `ecr:GetAuthorizationToken` (*), ECR push on
    `repository/janus`, `eks:DescribeCluster` on `sarc-aws`
- **EKS access entry** for the role, with `AmazonEKSEditPolicy` scoped to namespace `janus`
  (mirrors the fides role pattern — namespace-scoped, least privilege)
- **GitHub repo variable** `AWS_DEPLOY_ROLE_ARN` = the role ARN (used by `.github/workflows/deploy.yml`)

The OIDC provider (`token.actions.githubusercontent.com`) is shared at the account level.

## Recreate from scratch (if ever deleted)

```bash
PROFILE=Synechron   # SSO admin profile for account 796973489124
OIDC=arn:aws:iam::796973489124:oidc-provider/token.actions.githubusercontent.com

# 1. Role + trust (sub scoped to this repo)
aws iam create-role --role-name janus-github-deploy --profile $PROFILE \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"'$OIDC'"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:olafkfreund/janus:*"}}}]}'

# 2. ECR push + EKS describe (scoped to the janus repo/cluster)
aws iam put-role-policy --role-name janus-github-deploy --policy-name janus-deploy-ecr-eks --profile $PROFILE \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Sid":"ECRAuth","Effect":"Allow","Action":["ecr:GetAuthorizationToken"],"Resource":"*"},{"Sid":"ECRPush","Effect":"Allow","Action":["ecr:BatchCheckLayerAvailability","ecr:CompleteLayerUpload","ecr:InitiateLayerUpload","ecr:PutImage","ecr:UploadLayerPart","ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"],"Resource":"arn:aws:ecr:eu-west-2:796973489124:repository/janus"},{"Sid":"EKSDescribe","Effect":"Allow","Action":["eks:DescribeCluster"],"Resource":"arn:aws:eks:eu-west-2:796973489124:cluster/sarc-aws"}]}'

# 3. Cluster RBAC via EKS access entry (edit, namespace janus)
aws eks create-access-entry --cluster-name sarc-aws --region eu-west-2 --profile $PROFILE \
  --principal-arn arn:aws:iam::796973489124:role/janus-github-deploy --type STANDARD
aws eks associate-access-policy --cluster-name sarc-aws --region eu-west-2 --profile $PROFILE \
  --principal-arn arn:aws:iam::796973489124:role/janus-github-deploy \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy \
  --access-scope 'type=namespace,namespaces=janus'

# 4. Point the repo at the role
gh variable set AWS_DEPLOY_ROLE_ARN --repo olafkfreund/janus \
  --body arn:aws:iam::796973489124:role/janus-github-deploy
```

## Out-of-band cluster bootstrap (namespace + secret are NOT in the manifest)

```bash
kubectl create namespace janus
kubectl -n janus create secret generic mcp-gateway-secrets \
  --from-literal=jwt-secret="$(openssl rand -base64 48)" \
  --from-literal=gateway-token="$(openssl rand -base64 48)"
```

## Deploy

Push to `main` (auto) or: `gh workflow run "Deploy to AWS EKS (Synechron Profile)" --ref main`.
The pipeline builds, pushes `:<sha>`+`:latest` to ECR, and rolls out; pods gate on `/readyz`.
