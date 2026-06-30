# GitHub OIDC → AWS deploy role (account 796973489124)

The deploy workflow (`.github/workflows/deploy.yml`) authenticates to AWS via GitHub
OIDC — no long-lived keys. Run the steps below **once**, as an admin in account
**796973489124** (the ECR + `sarc-aws` EKS account), then add the role ARN as a repo
secret. The CLI snippets assume `aws` is configured for that account.

Repo: `olafkfreund/janus` · Region: `eu-west-2` · Cluster: `sarc-aws` · ECR repo: `janus`

---

## 1. Create the GitHub OIDC provider (skip if it already exists)

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```
(Check first: `aws iam list-open-id-connect-providers`.)

## 2. Trust policy — restrict to this repo's main branch

```bash
ACCOUNT=796973489124
cat > trust.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::${ACCOUNT}:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
      "StringLike": { "token.actions.githubusercontent.com:sub": "repo:olafkfreund/janus:ref:refs/heads/main" }
    }
  }]
}
JSON

aws iam create-role --role-name gha-janus-deploy \
  --assume-role-policy-document file://trust.json
```

## 3. Permissions — ECR push + EKS describe (least privilege)

```bash
cat > perms.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "EcrAuth", "Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*" },
    { "Sid": "EcrPush", "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"
      ],
      "Resource": "arn:aws:ecr:eu-west-2:796973489124:repository/janus" },
    { "Sid": "EksDescribe", "Effect": "Allow", "Action": "eks:DescribeCluster",
      "Resource": "arn:aws:eks:eu-west-2:796973489124:cluster/sarc-aws" }
  ]
}
JSON

aws iam put-role-policy --role-name gha-janus-deploy \
  --policy-name janus-deploy --policy-document file://perms.json
```

## 4. Grant the role Kubernetes permissions (EKS access entry)

`eks:DescribeCluster` only lets the pipeline build a kubeconfig; it still needs RBAC
inside the cluster to `kubectl apply`. The cluster uses **EKS access entries**:

```bash
ROLE_ARN=arn:aws:iam::796973489124:role/gha-janus-deploy

aws eks create-access-entry --cluster-name sarc-aws --region eu-west-2 \
  --principal-arn "$ROLE_ARN" --type STANDARD

# Scope this down to the janus namespace in production if you prefer a custom Role.
aws eks associate-access-policy --cluster-name sarc-aws --region eu-west-2 \
  --principal-arn "$ROLE_ARN" \
  --access-scope type=cluster \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy
```

## 5. Add the role ARN as a repo secret

```bash
gh secret set AWS_DEPLOY_ROLE_ARN \
  --repo olafkfreund/janus \
  --body "arn:aws:iam::796973489124:role/gha-janus-deploy"
```

## 6. Deploy

Re-run the latest **Deploy to AWS EKS** workflow:

```bash
gh run rerun --repo olafkfreund/janus $(gh run list --repo olafkfreund/janus \
  --workflow "Deploy to AWS EKS (Synechron Profile)" --branch main -L1 --json databaseId -q '.[0].databaseId')
# or trigger fresh:
gh workflow run "Deploy to AWS EKS (Synechron Profile)" --repo olafkfreund/janus --ref main
```

Watch it: `gh run watch <run-id>`. The pipeline builds the image, pushes `:<sha>` +
`:latest` to ECR, and rolls out via `kubectl`. The new pods expose `/healthz` and
`/readyz`, so readiness gates correctly.
