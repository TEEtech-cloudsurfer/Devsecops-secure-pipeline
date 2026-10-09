#!/usr/bin/env bash

set -euo pipefail

DEPLOYMENT_ROLE="devsecops-pipeline-deployer"
REPOSITORY_NAME="devsecops-secure-pipeline"

echo "SC-06: Validating AWS IAM authorization controls"

ROLE_ARN=$(aws iam get-role \
  --role-name "$DEPLOYMENT_ROLE" \
  --query 'Role.Arn' \
  --output text)

REPOSITORY_ARN=$(aws ecr describe-repositories \
  --repository-names "$REPOSITORY_NAME" \
  --query 'repositories[0].repositoryArn' \
  --output text)

echo "Testing ECR authentication permission..."

AUTH_DECISION=$(aws iam simulate-principal-policy \
  --policy-source-arn "$ROLE_ARN" \
  --action-names ecr:GetAuthorizationToken \
  --query 'EvaluationResults[0].EvalDecision' \
  --output text)

echo "Result: $AUTH_DECISION"

echo "Testing repository image push permission..."

PUSH_DECISION=$(aws iam simulate-principal-policy \
  --policy-source-arn "$ROLE_ARN" \
  --action-names ecr:PutImage \
  --resource-arns "$REPOSITORY_ARN" \
  --query 'EvaluationResults[0].EvalDecision' \
  --output text)

echo "Result: $PUSH_DECISION"

echo "Testing unauthorized repository deletion..."

DELETE_DECISION=$(aws iam simulate-principal-policy \
  --policy-source-arn "$ROLE_ARN" \
  --action-names ecr:DeleteRepository \
  --resource-arns "$REPOSITORY_ARN" \
  --query 'EvaluationResults[0].EvalDecision' \
  --output text)

echo "Result: $DELETE_DECISION"

if [[ "$AUTH_DECISION" != "allowed" ]]; then
  echo "FAIL: ECR authentication is not authorized."
  exit 1
fi

if [[ "$PUSH_DECISION" != "allowed" ]]; then
  echo "FAIL: Application image push is not authorized."
  exit 1
fi

if [[ "$DELETE_DECISION" != "implicitDeny" ]]; then
  echo "FAIL: Unauthorized ECR repository deletion was not implicitly denied."
  exit 1
fi

echo "PASS: SC-06 IAM authorization controls validated."