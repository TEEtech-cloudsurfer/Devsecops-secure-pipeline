
resource "aws_sns_topic" "security_alerts" {
  name              = "devsecops-security-alerts"
  kms_master_key_id = aws_kms_key.security_alerts.arn
}
data "aws_iam_policy_document" "security_alerts" {
  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts.json
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "security_alerts_kms" {
  statement {
    sid    = "EnableAccountIAMPermissions"
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowEventBridgeEncryption"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]

    resources = ["*"]
  }
}

resource "aws_kms_key" "security_alerts" {
  description             = "Encryption key for DevSecOps security alerts"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.security_alerts_kms.json

  tags = {
    Project = "DevSecOps-Secure-Pipeline"
    Control = "SC-09"
  }
}


resource "aws_cloudwatch_event_rule" "deployment_role_changes" {
  name        = "devsecops-deployment-role-changes"
  description = "Detect permission changes to the GitLab deployment role"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]

    detail = {
      eventSource = ["iam.amazonaws.com"]

      eventName = [
        "PutRolePolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "DeleteRolePolicy",
        "UpdateAssumeRolePolicy",
        "DeleteRole"
      ]

      requestParameters = {
        roleName = [aws_iam_role.deployment.name]
      }
    }
  })
}


resource "aws_cloudwatch_event_rule" "ecr_repository_changes" {
  name        = "devsecops-ecr-repository-changes"
  description = "Detect security-sensitive ECR repository operations"

  event_pattern = jsonencode({
    source        = ["aws.ecr"]
    "detail-type" = ["AWS API Call via CloudTrail"]

    detail = {
      eventSource = ["ecr.amazonaws.com"]

      eventName = [
        "DeleteRepository",
        "SetRepositoryPolicy",
        "DeleteRepositoryPolicy"
      ]

      requestParameters = {
        repositoryName = [aws_ecr_repository.application.name]
      }
    }
  })
}


resource "aws_cloudwatch_event_target" "deployment_role_alerts" {
  rule = aws_cloudwatch_event_rule.deployment_role_changes.name
  arn  = aws_sns_topic.security_alerts.arn

  depends_on = [
    aws_sns_topic_policy.security_alerts
  ]
}

resource "aws_cloudwatch_event_target" "ecr_repository_alerts" {
  rule = aws_cloudwatch_event_rule.ecr_repository_changes.name
  arn  = aws_sns_topic.security_alerts.arn

  depends_on = [
    aws_sns_topic_policy.security_alerts
  ]
}
