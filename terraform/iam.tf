resource "aws_iam_openid_connect_provider" "gitlab" {
  url = "https://gitlab.com"

  client_id_list = [
    "sts.amazonaws.com"
  ]
}

data "aws_iam_policy_document" "gitlab_assume_role" {
  statement {
    sid     = "GitLabOIDCAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type = "Federated"

      identifiers = [
        aws_iam_openid_connect_provider.gitlab.arn
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "gitlab.com:aud"

      values = [
        "sts.amazonaws.com"
      ]
    }

    condition {
      test     = "StringLike"
      variable = "gitlab.com:sub"

      values = [
        "project_path:TEEtech-cloudsurfer/devsecops-secure-pipeline:ref_type:branch:ref:main"
      ]
    }
  }
}

resource "aws_iam_role" "deployment" {
  name = "devsecops-pipeline-deployer"

  assume_role_policy = data.aws_iam_policy_document.gitlab_assume_role.json
}

data "aws_iam_policy_document" "deployment" {
  statement {
    sid    = "AllowECRAuthentication"
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "AllowApplicationImagePush"
    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart"
    ]

    resources = [
      aws_ecr_repository.application.arn
    ]
  }
}

resource "aws_iam_role_policy" "deployment" {
  name   = "devsecops-pipeline-ecr-deployment"
  role   = aws_iam_role.deployment.name
  policy = data.aws_iam_policy_document.deployment.json
}