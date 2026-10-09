provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "devsecops-secure-pipeline"
      ManagedBy = "Terraform"
    }
  }
}