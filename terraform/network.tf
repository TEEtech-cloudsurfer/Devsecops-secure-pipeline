resource "aws_security_group" "eks_admin" {
  name        = "devsecops-eks-admin"
  description = "Restricted administrative access for EKS-related infrastructure"

  ingress {
    description = "SSH from trusted administrative network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = {
    Name = "devsecops-eks-admin"
  }
}