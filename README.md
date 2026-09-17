# DevSecOps Secure Pipeline

## Overview

The DevSecOps Secure Pipeline is a portfolio security engineering project
designed to demonstrate how automated security controls can be integrated
throughout the software development lifecycle.

The project implements a CI/CD pipeline that evaluates application code,
dependencies, secrets, infrastructure-as-code, container images, and
deployment configurations before workloads are deployed into AWS.

The objective is not simply to identify vulnerabilities, but to enforce
security gates capable of preventing unacceptable risk from progressing
through the deployment pipeline.

## Problem Statement

Traditional CI/CD pipelines prioritize rapid software delivery but may allow
security vulnerabilities, exposed credentials, insecure infrastructure, or
vulnerable container images to reach production environments.

Security testing performed only after deployment increases remediation cost
and exposes organizations to unnecessary risk.

This project demonstrates a shift-left DevSecOps architecture in which
automated security controls are incorporated directly into the CI/CD
workflow.

## Project Objectives

- Build a functional CI/CD pipeline using GitLab CI/CD.
- Perform automated static application security testing (SAST).
- Detect secrets and credentials committed to source control.
- Identify vulnerable third-party dependencies.
- Scan Terraform infrastructure for insecure configurations.
- Scan container images for known vulnerabilities.
- Enforce security gates based on defined risk criteria.
- Store approved container images in Amazon ECR.
- Deploy approved workloads to Amazon EKS.
- Implement AWS security monitoring and logging.
- Demonstrate detection, pipeline failure, remediation, and successful
  redeployment of intentionally introduced security issues.

## Target Architecture

Developer
    |
    v
GitLab Repository
    |
    v
GitLab CI/CD
    |
    +-- SAST
    +-- Secret Scanning
    +-- Dependency Scanning
    +-- IaC Security Scanning
    |
    v
Docker Build
    |
    v
Container Vulnerability Scan
    |
    v
Amazon ECR
    |
    v
Deployment Security Gate
    |
    v
Amazon EKS
    |
    v
AWS Security Monitoring

## Security Philosophy

The pipeline follows a defense-in-depth approach. No individual security
control is treated as sufficient protection.

Controls are placed at multiple stages of the software delivery lifecycle
to identify security issues as early as possible and prevent unacceptable
risk from progressing toward deployment.

The project will demonstrate both preventive and detective controls,
including intentionally introduced security failures followed by documented
remediation.

## Planned Security Gates

| Pipeline Stage | Security Control | Purpose |
|---|---|---|
| Source | Secret scanning | Detect exposed credentials and sensitive data |
| Code | SAST | Identify insecure application code |
| Dependencies | SCA | Detect vulnerable third-party packages |
| Infrastructure | IaC scanning | Identify insecure Terraform configuration |
| Build | Container scanning | Detect vulnerable packages and images |
| Deployment | Policy enforcement | Prevent noncompliant workloads from deploying |
| Runtime | AWS monitoring | Detect suspicious activity after deployment |

## Technology Stack

### CI/CD
- GitLab
- GitLab CI/CD

### Application and Containers
- Python
- Docker

### Infrastructure
- Terraform
- AWS
- Amazon ECR
- Amazon EKS

### Security
- Semgrep
- Gitleaks
- Trivy
- Checkov
- Policy as Code

### Monitoring
- AWS Security Hub
- Amazon GuardDuty
- Amazon CloudWatch

## Repository Structure

```text
devsecops-secure-pipeline/
├── application/
├── docs/
│   ├── architecture.md
│   ├── security-controls.md
│   └── threat-model.md
├── kubernetes/
├── policies/
├── scripts/
├── terraform/
├── tests/
├── .gitignore
└── README.md