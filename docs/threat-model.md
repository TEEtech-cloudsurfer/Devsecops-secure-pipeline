# DevSecOps Secure Pipeline Threat Model

## 1. Purpose

This threat model identifies security threats affecting the DevSecOps
Secure Pipeline and defines the controls used to reduce those risks.

The threat model covers the software delivery path from developer
workstations through source control, CI/CD, AWS, container storage,
Kubernetes deployment, and runtime operations.

## 2. Assets

The primary assets requiring protection include:

- application source code
- Git repository
- CI/CD pipeline configuration
- AWS credentials and identities
- Terraform configuration and state
- container images
- Amazon ECR repositories
- Amazon EKS workloads
- Kubernetes configuration
- security scan results
- deployment artifacts
- audit and security logs

## 3. Threat Actors

Potential threat actors include:

### External Attacker

An attacker attempting to compromise application code, credentials,
dependencies, cloud infrastructure, or deployed workloads.

### Malicious Insider

An authorized user intentionally introducing malicious code,
configuration, or unauthorized changes.

### Compromised Developer Account

A legitimate developer identity or workstation that has been compromised
and is used to introduce malicious changes.

### Compromised Dependency

A third-party software package or container component containing
malicious code or known vulnerabilities.

## 4. Major Threat Scenarios

### T01 - Secret Exposure

**Threat:**
Credentials, API keys, tokens, certificates, or other sensitive values are
committed to source control.

**Potential Impact:**
Unauthorized access to cloud resources, repositories, applications, or
other systems.

**Controls:**

- `.gitignore`
- secret scanning
- short-lived credentials
- AWS IAM least privilege
- credential rotation when exposure occurs

**Pipeline Response:**

Mandatory secret detection should fail the pipeline and prevent artifact
promotion.

---

### T02 - Vulnerable Application Code

**Threat:**
Application source code contains insecure coding patterns.

**Potential Impact:**
Application compromise, unauthorized access, data exposure, or execution
of unintended operations.

**Controls:**

- static application security testing (SAST)
- peer review
- automated testing
- remediation validation

**Pipeline Response:**

Findings exceeding the defined enforcement threshold prevent pipeline
progression.

---

### T03 - Vulnerable Third-Party Dependency

**Threat:**
The application includes a dependency containing a known vulnerability.

**Potential Impact:**
Attackers may exploit vulnerable third-party software even when the
application's custom code is secure.

**Controls:**

- software composition analysis (SCA)
- dependency version management
- vulnerability severity thresholds
- dependency remediation

**Pipeline Response:**

Dependencies exceeding the accepted risk threshold prevent artifact
promotion.

---

### T04 - Insecure Infrastructure as Code

**Threat:**
Terraform introduces insecure AWS infrastructure.

Examples include:

- publicly accessible resources
- overly permissive security groups
- missing encryption
- insufficient logging
- excessive IAM permissions

**Potential Impact:**
Cloud resources may be exposed or deployed without required security
controls.

**Controls:**

- Checkov
- Terraform review
- policy as code
- AWS security monitoring

**Pipeline Response:**

Defined policy violations fail the infrastructure security stage.

---

### T05 - Vulnerable Container Image

**Threat:**
A container image contains operating system or application packages with
known vulnerabilities.

**Potential Impact:**
A deployed workload may expose exploitable software to an attacker.

**Controls:**

- minimal base images
- container vulnerability scanning
- approved image sources
- vulnerability thresholds
- image rebuild and remediation

**Pipeline Response:**

Images exceeding the defined vulnerability threshold are not promoted to
the approved registry/deployment stage.

---

### T06 - Unauthorized Pipeline Access to AWS

**Threat:**
CI/CD credentials provide excessive or persistent AWS access.

**Potential Impact:**
Compromise of the CI/CD environment could result in broader compromise of
AWS resources.

**Controls:**

- GitLab-to-AWS OIDC federation
- temporary credentials
- least-privilege IAM roles
- scoped trust policies
- CloudTrail logging

**Pipeline Response:**

Pipeline jobs receive only the permissions required for the specific
deployment workflow.

---

### T07 - Unauthorized Container Deployment

**Threat:**
An unapproved, modified, or insufficiently validated container image is
deployed to Kubernetes.

**Potential Impact:**
Security scanning and artifact promotion controls could be bypassed.

**Controls:**

- controlled ECR repositories
- immutable artifact references
- deployment policy enforcement
- Kubernetes admission controls
- future image signing and verification

**Pipeline Response:**

Only artifacts satisfying deployment policy are eligible for promotion.

---

### T08 - CI/CD Pipeline Tampering

**Threat:**
An attacker or unauthorized contributor modifies pipeline configuration to
disable or bypass security controls.

**Potential Impact:**
Malicious or vulnerable artifacts could bypass required security testing.

**Controls:**

- protected branches
- merge request review
- CODEOWNERS
- restricted pipeline variables
- change auditing

**Pipeline Response:**

Changes affecting security-critical pipeline configuration require
authorized review before reaching the protected branch.

---

### T09 - Runtime Compromise

**Threat:**
A workload that successfully passed pipeline controls is compromised after
deployment.

**Potential Impact:**
Unauthorized activity, data access, privilege escalation, persistence, or
lateral movement may occur.

**Controls:**

- Amazon GuardDuty
- AWS Security Hub
- Amazon CloudWatch
- CloudTrail
- Kubernetes logging
- least-privilege workload permissions

**Response:**

Runtime findings are investigated independently of pre-deployment security
validation.

## 5. Risk Register

| ID | Threat | Initial Risk | Primary Control |
|---|---|---|---|
| T01 | Secret exposure | High | Secret scanning |
| T02 | Vulnerable application code | High | SAST |
| T03 | Vulnerable dependency | High | SCA |
| T04 | Insecure IaC | High | Checkov |
| T05 | Vulnerable container | High | Trivy |
| T06 | Excessive CI/CD AWS access | Critical | OIDC + IAM |
| T07 | Unauthorized deployment | High | Deployment policy |
| T08 | Pipeline tampering | Critical | Protected workflow |
| T09 | Runtime compromise | Critical | Runtime monitoring |

## 6. Security Validation Strategy

The project will validate security controls using intentionally introduced,
non-production security failures.

Examples include:

- test secret committed to a controlled branch
- intentionally vulnerable application code
- vulnerable dependency
- insecure Terraform configuration
- vulnerable container component
- Kubernetes policy violation

Each validation scenario should demonstrate:

1. introduction of the security condition
2. automated detection
3. pipeline failure
4. analysis of the finding
5. remediation
6. successful rescan
7. successful pipeline progression

No real credentials or intentionally harmful payloads will be used.

## 7. Residual Risk

Automated security scanning reduces risk but does not eliminate it.

Potential residual risks include:

- zero-day vulnerabilities
- scanner false negatives
- compromised trusted dependencies
- authorized malicious changes
- misconfigured security thresholds
- runtime attacks not detectable during CI/CD
- vulnerabilities introduced after artifact creation

Runtime monitoring, access control, audit logging, manual review, and
defense-in-depth controls remain necessary.

## 8. Threat Model Review

The threat model should be updated whenever significant architectural
changes introduce new:

- components
- trust boundaries
- AWS services
- deployment mechanisms
- identities
- external dependencies
- security controls