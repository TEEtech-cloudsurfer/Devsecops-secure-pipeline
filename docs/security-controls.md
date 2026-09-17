# DevSecOps Secure Pipeline Security Controls

## 1. Purpose

This document defines the security controls implemented throughout the
DevSecOps Secure Pipeline.

Each control maps an identified threat to a technical control, enforcement
mechanism, and evidence source.

The objective is to ensure security tools are implemented to address
defined risks rather than added to the pipeline without a security
requirement.

## 2. Control Matrix

| ID | Threat | Security Control | Tool / Service | Pipeline Stage | Enforcement |
|---|---|---|---|---|---|
| SC-01 | T01 Secret Exposure | Secret detection | Gitleaks | Source | Block |
| SC-02 | T02 Vulnerable Code | Static analysis | Semgrep | Test | Risk-based |
| SC-03 | T03 Vulnerable Dependency | Software composition analysis | Trivy | Test | Risk-based |
| SC-04 | T04 Insecure IaC | IaC security scanning | Checkov | Validate | Block |
| SC-05 | T05 Vulnerable Container | Image vulnerability scanning | Trivy | Build | Risk-based |
| SC-06 | T06 Excessive AWS Access | Federated CI/CD identity | GitLab OIDC + AWS IAM/STS | Deploy | Preventive |
| SC-07 | T07 Unauthorized Deployment | Deployment policy | Policy as Code | Deploy | Block |
| SC-08 | T08 Pipeline Tampering | Protected pipeline workflow | GitLab | Source | Preventive |
| SC-09 | T09 Runtime Compromise | Runtime monitoring | Security Hub / GuardDuty / CloudWatch | Runtime | Detective |

## 3. Enforcement Model

Security controls are categorized as:

### Blocking

A blocking control prevents the pipeline from progressing when the defined
security condition is violated.

Examples:

- detected secrets
- prohibited infrastructure configuration
- deployment policy violations

### Risk-Based

A risk-based control evaluates findings against a defined severity or
policy threshold.

Examples:

- application vulnerabilities
- dependency vulnerabilities
- container vulnerabilities

### Preventive

A preventive control limits the ability for an insecure action to occur.

Examples:

- least-privilege IAM
- protected branches
- temporary AWS credentials

### Detective

A detective control identifies suspicious or insecure activity after an
artifact has been deployed.

Examples:

- GuardDuty findings
- Security Hub findings
- CloudWatch monitoring

## 4. Initial Security Gate Policy

The initial project policy will use the following baseline.

### Secrets

Confirmed secrets:

**BLOCK**

No production credentials will be intentionally committed for testing.

### Static Application Security Testing

Critical findings:

**BLOCK**

High findings:

**BLOCK**

Medium findings:

**REPORT**

Low findings:

**REPORT**

### Dependency Vulnerabilities

Critical vulnerabilities:

**BLOCK**

High vulnerabilities:

**BLOCK**

Medium vulnerabilities:

**REPORT**

Low vulnerabilities:

**REPORT**

### Infrastructure as Code

Failed mandatory infrastructure security policies:

**BLOCK**

Exceptions must be explicitly documented.

### Container Vulnerabilities

Critical vulnerabilities:

**BLOCK**

High vulnerabilities:

**BLOCK**

Medium vulnerabilities:

**REPORT**

Low vulnerabilities:

**REPORT**

These thresholds represent the project's initial security policy and may
be adjusted as the project develops.

## 5. Pipeline Security Stages

The target pipeline will progressively implement:

```text
VALIDATE
   |
   +-- Secret Scan
   +-- IaC Validation
   |
   v
TEST
   |
   +-- Unit Tests
   +-- SAST
   +-- Dependency Scan
   |
   v
BUILD
   |
   +-- Docker Build
   +-- Container Scan
   |
   v
PUBLISH
   |
   +-- Push Approved Image to ECR
   |
   v
DEPLOY
   |
   +-- Deployment Policy Validation
   +-- Deploy to EKS
   |
   v
MONITOR
A failure in a mandatory security gate prevents dependent stages from
executing.

6. Security Evidence

Each security control should generate evidence demonstrating that the
control executed.

Evidence may include:

GitLab pipeline results
scanner reports
failed security jobs
successful rescans
merge request history
CloudTrail events
AWS security findings
ECR image information
Kubernetes deployment status

Portfolio documentation should preserve examples of both failed and
successful security validation.

7. Exception Handling

Security controls should not be silently disabled to allow a pipeline to
succeed.

When an exception is necessary, it should document:

affected finding
business or technical justification
affected resource
risk
compensating control
approval
expiration or review date

This project will prefer remediation over exceptions whenever practical.

8. Control Validation

Each major control will eventually be validated using a controlled failure
scenario.
| Control | Validation Scenario                                | Expected Result                    |
| ------- | -------------------------------------------------- | ---------------------------------- |
| SC-01   | Introduce safe test-secret pattern                 | Pipeline blocked                   |
| SC-02   | Introduce insecure code pattern                    | SAST detects issue                 |
| SC-03   | Introduce controlled vulnerable dependency         | SCA detects vulnerability          |
| SC-04   | Introduce insecure Terraform configuration         | IaC stage blocked                  |
| SC-05   | Build image containing known vulnerable component  | Image promotion blocked            |
| SC-06   | Attempt unauthorized AWS operation                 | IAM denies operation               |
| SC-07   | Introduce prohibited Kubernetes configuration      | Deployment blocked                 |
| SC-08   | Attempt unauthorized security-control modification | Protected workflow prevents change |
| SC-09   | Generate controlled AWS security event             | Monitoring produces evidence       |

9. Control Lifecycle

Security controls will be implemented using the following lifecycle:

Identify threat.
Define security requirement.
Select control.
Implement control.
Test control.
Intentionally trigger control.
Verify enforcement.
Remediate finding.
Verify successful pipeline.
Document evidence.