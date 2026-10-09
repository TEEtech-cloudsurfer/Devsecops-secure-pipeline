# DevSecOps Secure Pipeline Security Controls

## 1. Purpose

This document defines the security controls implemented throughout the DevSecOps Secure Pipeline.

Each control maps an identified threat to a technical control, enforcement mechanism, and evidence source.

The objective is to ensure security tools are implemented to address defined risks rather than added to the pipeline without a security requirement.

---

## 2. Control Matrix

| ID    | Threat                      | Security Control              | Tool / Service                        | Pipeline Stage | Enforcement |
| ----- | --------------------------- | ----------------------------- | ------------------------------------- | -------------- | ----------- |
| SC-01 | T01 Secret Exposure         | Secret detection              | Gitleaks                              | Source         | Block       |
| SC-02 | T02 Vulnerable Code         | Static analysis               | Semgrep                               | Test           | Risk-based  |
| SC-03 | T03 Vulnerable Dependency   | Software composition analysis | Trivy                                 | Test           | Risk-based  |
| SC-04 | T04 Insecure IaC            | IaC security scanning         | Checkov                               | Validate       | Block       |
| SC-05 | T05 Vulnerable Container    | Image vulnerability scanning  | Trivy                                 | Build          | Risk-based  |
| SC-06 | T06 Excessive AWS Access    | Federated CI/CD identity      | GitLab OIDC + AWS IAM/STS             | Deploy         | Preventive  |
| SC-07 | T07 Unauthorized Deployment | Deployment policy             | Policy as Code                        | Deploy         | Block       |
| SC-08 | T08 Pipeline Tampering      | Protected pipeline workflow   | GitLab                                | Source         | Preventive  |
| SC-09 | T09 Runtime Compromise      | Runtime monitoring            | Security Hub / GuardDuty / CloudWatch | Runtime        | Detective   |

---

## 3. Enforcement Model

Security controls are categorized as follows.

### Blocking

A blocking control prevents the pipeline from progressing when a defined security condition is violated.

Examples include:

* detected secrets
* prohibited infrastructure configurations
* deployment policy violations
* vulnerabilities exceeding an established release-risk threshold

### Risk-Based

A risk-based control evaluates findings against defined security characteristics and release-risk thresholds rather than treating every finding identically.

Examples include:

* application vulnerabilities
* dependency vulnerabilities
* container vulnerabilities

Risk-based controls may produce either a BLOCK or REPORT decision depending on the applicable control policy.

### Preventive

A preventive control limits the ability for an insecure action to occur.

Examples include:

* least-privilege IAM
* protected branches
* temporary AWS credentials

### Detective

A detective control identifies suspicious or insecure activity after an artifact has been deployed.

Examples include:

* GuardDuty findings
* Security Hub findings
* CloudWatch monitoring

---

## 4. Security Gate Policy
### Infrastructure as Code

Infrastructure security findings are evaluated against the SC-04 policy classification before promotion.

Known Checkov controls receive an explicit `BLOCK` or `REPORT` decision. Prohibited infrastructure configurations block promotion, while reportable findings remain visible for remediation without automatically failing the pipeline.

Unclassified controls and scanner/report-integrity failures fail closed because the pipeline cannot establish that the infrastructure satisfies the project's security policy.

Detailed SC-04 classifications and validation evidence are documented in the Security Controls section below.

### Secrets

Confirmed secrets:

**BLOCK**

No production credentials will be intentionally committed for testing. Controlled synthetic secrets may be used for security-control validation and must be removed after testing.

### Static Application Security Testing

Semgrep findings are always reported.

Enforcement is based on finding likelihood:

* HIGH likelihood → **BLOCK**
* MEDIUM likelihood → **REPORT**
* LOW likelihood → **REPORT**
* UNKNOWN or missing likelihood → **REPORT**

Semgrep severity, impact, and confidence remain visible as contextual risk information but do not independently determine the pipeline decision.

A blocking finding prevents pipeline promotion.

### Dependency Vulnerabilities

Dependency vulnerabilities are evaluated according to release risk rather than severity alone.

* CRITICAL vulnerabilities → **BLOCK**
* HIGH vulnerabilities → **REPORT** and require prioritized remediation
* MEDIUM vulnerabilities → **REPORT**
* LOW vulnerabilities → **REPORT**
* Scanner execution or report-integrity failure → **ERROR / FAIL CLOSED**

High-severity dependency vulnerabilities require immediate visibility and prioritized remediation but do not automatically prevent application promotion under the baseline project policy.

Critical vulnerabilities exceed the project's initial dependency release-risk threshold and prevent promotion.

Future iterations may incorporate additional context such as exploitability, known exploitation, application exposure, fix availability, and compensating controls.

### Infrastructure as Code

Failed mandatory infrastructure security policies:

**BLOCK**

Exceptions must be explicitly documented.

### Container Vulnerabilities

Initial container security policy:

* CRITICAL vulnerabilities → **BLOCK**
* HIGH vulnerabilities → **BLOCK**
* MEDIUM vulnerabilities → **REPORT**
* LOW vulnerabilities → **REPORT**

This policy will be reevaluated when SC-05 is implemented so container enforcement reflects actual deployment risk and available vulnerability context.

---

## 5. Control Specifications

### SC-01 — Secret Detection

**Threat:** T01 — Secret Exposure

**Tool:** Gitleaks

**Purpose:** Detect credentials, tokens, keys, and other secret material before source code is allowed to progress through the pipeline.

**Enforcement:** Confirmed secret detection results in **BLOCK**.

The control uses the standard Gitleaks detection rules together with a controlled portfolio-specific test-secret rule used to validate control behavior.

The scanner version is pinned to a validated version rather than using a floating `latest` image so that scanner behavior remains reproducible.

**Validation:** A controlled synthetic secret must be detected and produce a blocking result. A clean repository must pass the same control.

### SC-02 — Static Application Security Testing

**Threat:** T02 — Vulnerable Application Code

**Tool:** Semgrep

**Purpose:** Identify insecure application-code patterns before application promotion.

**Enforcement:** Risk-based.

All findings are reported. HIGH-likelihood findings block promotion. MEDIUM, LOW, and UNKNOWN-likelihood findings remain visible but do not independently block promotion.

Scanner execution, report-integrity, or report-processing errors fail closed.

**Validation:** A controlled insecure-code pattern must be detected and evaluated according to the documented enforcement policy. Remediation must result in a successful rescan.

### SC-03 — Software Composition Analysis

**Threat:** T03 — Vulnerable Third-Party Dependency

**Tool:** Trivy

**Purpose:** Identify known vulnerabilities introduced through third-party application dependencies.

**Enforcement:** Risk-based.

* CRITICAL → **BLOCK**
* HIGH → **REPORT / PRIORITIZED REMEDIATION**
* MEDIUM → **REPORT**
* LOW → **REPORT**
* Scanner or report-integrity failure → **ERROR / FAIL CLOSED**

**Rationale:** Dependency findings are evaluated according to release risk rather than severity alone. High-severity vulnerabilities require immediate visibility and prioritized remediation but do not automatically prevent application promotion. Critical vulnerabilities exceed the project's baseline release-risk threshold and block promotion.

**Validation:** Introduce a controlled vulnerable dependency, verify that Trivy detects the vulnerability, confirm the appropriate policy decision, remediate or update the dependency, and verify a successful rescan.

**Status:** Planned for implementation following completion of SECURITY-GATE-HARDENING-01.

### SC-04 — Infrastructure as Code Security

**Threat:** T04 — Insecure Infrastructure as Code

**Tool:** Checkov 3.3.20

**Purpose:** Detect prohibited or insecure Terraform configurations before infrastructure changes progress toward deployment.

**Enforcement:** Risk-based policy enforcement. Checkov findings are validated and normalized before policy evaluation. Classified controls receive either a BLOCK or REPORT decision. BLOCK findings prevent promotion, while REPORT findings remain visible without failing the pipeline. Unclassified Checkov controls fail closed and require human review before the pipeline can continue.

**Policy Classification:**

| Checkov Control | Policy Decision | Rationale |
| --------------- | --------------- | --------- |
| CKV_AWS_24 | BLOCK | Security groups permitting unrestricted SSH access create an unacceptable remote-access exposure. |
| CKV_AWS_23 | REPORT | Security-group description findings require visibility and remediation but do not independently exceed the release-risk threshold. |
| CKV2_AWS_5 | REPORT | Unattached security groups require review but do not independently represent a prohibited deployment condition. |

**Validation:** Scan controlled Terraform with Checkov and preserve the JSON evidence artifact. Verify that known nonblocking findings are reported without stopping promotion. Introduce a controlled prohibited configuration permitting SSH from `0.0.0.0/0`, verify detection of CKV_AWS_24, and confirm that the security gate blocks promotion. Restore the secure configuration and verify the repository returns to its expected state.

**Status:** Implemented and validated.

### SC-05 — Container Image Security

**Threat:** T05 — Vulnerable Container Image

**Tool:** Trivy

**Purpose:** Identify vulnerable operating-system packages and application components contained within built container images.

**Enforcement:** Risk-based. Final enforcement criteria will be validated during SC-05 implementation.

**Status:** Planned.

### SC-06 — Federated CI/CD Identity

**Threat:** T06 — Excessive AWS Access

**Tool:** GitLab OIDC + AWS IAM/STS

**Purpose:** Provide temporary, least-privilege AWS credentials to CI/CD workloads without storing long-lived AWS access keys.

**Enforcement:** Preventive.

**Authorization Foundation:**

A Terraform-managed AWS deployment identity and repository-scoped IAM policy establish the least-privilege authorization boundary required by the CI/CD deployment workflow.

Required ECR operations are explicitly permitted:

- `ecr:GetAuthorizationToken`
- `ecr:BatchCheckLayerAvailability`
- `ecr:CompleteLayerUpload`
- `ecr:InitiateLayerUpload`
- `ecr:PutImage`
- `ecr:UploadLayerPart`

Image operations are restricted to the `devsecops-secure-pipeline` ECR repository. Administrative ECR permissions such as `ecr:DeleteRepository` are not granted.

**Authorization Validation:**

AWS IAM policy simulation confirmed:

- `ecr:GetAuthorizationToken` → `allowed`
- `ecr:PutImage` against the project repository → `allowed`
- `ecr:DeleteRepository` against the project repository → `implicitDeny`

The negative test validates AWS IAM default-deny behavior rather than relying on an artificial explicit-deny statement.

The authorization tests are repeatable through:

`./scripts/aws/validate_iam_authorization.sh`

The validation script fails if required deployment operations are not allowed or if repository deletion is not implicitly denied.

**Regression Validation:**

The existing security-control test suite remained successful after the IAM implementation:

`70 passed`

***Federation Validation:**

GitLab CI/CD successfully authenticated to AWS using an OIDC identity token with the audience `sts.amazonaws.com`.

AWS STS successfully exchanged the GitLab OIDC token through `AssumeRoleWithWebIdentity` and issued temporary credentials for the `devsecops-pipeline-deployer` IAM role.

The role trust policy restricts federation to:

- GitLab as the trusted OIDC provider
- the `TEEtech-cloudsurfer/devsecops-secure-pipeline` project
- the `main` branch
- the `sts.amazonaws.com` audience

The GitLab deployment job successfully validated the assumed AWS identity with `aws sts get-caller-identity` and verified authorized ECR authentication.

No long-lived AWS access keys or secret access keys are stored in GitLab CI/CD.

**Status:** Implemented and validated.

### SC-07 — Deployment Policy

**Threat:** T07 — Unauthorized Container Deployment

**Tool:** Policy as Code

**Purpose:** Prevent workloads that violate established deployment requirements from reaching the Kubernetes environment.

**Enforcement:** Policy violations block deployment.

**Status:** Planned.

## SC-08 — GitLab Protected Pipeline Workflow

**Status:** Implemented and validated

### Security Objective
Protect the integrity of the DevSecOps pipeline by preventing
unauthorized direct changes to the default branch and requiring
successful CI validation before changes can be merged.

### Implemented Controls
- Protected default branch (`main`).
- Direct pushes to `main` disabled.
- Merge permissions restricted to Maintainers.
- Successful pipelines required before merging.
- All merge request discussions must be resolved.

### Validation Evidence
1. Attempted a direct push to `main`.
   - Result: Rejected by GitLab protected branch enforcement.
2. Introduced a temporary failing CI job.
   - Result: Pipeline failed as expected.
3. Verified the merge request displayed "Merge blocked".
   - Result: Failed pipeline prevented merging.
4. Removed the temporary failing job.
   - Result: All pipeline jobs passed and merge became eligible.

### Residual Risk
Mandatory independent reviewer approvals and Code Owner approval
enforcement are unavailable under the current GitLab plan.

Maintainers retain administrative authority over project settings.
Therefore, SC-08 protects the normal merge workflow but does not
provide an immutable separation-of-duties control.

### Security Outcome
Direct branch modifications are prevented, and the configured
merge workflow requires successful CI validation before changes
can enter the protected default branch.

### SC-09 — AWS Runtime Security Monitoring

**Objective:** Detect security-relevant modifications to the DevSecOps deployment IAM role and ECR repository, and generate automated security notifications.

**Implementation:**
- AWS CloudTrail multi-Region trail captures management events, including global IAM activity.
- Amazon S3 provides encrypted audit-log storage with public access blocked, versioning enabled, and lifecycle-based retention.
- Amazon EventBridge rules monitor selected IAM role and ECR repository API operations.
- Amazon SNS delivers matching security events to a confirmed email subscription.
- Terraform manages the monitoring infrastructure.
- Amazon SNS uses a customer-managed AWS KMS key for encryption at rest.
- The KMS key policy permits EventBridge to generate data keys and decrypt
  as required for encrypted security notification delivery.
- KMS key rotation is enabled.

**Validation performed:**
- Terraform configuration validated successfully.
- CloudTrail confirmed active with successful S3 log delivery and no reported delivery errors.
- Positive and negative EventBridge pattern tests passed for IAM and ECR.
- Synthetic EventBridge-to-SNS notification delivery succeeded.
- A live `UpdateAssumeRolePolicy` API operation was executed against the deployment IAM role using its existing trust policy.
- CloudTrail recorded the IAM management event.
- EventBridge matched the event and delivered it through SNS.
- The SNS security alert was received by email.
- A controlled EventBridge event was published to the encrypted SNS topic.
- EventBridge accepted the event with zero failed entries.
- The encrypted SNS notification was successfully received by email.
- Checkov confirmed remediation of CKV_AWS_26 and CKV_AWS_300.
- SC-04 evaluated 12 remaining findings as REPORT with zero blocking findings.
- Resource-scoped exceptions for CKV_AWS_109, CKV_AWS_111, and CKV_AWS_356
  passed six positive and negative regression tests.
- The complete Python automated test suite passed all 76 tests.

**Security outcome:** Successfully demonstrated automated detection and notification of a real IAM trust-policy update operation affecting the CI/CD deployment role.

**Limitations and residual risks:**
- Live ECR event detection has not yet been validated end-to-end.
- Monitoring covers selected API operations and resources rather than all AWS security events.
- Email notifications provide alerting but do not implement automatic remediation.
- CloudTrail and EventBridge delivery are not guaranteed to be instantaneous.
- Independent review and alert-response procedures remain operational considerations.
- Twelve Checkov findings remain classified as REPORT. These represent
  residual security limitations rather than fully remediated controls.
- The KMS key policy retains the standard account-root IAM delegation
  statement using kms:*.
- CKV_AWS_109, CKV_AWS_111, and CKV_AWS_356 are permitted only for
  aws_iam_policy_document.security_alerts_kms.
- Resource-specific exceptions are currently matched by Checkov resource
  identifier and do not independently validate the full KMS policy contents.
- CloudTrail does not currently use KMS CMK encryption or CloudWatch Logs
  integration; these remain future hardening considerations.
- Production deployment requires review of accepted risks, effective IAM
  permissions, monitoring coverage, and log-retention requirements.

**Evidence:** Terraform infrastructure configuration, successful CloudTrail logging status, EventBridge pattern tests, CloudTrail event history, and received SNS notification.

---

## 6. Pipeline Security Stages

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
```

A failure in a mandatory security gate prevents dependent stages from executing.

---

## 7. Security Evidence

Each security control should generate evidence demonstrating that the control executed.

Evidence may include:

* GitLab pipeline results
* scanner reports
* failed security jobs
* successful rescans
* merge history
* CloudTrail events
* AWS security findings
* ECR image information
* Kubernetes deployment status

Portfolio documentation should preserve examples of both failed and successful security validation.

---

## 8. Exception Handling

Security controls should not be silently disabled to allow a pipeline to succeed.

When an exception is necessary, it should document:

* affected finding
* business or technical justification
* affected resource
* risk
* compensating control
* approval
* expiration or review date

This project will prefer remediation over exceptions whenever practical.

---

## 9. Control Validation

Each major control will be validated using a controlled failure scenario.

| Control | Validation Scenario                                | Expected Result                                         |
| ------- | -------------------------------------------------- | ------------------------------------------------------- |
| SC-01   | Introduce safe test-secret pattern                 | Pipeline blocks the controlled secret                   |
| SC-02   | Introduce insecure code pattern                    | SAST detects the issue and applies risk-based policy    |
| SC-03   | Introduce controlled vulnerable dependency         | SCA detects vulnerability and applies dependency policy |
| SC-04   | Introduce insecure Terraform configuration         | IaC stage blocks prohibited configuration               |
| SC-05   | Build image containing known vulnerable component  | Image control applies documented promotion policy       |
| SC-06   | Attempt unauthorized AWS operation                 | IAM denies operation                                    |
| SC-07   | Introduce prohibited Kubernetes configuration      | Deployment blocked                                      |
| SC-08   | Attempt unauthorized security-control modification | Protected workflow prevents change                      |
| SC-09   | Generate controlled AWS security event             | Monitoring produces evidence                            |

### Validation Evidence

* Trivy 0.74.0 detected controlled vulnerabilities in Flask 2.0.0.
* HIGH and LOW findings were normalized and reported without blocking.
* Flask 3.1.3 produced a clean dependency scan.
* CRITICAL severity policy is covered by automated tests and returns BLOCK.
* Malformed Trivy evidence fails closed with exit code 2.
* * Reporter regression suite reached 70 passing tests after implementation of SC-05 container security policy coverage.
* GitLab feature-branch pipeline passed dependency_scan and dependency_gate.
* Checkov 3.3.20 scanned the Terraform configuration with no parsing errors.
* CKV2_AWS_5 was classified as REPORT; the security gate recorded the finding with zero blocking findings and returned exit code 0.
* A controlled negative test changed SSH ingress to `0.0.0.0/0`, causing Checkov to detect CKV_AWS_24.
* SC-04 classified CKV_AWS_24 as BLOCK while retaining CKV2_AWS_5 as REPORT; the security gate reported one blocking finding and returned exit code 1.
* The secure Terraform configuration was restored after controlled negative-path validation.
* SC-05 container image security was implemented using Trivy 0.74.0 against the built runtime container image.
* Initial container validation identified a larger vulnerability surface in the `python:3.10-slim` runtime. OS package remediation reduced the initial HIGH OS findings from 51 to 44, but significant residual runtime exposure remained.
* A Debian Bookworm runtime experiment was rejected after producing 53 HIGH and 2 CRITICAL OS findings.
* A packaging-tool upgrade experiment was also rejected after increasing Python-package HIGH findings rather than reducing runtime risk.
* The application was migrated to a multi-stage container build using a distroless Debian 13 runtime to reduce unnecessary runtime packages and tooling.
* The distroless runtime successfully passed the application health check and executed as non-root user UID 65532.
* Trivy scanning of the distroless runtime reported 26 HIGH and 0 CRITICAL OS findings, reducing HIGH OS findings by approximately 49% compared with the initial 51-HIGH runtime baseline.
* Remaining HIGH findings without an available fixed version are classified as REPORT for residual-risk visibility. HIGH findings with an available fixed version are classified as BLOCK.
* All CRITICAL container findings are classified as BLOCK and require remediation or explicit human risk review before release.
* The real distroless container scan produced no blocking findings and the SC-05 security gate returned exit code 0.
* A controlled negative-path test added a synthetic fixed version to a HIGH vulnerability. SC-05 classified the finding as BLOCK and returned exit code 1.
* Automated tests verify SC-05 HIGH-with-fix, HIGH-without-fix, CRITICAL-with-fix, CRITICAL-without-fix, and SC-03/SC-05 policy separation behavior.
* Reporter regression testing completed successfully with 70 tests passed.
* GitLab CI implements container build, Trivy image scanning, JSON evidence preservation, and a dedicated SC-05 policy gate.
* The GitLab feature-branch pipeline completed successfully with the container build, container scan, and container security gate all passing.

---

## 10. Control Lifecycle

Security controls will be implemented using the following lifecycle:

1. Identify threat.
2. Define security requirement.
3. Define enforcement policy.
4. Select control and tooling.
5. Implement control.
6. Test control.
7. Intentionally trigger control.
8. Verify enforcement.
9. Remediate finding.
10. Verify successful pipeline.
11. Document evidence.

---

## 11. Hardening Milestone and Roadmap

### SECURITY-GATE-HARDENING-01 — Harden Existing CI Security Controls

**Status:** **COMPLETED**

**Objective:** Validate that the existing CI security gates are reliable, fail closed, align with documented security policy, and have automated test coverage before SC-03 dependency scanning is introduced.

### Acceptance Criteria

**SGH-01 — Gitleaks hardening**

Gitleaks must detect the controlled portfolio test-secret pattern while retaining standard
