# Repository Engineering Rules

These rules apply to all engineering work in this repository.

1. Never weaken an existing security control simply to make CI pass.
2. Security controls must fail closed when scanner execution or report integrity cannot be established.
3. Preserve the security reporter exit-code contract:
   - `0` = successful scan with no blocking findings
   - `1` = valid scan with blocking security findings
   - `2` = scanner execution, report integrity, or report-processing error
4. Do not commit generated scanner reports or temporary security artifacts.
5. Never introduce real credentials, tokens, private keys, or long-lived AWS access keys.
6. Controlled vulnerabilities and synthetic secrets may only be used for security-control validation and must be removed before merging.
7. Keep scanner parsing/normalization separate from security-policy decisions where practical.
8. Existing tests and security gates must continue to pass unless a controlled failure test is intentionally being performed.
9. Security-impacting changes should include automated tests.
10. Do not silently change documented security policy. Identify implementation/documentation conflicts before changing either.
11. Use feature branches for new security controls and hardening work.
12. Do not modify GitLab or GitHub remote configuration.
13. Do not push, merge, or delete branches unless explicitly instructed.
14. AWS authentication must use short-lived federation/OIDC rather than stored long-lived AWS credentials when AWS integration is implemented.
15. Prefer straightforward, explainable implementations that can be defended in a technical interview.


## Implemented Security Controls

| Control | Capability |
|---|---|
| SC-01 | Gitleaks secret detection |
| SC-02 | Semgrep static application security testing |
| SC-03 | Trivy dependency vulnerability scanning |
| SC-04 | Checkov infrastructure-as-code policy enforcement |
| SC-05 | Trivy container image scanning |
| SC-06 | GitLab OIDC federation with AWS IAM |
| SC-07 | Conftest Kubernetes deployment policy validation |
| SC-08 | GitLab protected workflow |
| SC-09 | AWS runtime monitoring using CloudTrail, EventBridge, SNS, and KMS |

Security findings are evaluated according to documented blocking,
reporting, and resource-specific exception policies.

See `docs/security-controls.md` for implementation details,
validation evidence, and residual risks.