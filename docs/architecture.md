# DevSecOps Secure Pipeline Architecture

## 1. Purpose

This document defines the architecture of the DevSecOps Secure Pipeline,
including major system components, trust boundaries, security control
points, and the flow of software artifacts from source code to the AWS
runtime environment.

The architecture is designed around defense in depth, least privilege,
shift-left security, automated security validation, and controlled
promotion of software artifacts.

## 2. High-Level Architecture

```text
Developer Workstation
        |
        | Git Push / Merge Request
        v
+---------------------------+
| GitLab Repository         |
| Source Code               |
| Terraform                 |
| Kubernetes Manifests      |
+---------------------------+
        |
        v
+---------------------------+
| GitLab CI/CD              |
|                           |
|  SAST                     |
|  Secret Scanning          |
|  Dependency Scanning      |
|  IaC Scanning             |
+---------------------------+
        |
        | Security Gates
        v
+---------------------------+
| Build Stage               |
| Docker Image              |
+---------------------------+
        |
        v
+---------------------------+
| Container Security Scan   |
+---------------------------+
        |
        | Approved Artifact
        v
+---------------------------+
| Amazon ECR                |
+---------------------------+
        |
        | Image Deployment
        v
+---------------------------+
| Amazon EKS                |
+---------------------------+
        |
        v
+---------------------------+
| AWS Security Monitoring   |
| Security Hub              |
| GuardDuty                 |
| CloudWatch                |
+---------------------------+

3. Primary Components
Developer Workstation

The developer workstation is used to create application code,
infrastructure-as-code, Kubernetes manifests, tests, and pipeline
configuration.

Local development controls reduce accidental exposure of credentials and
unnecessary artifacts but are not considered sufficient security
boundaries.

GitLab Repository

GitLab serves as the source control system and entry point into the
automated delivery process.

Changes pushed to the repository will trigger CI/CD security validation.

GitLab CI/CD

GitLab CI/CD orchestrates application testing, security scanning, artifact
creation, and deployment activities.

Security jobs will evaluate multiple classes of risk before an artifact is
permitted to progress through the pipeline.

Container Build

Application code that passes the required pre-build security controls is
packaged into a Docker container image.

The resulting image is treated as a new security artifact and must undergo
container vulnerability scanning.

Amazon ECR

Amazon Elastic Container Registry stores container images that have
satisfied the required pipeline controls.

Pipeline access to ECR will use narrowly scoped AWS permissions rather than
general administrative credentials.

Amazon EKS

Amazon Elastic Kubernetes Service provides the target Kubernetes runtime
environment.

Deployment occurs only after required pipeline security controls have
completed successfully.

AWS Security Monitoring

AWS-native security services provide detective controls after deployment.

Security Hub, GuardDuty, and CloudWatch will be used to demonstrate the
transition from preventive pipeline security to runtime security
monitoring.

4. Trust Boundaries
Trust Boundary 1: Developer to Source Control

A developer-controlled workstation cannot automatically be trusted by the
CI/CD environment.

Risks include:

exposed credentials
malicious or vulnerable code
vulnerable dependencies
insecure configuration
accidental sensitive files

Repository and pipeline controls therefore validate submitted content.

Trust Boundary 2: Source Control to Build Environment

Source code entering the build environment must pass defined security
checks before producing a deployable artifact.

Failure of mandatory security controls prevents progression through the
pipeline.

Trust Boundary 3: Build Environment to AWS

The CI/CD system requires AWS access to publish and eventually deploy
artifacts.

This boundary introduces credential and authorization risk.

AWS access will therefore follow least-privilege principles and will be
limited to the actions required by the pipeline.

Trust Boundary 4: Container Registry to Kubernetes

An image existing in a container registry does not automatically make the
image trusted.

Deployment controls must ensure that only approved artifacts are promoted
to the Kubernetes environment.

Trust Boundary 5: Deployment to Runtime

Successful deployment does not guarantee continued security.

Runtime activity must therefore be monitored for suspicious behavior,
configuration drift, and security findings.

5. Security Control Points
| Control Point  | Control             | Expected Result                     |
| -------------- | ------------------- | ----------------------------------- |
| Source         | Secret scanning     | Detect exposed credentials          |
| Application    | SAST                | Detect insecure coding patterns     |
| Dependencies   | SCA                 | Detect known vulnerable packages    |
| Infrastructure | IaC scanning        | Detect insecure cloud configuration |
| Container      | Image scanning      | Detect vulnerable image components  |
| Deployment     | Policy enforcement  | Block noncompliant deployment       |
| AWS Access     | Least-privilege IAM | Limit CI/CD permissions             |
| Runtime        | Security monitoring | Detect post-deployment threats      |

6. Security Gate Philosophy

Security findings are not treated equally.

Pipeline enforcement will eventually consider factors such as:

vulnerability severity
exploitability
affected component
security-control type
deployment environment
approved exceptions

Critical security conditions should prevent artifact promotion unless an
explicitly documented exception process exists.

The project will document both blocked deployments and successful
remediation.

7. Artifact Promotion Model
SOURCE
   |
   v
VALIDATED SOURCE
   |
   v
BUILT IMAGE
   |
   v
SCANNED IMAGE
   |
   v
APPROVED IMAGE
   |
   v
DEPLOYED WORKLOAD

Each transition represents a security decision.

An artifact should progress only when the controls required for that stage
have succeeded.

8. Design Principles

The architecture follows these principles:

Shift security testing left in the SDLC.
Apply defense in depth rather than relying on a single scanner.
Use least-privilege access between CI/CD and AWS.
Treat build artifacts as untrusted until validated.
Automate repeatable security decisions where practical.
Preserve evidence of failed and successful security validation.
Maintain runtime monitoring after deployment.
Document security exceptions rather than silently bypassing controls.
9. Future Architecture Enhancements

Later phases may introduce:

OpenID Connect federation between GitLab and AWS
image signing and verification
software bill of materials (SBOM) generation
Kubernetes admission policies
policy-as-code enforcement
automated security notifications
centralized security findings



