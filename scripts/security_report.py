import argparse
import json
import sys
from pathlib import Path


CHECKOV_POLICY = {
    # Existing controls
    "CKV_AWS_24": "BLOCK",
    "CKV_AWS_23": "REPORT",
    "CKV2_AWS_5": "REPORT",
    "CKV_AWS_136": "REPORT",

    # SC-09 remediation
    "CKV_AWS_300": "BLOCK",
    "CKV_AWS_26": "BLOCK",

    # SC-09 accepted limitations
    "CKV_AWS_252": "REPORT",
    "CKV_AWS_35": "REPORT",
    "CKV2_AWS_10": "REPORT",
    "CKV2_AWS_62": "REPORT",
    "CKV_AWS_18": "REPORT",
    "CKV_AWS_144": "REPORT",
    "CKV_AWS_145": "REPORT",
}
CHECKOV_RESOURCE_EXCEPTIONS = {
    "aws_iam_policy_document.security_alerts_kms": {
        "CKV_AWS_109": "REPORT",
        "CKV_AWS_111": "REPORT",
        "CKV_AWS_356": "REPORT",
    }
}


def load_json(report_path):
    """Load a scanner JSON report."""
    path = Path(report_path)

    if not path.exists():
        raise FileNotFoundError(f"Report not found: {report_path}")

    with path.open("r", encoding="utf-8") as report_file:
        return json.load(report_file)


def validate_semgrep(report):
    """Reject incomplete scans before normalization or policy evaluation.

    JSON cannot authenticate scanner execution; CI must also check the scanner's
    process exit status. Require evidence that at least one target was scanned.
    No scanner-error exceptions are approved, so all reported errors fail closed.
    """
    if not isinstance(report, dict):
        raise ValueError("Semgrep report must be an object")
    if not isinstance(report.get("version"), str) or not report["version"].strip():
        raise ValueError("Semgrep report requires a nonempty version")
    for field in ("results", "errors"):
        if not isinstance(report.get(field), list):
            raise ValueError(f"Semgrep report requires a {field} list")
    if report["errors"]:
        raise ValueError("Semgrep reported scanner errors; scan reliability is unknown")

    paths = report.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("Semgrep report requires a paths object")
    scanned = paths.get("scanned")
    if (not isinstance(scanned, list) or not scanned
            or any(not isinstance(path, str) or not path.strip() for path in scanned)):
        raise ValueError("Semgrep report requires a nonempty paths.scanned list of paths")

    for result in report["results"]:
        if not isinstance(result, dict):
            raise ValueError("Semgrep finding must be an object")
        for field in ("check_id", "path"):
            if not isinstance(result.get(field), str) or not result[field].strip():
                raise ValueError(f"Semgrep finding requires a nonempty {field}")
        start = result.get("start")
        if (not isinstance(start, dict) or type(start.get("line")) is not int
                or start["line"] < 1):
            raise ValueError("Semgrep finding requires a positive start.line")
        extra = result.get("extra")
        if not isinstance(extra, dict):
            raise ValueError("Semgrep finding requires an extra object")
        for field in ("severity", "message"):
            if not isinstance(extra.get(field), str) or not extra[field].strip():
                raise ValueError(f"Semgrep finding requires a nonempty extra.{field}")
        metadata = extra.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Semgrep finding metadata must be an object")
        cwe = metadata.get("cwe", [])
        if not isinstance(cwe, (str, list)) or (
                isinstance(cwe, list) and any(not isinstance(value, str) for value in cwe)):
            raise ValueError("Semgrep finding CWE must be a string or list of strings")

def validate_trivy(report):
    """Validate the minimum Trivy report structure required for policy decisions."""

    # The top-level Trivy report must be a JSON object.
    if not isinstance(report, dict):
        raise ValueError("Trivy report must be a JSON object")

    # SchemaVersion identifies the Trivy JSON report schema.
    # Reject bool explicitly because bool is a subclass of int in Python.
    schema_version = report.get("SchemaVersion")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version <= 0
    ):
        raise ValueError("Trivy report has an invalid SchemaVersion")

    # Trivy contains scanner metadata, including the scanner version.
    trivy_metadata = report.get("Trivy")
    if not isinstance(trivy_metadata, dict):
        raise ValueError("Trivy report is missing valid Trivy metadata")

    # Results contains the targets Trivy actually analyzed.
    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError("Trivy report is missing a valid Results list")

    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Trivy result must be a JSON object")

        target = result.get("Target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Trivy result is missing a valid Target")

        package_type = result.get("Type")
        if not isinstance(package_type, str) or not package_type.strip():
            raise ValueError("Trivy result is missing a valid Type")

        # Trivy 0.74.0 omits the Vulnerabilities key when a target has
        # no detected vulnerabilities. That is a valid clean result.
        if "Vulnerabilities" not in result:
            continue

        vulnerabilities = result["Vulnerabilities"]

        if not isinstance(vulnerabilities, list):
            raise ValueError(
                "Trivy Vulnerabilities must be a list when present"
            )

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("Trivy vulnerability must be a JSON object")

            required_fields = (
                "VulnerabilityID",
                "PkgName",
                "InstalledVersion",
                "Severity",
            )

            for field in required_fields:
                value = vulnerability.get(field)

                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"Trivy vulnerability is missing valid {field}"
                    )

            # FixedVersion is intentionally optional. A vulnerability may
            # legitimately have no known fixed version.
            if "FixedVersion" in vulnerability:
                fixed_version = vulnerability["FixedVersion"]

                if fixed_version is not None and not isinstance(
                    fixed_version, str
                ):
                    raise ValueError(
                        "Trivy vulnerability has an invalid FixedVersion"
                    )

def validate_checkov(report):
    """Validate Checkov evidence required for SC-04 policy decisions."""

    if not isinstance(report, dict):
        raise ValueError("Checkov report must be a JSON object")

    check_type = report.get("check_type")
    if not isinstance(check_type, str) or not check_type.strip():
        raise ValueError("Checkov report requires a nonempty check_type")

    results = report.get("results")
    if not isinstance(results, dict):
        raise ValueError("Checkov report requires a results object")

    required_result_lists = (
        "passed_checks",
        "failed_checks",
        "skipped_checks",
        "parsing_errors",
    )

    for field in required_result_lists:
        if not isinstance(results.get(field), list):
            raise ValueError(f"Checkov results require a {field} list")

    if results["parsing_errors"]:
        raise ValueError(
            "Checkov reported Terraform parsing errors; "
            "scan reliability is unknown"
        )

    for finding in results["failed_checks"]:
        if not isinstance(finding, dict):
            raise ValueError("Checkov failed check must be a JSON object")

        for field in ("check_id", "check_name", "file_path", "resource"):
            value = finding.get(field)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Checkov failed check requires a nonempty {field}"
                )

        check_result = finding.get("check_result")

        if not isinstance(check_result, dict):
            raise ValueError(
                "Checkov failed check requires a check_result object"
            )

        if check_result.get("result") != "FAILED":
            raise ValueError(
                "Checkov failed_checks entry must have result FAILED"
            )

def determine_checkov_pipeline_decision(check_id, resource=None):
    """Determine Checkov enforcement with resource-scoped exceptions."""

    exceptions = CHECKOV_RESOURCE_EXCEPTIONS.get(resource, {})

    if check_id in exceptions:
        return exceptions[check_id]

    if check_id not in CHECKOV_POLICY:
        raise ValueError(
            f"Checkov detected unclassified control {check_id}. "
            "The finding requires human review before the pipeline can continue."
        )

    return CHECKOV_POLICY[check_id]

def normalize_checkov(report):
    """Normalize validated Checkov failures into security findings."""

    validate_checkov(report)

    findings = []

    for result in report["results"]["failed_checks"]:
        check_id = result["check_id"]

        try:
            pipeline_decision = determine_checkov_pipeline_decision(
    check_id,
    result["resource"],
)
        except ValueError as error:
            raise ValueError(
                f"{error} "
                f"Checkov reported: '{result['check_name']}'. "
                f"Affected resource: {result['resource']}. "
                f"Terraform file: {result['file_path']}. "
                "Required action: review this finding and classify the control "
                "as BLOCK or REPORT in the SC-04 policy."
            ) from error

        findings.append(
            {
                "scanner": "Checkov",
                "control_id": "SC-04",
                "rule_id": check_id,
                "severity": result.get("severity") or "UNSPECIFIED",
                "description": result["check_name"],
                "remediation": (
                    "Review the affected Terraform configuration and remediate "
                    "the infrastructure security finding before deployment."
                ),
                "file": result["file_path"],
                "resource": result["resource"],
                "pipeline_decision": pipeline_decision,
            }
        )

    return findings

def determine_trivy_pipeline_decision(severity):
    """Determine pipeline enforcement for dependency vulnerabilities."""
    if severity.upper() == "CRITICAL":
        return "BLOCK"

    return "REPORT"

def determine_container_pipeline_decision(severity, fixed_version):
    """Determine pipeline enforcement for container image vulnerabilities."""
    severity = severity.upper()

    if severity == "CRITICAL":
        return "BLOCK"

    if severity == "HIGH" and fixed_version:
        return "BLOCK"

    return "REPORT"

def normalize_trivy(report, control_id="SC-03"):
    """Normalize validated Trivy vulnerabilities into security findings."""

    validate_trivy(report)

    findings = []

    for result in report["Results"]:
        target = result["Target"]
        package_type = result["Type"]

        # A clean Trivy target may omit Vulnerabilities entirely.
        vulnerabilities = result.get("Vulnerabilities", [])

        for vulnerability in vulnerabilities:
            severity = vulnerability["Severity"].upper()
            package = vulnerability["PkgName"]
            installed_version = vulnerability["InstalledVersion"]
            fixed_version = vulnerability.get("FixedVersion", "")

            # Use Trivy's vulnerability title when available.
            description = vulnerability.get(
                "Title",
                f"{package} {installed_version} contains "
                f"{vulnerability['VulnerabilityID']}",
            )

            # A fixed version may legitimately be unavailable.
            if fixed_version:
                remediation = (
                    f"Upgrade {package} from {installed_version} "
                    f"to a fixed version: {fixed_version}."
                )
            else:
                remediation = (
                    f"Review {package} {installed_version} and apply "
                    "available vendor remediation or compensating controls."
                )

            findings.append(
                {
                    "scanner": "Trivy",
                    "control_id": control_id,
                    "rule_id": vulnerability["VulnerabilityID"],
                    "severity": severity,
                    "description": description,
                    "remediation": remediation,
                    "package": package,
                    "installed_version": installed_version,
                    "fixed_version": fixed_version,
                    "target": target,
                    "package_type": package_type,
                    "pipeline_decision": (
                        determine_container_pipeline_decision(severity, fixed_version)
                        if control_id == "SC-05"
                        else determine_trivy_pipeline_decision(severity)
                    ),
                }
            )

    return findings

def determine_pipeline_decision(likelihood):
    """Determine pipeline enforcement based on finding likelihood."""
    if likelihood == "HIGH":
        return "BLOCK"

    return "REPORT"

def normalize_semgrep(report):
    """Convert Semgrep results into the common finding format."""
    validate_semgrep(report)
    findings = []

    for result in report["results"]:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        likelihood = metadata.get("likelihood", "UNKNOWN")
        start = result.get("start", {})

        cwe_values = metadata.get("cwe", [])
        if isinstance(cwe_values, str):
            cwe_values = [cwe_values]

        finding = {
            "scanner": "Semgrep",
            "control_id": "SC-02",
            "rule_id": result.get("check_id", "unknown"),
            "severity": extra.get("severity", "UNKNOWN"),
            "likelihood": likelihood,
            "impact": metadata.get("impact", "UNKNOWN"),
            "confidence": metadata.get("confidence", "UNKNOWN"),
            "category": metadata.get("category", "unknown"),
            "cwe": ", ".join(cwe_values) if cwe_values else "N/A",
            "file": result.get("path", "unknown"),
            "line": start.get("line", "unknown"),
            "description": extra.get("message", "No description provided"),
            "remediation": "Review the finding and remediate the insecure code pattern.",
            "pipeline_decision": determine_pipeline_decision(likelihood),
        }

        findings.append(finding)

    return findings


def print_report(findings):
    """Render normalized security findings in a developer-friendly format."""
    print("=" * 64)
    print("SECURITY RESULTS")
    print("=" * 64)

    if not findings:
        print("Status:   PASSED")
        print("Findings: 0")
        print("=" * 64)
        return 0

    blocking_findings = [
        finding
        for finding in findings
        if finding["pipeline_decision"] == "BLOCK"
    ]

    if blocking_findings:
        print("Status:   BLOCKED")
    else:
        print("Status:   PASSED")

    print(f"Findings: {len(findings)}")
    print(f"Blocking: {len(blocking_findings)}")

    for number, finding in enumerate(findings, start=1):
        print("-" * 64)
        print(f"[{number}] {finding['rule_id']}")
        print(f"Scanner:     {finding['scanner']}")
        print(f"Control:     {finding['control_id']}")
        print(f"Severity:    {finding['severity']}")

        # Scanner-specific contextual fields.
        optional_fields = (
            ("Likelihood", "likelihood"),
            ("Impact", "impact"),
            ("Confidence", "confidence"),
            ("Category", "category"),
            ("CWE", "cwe"),
            ("File", "file"),
            ("Line", "line"),
            ("Package", "package"),
            ("Installed", "installed_version"),
            ("Fixed", "fixed_version"),
            ("Target", "target"),
            ("Package Type", "package_type"),
            ("Resource", "resource"),
        )

        for label, key in optional_fields:
            value = finding.get(key)

            if value not in (None, "", []):
                print(f"{label + ':':<13}{value}")

        print()
        print(f"Issue: {finding['description']}")
        print()
        print(f"Remediation: {finding['remediation']}")
        print()
        print(f"Pipeline Decision: {finding['pipeline_decision']}")

    print("=" * 64)

    return 1 if blocking_findings else 0


def main():
    parser = argparse.ArgumentParser(
        description="Normalize security scanner results."
    )

    parser.add_argument(
        "--scanner",
        choices=["semgrep", "trivy", "checkov"],
        required=True,
        help="Scanner that generated the report.",
    )

    parser.add_argument(
        "--control",
        choices=["SC-03", "SC-05"],
        help="Security control policy to apply to Trivy results.",
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the scanner JSON report.",
    )

    args = parser.parse_args()

    try:
        report = load_json(args.input)

        if args.scanner == "semgrep":
            findings = normalize_semgrep(report)
        elif args.scanner == "trivy":
            findings = normalize_trivy(
                report,
                control_id=args.control or "SC-03"
            )
        elif args.scanner == "checkov":
            findings = normalize_checkov(report)
        else:
            findings = []

        exit_code = print_report(findings)
        sys.exit(exit_code)

    except Exception as error:
        # At the CLI boundary, processing failures are errors (2), not findings
        # (1). This also covers I/O, encoding, and unexpected normalization errors.
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
