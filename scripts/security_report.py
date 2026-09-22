import argparse
import json
import sys
from pathlib import Path


def load_json(report_path):
    """Load a scanner JSON report."""
    path = Path(report_path)

    if not path.exists():
        raise FileNotFoundError(f"Report not found: {report_path}")

    with path.open("r", encoding="utf-8") as report_file:
        return json.load(report_file)


def normalize_semgrep(report):
    """Convert Semgrep results into the common finding format."""
    findings = []

    for result in report.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        start = result.get("start", {})

        cwe_values = metadata.get("cwe", [])

        finding = {
            "scanner": "Semgrep",
            "control_id": "SC-02",
            "rule_id": result.get("check_id", "unknown"),
            "severity": extra.get("severity", "UNKNOWN"),
            "confidence": metadata.get("confidence", "UNKNOWN"),
            "category": metadata.get("category", "unknown"),
            "cwe": ", ".join(cwe_values) if cwe_values else "N/A",
            "file": result.get("path", "unknown"),
            "line": start.get("line", "unknown"),
            "description": extra.get("message", "No description provided"),
            "remediation": "Review the finding and remediate the insecure code pattern.",
            "pipeline_decision": "BLOCK",
        }

        findings.append(finding)

    return findings


def print_report(findings):
    """Render normalized findings in a developer-friendly format."""
    print("=" * 64)
    print("SECURITY RESULTS")
    print("=" * 64)

    if not findings:
        print("Status:   PASSED")
        print("Findings: 0")
        print("=" * 64)
        return 0


    print("Status:   BLOCKED")
    print(f"Findings: {len(findings)}")

    for number, finding in enumerate(findings, start=1):
        print("-" * 64)
        print(f"[{number}] {finding['rule_id']}")
        print(f"Scanner:     {finding['scanner']}")
        print(f"Control:     {finding['control_id']}")
        print(f"Severity:    {finding['severity']}")
        print(f"Confidence:  {finding['confidence']}")
        print(f"Category:    {finding['category']}")
        print(f"CWE:         {finding['cwe']}")
        print(f"File:        {finding['file']}")
        print(f"Line:        {finding['line']}")
        print()
        print(f"Issue: {finding['description']}")
        print()
        print(f"Remediation: {finding['remediation']}")
        print()
        print(f"Pipeline Decision: {finding['pipeline_decision']}")

    print("=" * 64)
    return 1


def main():
    parser = argparse.ArgumentParser(
        description="Normalize security scanner results."
    )

    parser.add_argument(
        "--scanner",
        required=True,
        choices=["semgrep"],
        help="Scanner that generated the report.",
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
        else:
            findings = []

        exit_code = print_report(findings)
        sys.exit(exit_code)

    except (FileNotFoundError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
