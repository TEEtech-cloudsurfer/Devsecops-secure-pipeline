import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.security_report import (
    determine_checkov_pipeline_decision,
    normalize_checkov,
    validate_checkov,
)



REPORTER = Path(__file__).resolve().parents[1] / "scripts" / "security_report.py"
SPEC = importlib.util.spec_from_file_location("security_report", REPORTER)
security_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security_report)


@pytest.fixture
def report():
    return {
        "version": "1.100.0",
        "results": [],
        "errors": [],
        "paths": {"scanned": ["application/app.py"]},
    }


@pytest.fixture
def finding():
    return {
        "check_id": "test.security-rule",
        "path": "application/app.py",
        "start": {"line": 1, "col": 1, "offset": 0},
        "end": {"line": 1, "col": 2, "offset": 1},
        "extra": {"severity": "WARNING", "message": "Synthetic finding", "metadata": {}},
    }


def run_reporter(path, scanner="semgrep"):
    return subprocess.run(
        [
            sys.executable,
            "-B",
            str(REPORTER),
            "--scanner",
            scanner,
            "--input",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def run_json(tmp_path, report):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return run_reporter(path)


def assert_error(result):
    assert result.returncode == 2
    assert "ERROR:" in result.stderr
    assert "Status:   PASSED" not in result.stdout
    assert "Status:   BLOCKED" not in result.stdout
    assert "Traceback" not in result.stderr


def test_valid_clean_report(tmp_path, report):
    result = run_json(tmp_path, report)
    assert result.returncode == 0
    assert "Status:   PASSED" in result.stdout
    assert "Findings: 0" in result.stdout
    assert not result.stderr


def test_high_likelihood_finding_blocks(tmp_path, report, finding):
    finding["extra"]["metadata"]["likelihood"] = "HIGH"
    report["results"] = [finding]

    result = run_json(tmp_path, report)

    assert result.returncode == 1
    assert "Status:   BLOCKED" in result.stdout
    assert "Blocking: 1" in result.stdout
    assert "Likelihood:  HIGH" in result.stdout
    assert "Pipeline Decision: BLOCK" in result.stdout
    assert not result.stderr

@pytest.mark.parametrize("likelihood", ["MEDIUM", "LOW"])
def test_lower_likelihood_finding_reports_without_blocking(
    tmp_path, report, finding, likelihood
):
    finding["extra"]["metadata"]["likelihood"] = likelihood
    report["results"] = [finding]

    result = run_json(tmp_path, report)

    assert result.returncode == 0
    assert "Status:   PASSED" in result.stdout
    assert "Findings: 1" in result.stdout
    assert "Blocking: 0" in result.stdout
    assert f"Likelihood:  {likelihood}" in result.stdout
    assert "Pipeline Decision: REPORT" in result.stdout
    assert not result.stderr

def test_mixed_findings_block_when_any_finding_is_high_likelihood(
    tmp_path, report, finding
):
    high_finding = finding.copy()
    high_finding["extra"] = {
        **finding["extra"],
        "metadata": {"likelihood": "HIGH"},
    }
    high_finding["check_id"] = "test.high-risk-rule"

    medium_finding = finding.copy()
    medium_finding["extra"] = {
        **finding["extra"],
        "metadata": {"likelihood": "MEDIUM"},
    }
    medium_finding["check_id"] = "test.medium-risk-rule"

    report["results"] = [high_finding, medium_finding]

    result = run_json(tmp_path, report)

    assert result.returncode == 1
    assert "Status:   BLOCKED" in result.stdout
    assert "Findings: 2" in result.stdout
    assert "Blocking: 1" in result.stdout
    assert "test.high-risk-rule" in result.stdout
    assert "test.medium-risk-rule" in result.stdout
    assert not result.stderr

@pytest.mark.parametrize("field", ["results", "errors", "version", "paths"])
def test_missing_required_field(tmp_path, report, field):
    del report[field]
    assert_error(run_json(tmp_path, report))


@pytest.mark.parametrize("field,value", [
    ("results", None), ("results", {}), ("errors", None), ("errors", {}),
    ("version", ""), ("version", 123), ("paths", None), ("paths", {}),
    ("paths", {"scanned": []}), ("paths", {"scanned": "application/app.py"}),
    ("paths", {"scanned": [None]}), ("paths", {"scanned": [""]}),
])
def test_invalid_required_structure(tmp_path, report, field, value):
    report[field] = value
    assert_error(run_json(tmp_path, report))


@pytest.mark.parametrize("report", [None, [], "not a report", {}])
def test_invalid_report_root(tmp_path, report):
    assert_error(run_json(tmp_path, report))


@pytest.mark.parametrize("with_finding", [False, True])
@pytest.mark.parametrize("error_type", ["PartialParsing", "Timeout", "FatalError"])
def test_scanner_errors_take_precedence(tmp_path, report, finding, with_finding, error_type):
    report["errors"] = [{"type": error_type, "message": "Scan incomplete"}]
    if with_finding:
        report["results"] = [finding]
    assert_error(run_json(tmp_path, report))


@pytest.mark.parametrize("invalid_finding", [None, {}, {"extra": None}])
def test_invalid_findings(tmp_path, report, invalid_finding):
    report["results"] = [invalid_finding]
    assert_error(run_json(tmp_path, report))


@pytest.mark.parametrize("field,value", [
    ("check_id", None), ("path", ""), ("start", {"line": True}),
    ("start", {"line": 0}), ("extra", None),
    ("extra", {"severity": "ERROR", "message": "test", "metadata": None}),
    ("extra", {"severity": "ERROR", "message": "test", "metadata": {"cwe": [123]}}),
])
def test_invalid_finding_fields(tmp_path, report, finding, field, value):
    finding[field] = value
    report["results"] = [finding]
    assert_error(run_json(tmp_path, report))


def test_malformed_json(tmp_path):
    path = tmp_path / "report.json"
    path.write_text('{"results": [', encoding="utf-8")
    assert_error(run_reporter(path))


def test_missing_input_file(tmp_path):
    assert_error(run_reporter(tmp_path / "missing.json"))


def test_invalid_encoding(tmp_path):
    path = tmp_path / "report.json"
    path.write_bytes(b"\xff")
    assert_error(run_reporter(path))


def test_unreadable_report_path(tmp_path):
    assert_error(run_reporter(tmp_path))


def test_unexpected_processing_error(monkeypatch, capsys, report):
    monkeypatch.setattr(sys, "argv", [str(REPORTER), "--scanner", "semgrep", "--input", "unused"])
    monkeypatch.setattr(security_report, "load_json", lambda path: report)

    def broken_normalizer(report):
        raise RuntimeError("Unexpected processing failure")

    monkeypatch.setattr(security_report, "normalize_semgrep", broken_normalizer)
    with pytest.raises(SystemExit) as error:
        security_report.main()
    assert error.value.code == 2
    output = capsys.readouterr()
    assert "Unexpected processing failure" in output.err
    assert "PASSED" not in output.out

def test_trivy_critical_severity_blocks():
    assert security_report.determine_trivy_pipeline_decision(
        "CRITICAL"
    ) == "BLOCK"


def test_trivy_high_severity_reports():
    assert security_report.determine_trivy_pipeline_decision(
        "HIGH"
    ) == "REPORT"


def test_trivy_medium_severity_reports():
    assert security_report.determine_trivy_pipeline_decision(
        "MEDIUM"
    ) == "REPORT"


def test_trivy_low_severity_reports():
    assert security_report.determine_trivy_pipeline_decision(
        "LOW"
    ) == "REPORT"

def test_container_high_with_fix_blocks():
    assert security_report.determine_container_pipeline_decision(
        "HIGH",
        "2.0.0",
    ) == "BLOCK"


def test_container_high_without_fix_reports():
    assert security_report.determine_container_pipeline_decision(
        "HIGH",
        "",
    ) == "REPORT"


def test_container_critical_with_fix_blocks():
    assert security_report.determine_container_pipeline_decision(
        "CRITICAL",
        "2.0.0",
    ) == "BLOCK"


def test_container_critical_without_fix_blocks():
    assert security_report.determine_container_pipeline_decision(
        "CRITICAL",
        "",
    ) == "BLOCK"


def test_trivy_policy_differs_between_dependency_and_container_controls():
    severity = "HIGH"
    fixed_version = "2.0.0"

    assert security_report.determine_trivy_pipeline_decision(
        severity
    ) == "REPORT"

    assert security_report.determine_container_pipeline_decision(
        severity,
        fixed_version,
    ) == "BLOCK"
def test_normalize_trivy_applies_sc05_container_policy():
    report = {
        "SchemaVersion": 2,
        "Trivy": {
            "Version": "0.74.0"
        },
        "Results": [
            {
                "Target": "devsecops-secure-pipeline:test",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-TEST-0001",
                        "PkgName": "example-package",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "2.0.0",
                        "Severity": "HIGH",
                        "Title": "Test container vulnerability",
                    }
                ],
            }
        ],
    }

    findings = security_report.normalize_trivy(
        report,
        control_id="SC-05",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding["scanner"] == "Trivy"
    assert finding["control_id"] == "SC-05"
    assert finding["rule_id"] == "CVE-TEST-0001"
    assert finding["severity"] == "HIGH"
    assert finding["fixed_version"] == "2.0.0"
    assert finding["pipeline_decision"] == "BLOCK"

def test_trivy_malformed_report_returns_error(tmp_path):
    report_path = tmp_path / "trivy-invalid.json"

    report_path.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Trivy": {},
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Type": "pip",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-TEST-0001",
                                "PkgName": "example-package",
                                "InstalledVersion": "1.0.0",
                                # Severity intentionally missing
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_reporter(report_path, scanner="trivy")

    assert result.returncode == 2
    assert "ERROR" in result.stderr
    assert "Severity" in result.stderr

def test_trivy_clean_report_returns_success(tmp_path):
    report_path = tmp_path / "trivy-clean.json"

    report_path.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Trivy": {
                    "Version": "0.74.0"
                },
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Type": "pip",
                        "Packages": [
                            {
                                "Name": "Flask",
                                "Version": "3.1.3"
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_reporter(report_path, scanner="trivy")

    assert result.returncode == 0
    assert "Status:   PASSED" in result.stdout
    assert "Findings: 0" in result.stdout
    assert result.stderr == ""

def test_validate_checkov_accepts_valid_failed_check():
    report = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_24",
                    "check_name": "Ensure SSH is not open to the public",
                    "file_path": "/network.tf",
                    "resource": "aws_security_group.eks_admin",
                    "check_result": {
                        "result": "FAILED",
                        "evaluated_keys": ["ingress/[0]/cidr_blocks"],
                    },
                }
            ],
            "skipped_checks": [],
            "parsing_errors": [],
        },
    }

    validate_checkov(report)

def test_validate_checkov_rejects_parsing_errors():
    report = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [],
            "skipped_checks": [],
            "parsing_errors": ["Unable to parse network.tf"],
        },
    }

    with pytest.raises(
        ValueError,
        match="Checkov reported Terraform parsing errors",
    ):
        validate_checkov(report)

def test_validate_checkov_rejects_failed_check_without_resource():
    report = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_24",
                    "check_name": "Ensure SSH is not open to the public",
                    "file_path": "/network.tf",
                    "check_result": {"result": "FAILED"},
                }
            ],
            "skipped_checks": [],
            "parsing_errors": [],
        },
    }

    with pytest.raises(
        ValueError,
        match="Checkov failed check requires a nonempty resource",
    ):
        validate_checkov(report)

def test_checkov_public_ssh_blocks():
    assert determine_checkov_pipeline_decision("CKV_AWS_24") == "BLOCK"


def test_checkov_missing_description_reports():
    assert determine_checkov_pipeline_decision("CKV_AWS_23") == "REPORT"


def test_checkov_unknown_control_requires_review():
    with pytest.raises(
        ValueError,
        match="unclassified control CKV_AWS_999",
    ):
        determine_checkov_pipeline_decision("CKV_AWS_999")

def test_normalize_checkov_public_ssh_blocks():
    report = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_24",
                    "check_name": "Ensure SSH is not open to the public",
                    "file_path": "/network.tf",
                    "resource": "aws_security_group.eks_admin",
                    "check_result": {"result": "FAILED"},
                    "severity": "HIGH",
                }
            ],
            "skipped_checks": [],
            "parsing_errors": [],
        },
    }

    findings = normalize_checkov(report)

    assert len(findings) == 1
    assert findings[0]["scanner"] == "Checkov"
    assert findings[0]["control_id"] == "SC-04"
    assert findings[0]["rule_id"] == "CKV_AWS_24"
    assert findings[0]["resource"] == "aws_security_group.eks_admin"
    assert findings[0]["pipeline_decision"] == "BLOCK"

def test_normalize_checkov_missing_description_reports():
    report = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_23",
                    "check_name": "Ensure every security group has a description",
                    "file_path": "/network.tf",
                    "resource": "aws_security_group.eks_admin",
                    "check_result": {"result": "FAILED"},
                    "severity": None,
                }
            ],
            "skipped_checks": [],
            "parsing_errors": [],
        },
    }

    findings = normalize_checkov(report)

    assert findings[0]["pipeline_decision"] == "REPORT"
    assert findings[0]["severity"] == "UNSPECIFIED"

def test_normalize_checkov_unknown_control_explains_finding():
    report = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_999",
                    "check_name": "Ensure example infrastructure is protected",
                    "file_path": "/example.tf",
                    "resource": "aws_example.test",
                    "check_result": {"result": "FAILED"},
                }
            ],
            "skipped_checks": [],
            "parsing_errors": [],
        },
    }

    with pytest.raises(ValueError) as error:
        normalize_checkov(report)

    message = str(error.value)

    assert "CKV_AWS_999" in message
    assert "Ensure example infrastructure is protected" in message
    assert "aws_example.test" in message
    assert "/example.tf" in message
    assert "classify the control as BLOCK or REPORT" in message

def test_checkov_unattached_security_group_reports():
    assert determine_checkov_pipeline_decision("CKV2_AWS_5") == "REPORT"