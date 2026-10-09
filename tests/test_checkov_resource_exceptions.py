import pytest

from scripts.security_report import determine_checkov_pipeline_decision


@pytest.mark.parametrize(
    "check_id",
    [
        "CKV_AWS_109",
        "CKV_AWS_111",
        "CKV_AWS_356",
    ],
)
def test_approved_kms_resource_reports(check_id):
    decision = determine_checkov_pipeline_decision(
        check_id,
        "aws_iam_policy_document.security_alerts_kms",
    )

    assert decision == "REPORT"


@pytest.mark.parametrize(
    "check_id",
    [
        "CKV_AWS_109",
        "CKV_AWS_111",
        "CKV_AWS_356",
    ],
)
def test_unapproved_iam_resource_fails_closed(check_id):
    with pytest.raises(ValueError, match="unclassified control"):
        determine_checkov_pipeline_decision(
            check_id,
            "aws_iam_policy_document.unapproved_policy",
        )