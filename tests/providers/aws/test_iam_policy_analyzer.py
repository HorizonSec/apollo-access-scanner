"""Tests for IAMPolicyAnalyzer."""

import json

import pytest

from apollo_access_scanner.core.reporting import ComplianceFinding
from apollo_access_scanner.providers.aws.resources.iam_policy_analyzer import IAMPolicyAnalyzer


ACCOUNT_ID = "123456789012"


@pytest.fixture
def analyzer():
    return IAMPolicyAnalyzer(ACCOUNT_ID)


def _policy(statement):
    return json.dumps({"Statement": [statement]})


class TestAnalyzePolicy:
    def test_public_access_detected(self, analyzer):
        policy = _policy({"Principal": "*", "Action": "s3:GetObject", "Resource": "*"})
        findings = analyzer.analyze_policy(policy, "my-bucket", "arn:aws:s3:::my-bucket")
        types = [f.finding_info.types[0] for f in findings]
        assert "Public Access" in types

    def test_external_access_detected(self, analyzer):
        policy = _policy({"Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "s3:*", "Resource": "*"})
        findings = analyzer.analyze_policy(policy, "bucket", "arn:aws:s3:::bucket")
        types = [f.finding_info.types[0] for f in findings]
        assert "External Access" in types

    def test_internal_account_not_flagged_as_external(self, analyzer):
        policy = _policy({"Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}, "Action": "s3:*", "Resource": "*"})
        findings = analyzer.analyze_policy(policy, "bucket", "arn:aws:s3:::bucket")
        types = [f.finding_info.types[0] for f in findings]
        assert "External Access" not in types

    def test_overly_broad_detected(self, analyzer):
        policy = _policy({"Action": "s3:*", "Resource": "*"})
        findings = analyzer.analyze_policy(policy, "bucket", "arn")
        types = [f.finding_info.types[0] for f in findings]
        assert "Overly Broad Access" in types

    def test_privilege_escalation_detected(self, analyzer):
        policy = _policy({"Action": "iam:CreateRole", "Resource": "arn:aws:iam::123:role/test"})
        findings = analyzer.analyze_policy(policy, "policy", "arn")
        types = [f.finding_info.types[0] for f in findings]
        assert "Privilege Escalation Risk" in types

    def test_invalid_json_returns_parse_error_finding(self, analyzer):
        findings = analyzer.analyze_policy("not-valid-json", "r", "id")
        assert len(findings) == 1
        assert findings[0].finding_info.types == ["Policy Parse Error"]

    def test_dict_policy_accepted(self, analyzer):
        policy = {"Statement": [{"Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/key"}]}
        findings = analyzer.analyze_policy(policy, "bucket", "arn")
        assert isinstance(findings, list)

    def test_all_findings_are_compliance_findings(self, analyzer):
        policy = _policy({"Principal": "*", "Action": "*", "Resource": "*"})
        findings = analyzer.analyze_policy(policy, "r", "id")
        assert all(isinstance(f, ComplianceFinding) for f in findings)
