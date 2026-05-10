"""Tests for IAMService."""

from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from apollo_access_scanner.core.reporting import ComplianceFinding
from apollo_access_scanner.providers.aws.resources.iam import IAMService


@pytest.fixture
def mock_session():
    return Mock()


@pytest.fixture
def service(mock_session):
    return IAMService(mock_session)


def _client_error(operation="ListPolicies"):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, operation)


class TestScanPolicies:
    def test_detects_admin_permissions(self, service, mock_session):
        mock_iam = Mock()
        mock_iam.get_paginator.return_value.paginate.return_value = [
            {
                "Policies": [
                    {"PolicyName": "TestPolicy", "Arn": "arn:aws:iam::123:policy/Test", "DefaultVersionId": "v1"}
                ]
            }
        ]
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {"Document": {"Statement": [{"Action": "*", "Resource": "*"}]}}
        }
        mock_session.client.return_value = mock_iam

        issues = service.scan_policies("123456789012")
        assert any("Administrative permissions" in i for i in issues)

    def test_handles_client_error_on_list(self, service, mock_session):
        mock_iam = Mock()
        mock_iam.get_paginator.side_effect = _client_error()
        mock_session.client.return_value = mock_iam

        issues = service.scan_policies("123456789012")
        assert len(issues) == 1
        assert "Failed to list customer managed policies" in issues[0]


class TestScanPoliciesDetailed:
    def test_returns_compliance_findings(self, service, mock_session):
        mock_iam = Mock()
        mock_iam.get_paginator.return_value.paginate.return_value = [
            {
                "Policies": [
                    {"PolicyName": "TestPolicy", "Arn": "arn:aws:iam::123:policy/Test", "DefaultVersionId": "v1"}
                ]
            }
        ]
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {"Document": {"Statement": [{"Action": "*", "Resource": "*"}]}}
        }
        mock_session.client.return_value = mock_iam

        findings = service.scan_policies_detailed("123456789012")
        assert all(isinstance(f, ComplianceFinding) for f in findings)
        assert len(findings) > 0

    def test_access_error_on_list_returns_finding(self, service, mock_session):
        mock_iam = Mock()
        mock_iam.get_paginator.side_effect = _client_error()
        mock_session.client.return_value = mock_iam

        findings = service.scan_policies_detailed("123456789012")
        assert len(findings) == 1
        assert findings[0].finding_info.types == ["Access Error"]


class TestDetectionHelpers:
    def test_has_admin_permissions_wildcard(self, service):
        assert service._has_admin_permissions({"Action": "*"})

    def test_has_admin_permissions_star_colon_star(self, service):
        assert service._has_admin_permissions({"Action": ["s3:Get", "*:*"]})

    def test_has_admin_permissions_normal_action(self, service):
        assert not service._has_admin_permissions({"Action": "s3:GetObject"})

    def test_has_wildcard_resources(self, service):
        assert service._has_wildcard_resources({"Resource": "*"})
        assert service._has_wildcard_resources({"Resource": ["arn:aws:s3:::bucket/*", "*"]})
        assert not service._has_wildcard_resources({"Resource": "arn:aws:s3:::bucket/key"})

    def test_has_privilege_escalation_risk(self, service):
        assert service._has_privilege_escalation_risk({"Action": "iam:CreateRole"})
        assert service._has_privilege_escalation_risk({"Action": ["s3:Get", "iam:AttachRolePolicy"]})
        assert not service._has_privilege_escalation_risk({"Action": "s3:GetObject"})
