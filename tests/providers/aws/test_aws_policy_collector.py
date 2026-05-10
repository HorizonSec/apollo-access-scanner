"""Tests for AWSPolicyCollector — focuses on error path coverage."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from apollo_access_scanner.providers.aws.aws_policy_collector import AWSPolicyCollector


def _client_error(code: str = "AccessDenied") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "Access Denied"}}, "operation")


@pytest.fixture
def mock_session():
    return MagicMock()


@pytest.fixture
def collector(mock_session):
    return AWSPolicyCollector(mock_session)


class TestScanAllPoliciesErrorHandling:
    def test_client_error_emits_scan_error_finding(self, collector, mock_session):
        mock_session.client.return_value.list_buckets.side_effect = _client_error()

        with patch.object(collector, "service_collectors", {"s3": collector._collect_s3}):
            findings = collector.scan_all_policies("123456789012")

        assert len(findings) == 1
        assert findings[0].finding_info.types == ["Scan Error"]
        assert "s3" in findings[0].finding_info.desc

    def test_unexpected_error_emits_scan_error_finding(self, collector, mock_session):
        mock_session.client.return_value.list_buckets.side_effect = RuntimeError("network timeout")

        with patch.object(collector, "service_collectors", {"s3": collector._collect_s3}):
            findings = collector.scan_all_policies("123456789012")

        assert len(findings) == 1
        assert findings[0].finding_info.types == ["Scan Error"]
        assert "s3" in findings[0].finding_info.desc

    def test_error_in_one_service_does_not_block_others(self, collector, mock_session):
        s3_client = MagicMock()
        s3_client.list_buckets.side_effect = _client_error()

        sqs_client = MagicMock()
        sqs_client.list_queues.return_value = {"QueueUrls": []}

        mock_session.client.side_effect = lambda svc, **kw: s3_client if svc == "s3" else sqs_client

        with patch.object(
            collector,
            "service_collectors",
            {"s3": collector._collect_s3, "sqs": collector._collect_sqs},
        ):
            findings = collector.scan_all_policies("123456789012")

        # one error finding for s3, zero findings for sqs (no queues)
        assert len(findings) == 1
        assert "s3" in findings[0].finding_info.desc


class TestCollectS3:
    def test_skips_buckets_without_policy(self, collector, mock_session):
        s3 = mock_session.client.return_value
        s3.list_buckets.return_value = {"Buckets": [{"Name": "my-bucket"}]}
        s3.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy")

        result = collector._collect_s3("123456789012")
        assert result == []

    def test_collects_bucket_with_policy(self, collector, mock_session):
        policy_doc = '{"Statement": []}'
        s3 = mock_session.client.return_value
        s3.list_buckets.return_value = {"Buckets": [{"Name": "my-bucket"}]}
        s3.get_bucket_policy.return_value = {"Policy": policy_doc}

        result = collector._collect_s3("123456789012")
        assert len(result) == 1
        assert result[0]["resource_name"] == "my-bucket"
        assert result[0]["policy"] == policy_doc

    def test_list_buckets_error_bubbles_up(self, collector, mock_session):
        mock_session.client.return_value.list_buckets.side_effect = _client_error()
        with pytest.raises(ClientError):
            collector._collect_s3("123456789012")
