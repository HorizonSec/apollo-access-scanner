"""Tests for apollo_access_scanner.core.scanner."""

from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from apollo_access_scanner.core.reporting import ScanReport
from apollo_access_scanner.core.scanner import ApolloScanner
from apollo_access_scanner.types.credentials import AWSCreds, AzureCreds, GCPCreds


@pytest.fixture
def scanner():
    return ApolloScanner()


def _dummy_report(provider="AWS"):
    return ScanReport(
        provider=provider,
        account_id="123456789012",
        findings=[],
        scan_time=datetime.utcnow(),
        report_path="/tmp/test_report.json",
    )


class TestApolloScannerInit:
    def test_has_providers(self, scanner):
        assert scanner.providers

    def test_has_reporter(self, scanner):
        assert scanner.reporter is not None

    def test_default_output_dir(self, scanner):
        assert scanner.output_dir == "./reports"

    def test_custom_output_dir(self):
        s = ApolloScanner(output_dir="/tmp/reports")
        assert s.output_dir == "/tmp/reports"


class TestBuildCredentials:
    def test_aws_credentials(self, scanner):
        creds = scanner._build_credentials(
            "AWS",
            profile="test-profile",
            access_key="key",
            secret_key="secret",
            region="us-east-1",
        )
        assert isinstance(creds, AWSCreds)
        assert creds.profile == "test-profile"
        assert creds.access_key == "key"
        assert creds.secret_key == "secret"
        assert creds.region == "us-east-1"

    def test_gcp_credentials(self, scanner):
        creds = scanner._build_credentials(
            "GCP",
            creds_path="/path/to/creds.json",
            creds_json='{"type":"service_account"}',
        )
        assert isinstance(creds, GCPCreds)
        assert creds.creds_path == "/path/to/creds.json"

    def test_azure_credentials(self, scanner):
        creds = scanner._build_credentials(
            "Azure",
            client_id="client",
            secret="sec",
            tenant_id="tenant",
            subscription_id="sub",
        )
        assert isinstance(creds, AzureCreds)
        assert creds.client_id == "client"
        assert creds.tenant_id == "tenant"

    def test_invalid_provider_returns_none(self, scanner):
        assert scanner._build_credentials("BOGUS") is None


class TestRunSingleProvider:
    @patch("apollo_access_scanner.core.scanner.typer.confirm", return_value=False)
    def test_unknown_provider_prints_error(self, mock_confirm, scanner, capsys):
        scanner.run_single_provider("BOGUS")
        # Should not raise, and confirm should never be called
        mock_confirm.assert_not_called()

    @patch("apollo_access_scanner.core.scanner.typer.confirm", return_value=False)
    def test_scan_cancelled_when_not_confirmed(self, mock_confirm, scanner):
        mock_provider_cls = Mock()
        mock_provider = Mock()
        mock_provider_cls.return_value = mock_provider
        mock_provider_cls.description = "Test"

        with patch.dict(scanner.providers, {"AWS": mock_provider_cls}):
            scanner._build_credentials = Mock(return_value=AWSCreds(profile="test"))
            scanner.run_single_provider("AWS", profile="test")

        mock_provider.run_analysis.assert_not_called()

    @patch("apollo_access_scanner.core.scanner.typer.confirm", return_value=True)
    def test_run_single_provider_calls_analysis(self, mock_confirm, scanner):
        mock_provider_cls = Mock()
        mock_provider = Mock()
        mock_provider_cls.return_value = mock_provider
        mock_provider_cls.description = "Amazon Web Services"
        mock_provider.run_analysis.return_value = _dummy_report("AWS")

        with patch.dict(scanner.providers, {"AWS": mock_provider_cls}):
            scanner._build_credentials = Mock(return_value=AWSCreds(profile="test"))
            scanner.run_single_provider("AWS", profile="test")

        mock_provider.run_analysis.assert_called_once()

    @patch("apollo_access_scanner.core.scanner.typer.confirm")
    def test_yes_flag_skips_confirmation(self, mock_confirm, scanner):
        mock_provider_cls = Mock()
        mock_provider = Mock()
        mock_provider_cls.return_value = mock_provider
        mock_provider_cls.description = "Amazon Web Services"
        mock_provider.run_analysis.return_value = _dummy_report("AWS")

        with patch.dict(scanner.providers, {"AWS": mock_provider_cls}):
            scanner._build_credentials = Mock(return_value=AWSCreds(profile="test"))
            scanner.run_single_provider("AWS", yes=True, profile="test")

        mock_confirm.assert_not_called()
        mock_provider.run_analysis.assert_called_once()


class TestSelectCloudProvider:
    @patch("apollo_access_scanner.core.scanner.typer.prompt", return_value=1)
    def test_valid_selection(self, mock_prompt, scanner):
        result = scanner.select_cloud_provider()
        assert result in scanner.providers

    @patch("apollo_access_scanner.core.scanner.typer.prompt", return_value=999)
    def test_invalid_selection_returns_none(self, mock_prompt, scanner):
        assert scanner.select_cloud_provider() is None
