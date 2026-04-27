"""Tests for AWSProvider."""

from unittest.mock import patch

import pytest

from apollo_access_scanner.core.reporting import ScanReport
from apollo_access_scanner.providers.aws.aws_provider import AWSProvider
from apollo_access_scanner.types.base import CloudProviderBase
from apollo_access_scanner.types.credentials import AWSCreds


@pytest.fixture
def provider():
    return AWSProvider()


def test_inherits_from_base(provider):
    assert isinstance(provider, CloudProviderBase)


def test_class_attributes(provider):
    assert provider.name == "AWS"
    assert provider.description == "Amazon Web Services"


@patch("apollo_access_scanner.providers.aws.aws_provider.typer.prompt", return_value="test-profile")
def test_prompt_creds_with_profile(mock_prompt, provider):
    creds = provider.prompt_creds()
    assert isinstance(creds, AWSCreds)
    assert creds.profile == "test-profile"
    assert creds.access_key is None
    assert mock_prompt.call_count == 1


@patch(
    "apollo_access_scanner.providers.aws.aws_provider.typer.prompt",
    side_effect=["", "AKIATEST", "secret-key", "us-west-2"],
)
def test_prompt_creds_with_keys(mock_prompt, provider):
    creds = provider.prompt_creds()
    assert isinstance(creds, AWSCreds)
    assert creds.profile is None
    assert creds.access_key == "AKIATEST"
    assert creds.secret_key == "secret-key"
    assert creds.region == "us-west-2"
    assert mock_prompt.call_count == 4


@patch(
    "apollo_access_scanner.providers.aws.aws_provider.typer.prompt",
    side_effect=["", "AKIATEST", "secret", "us-east-1"],
)
def test_prompt_creds_default_region(mock_prompt, provider):
    creds = provider.prompt_creds()
    assert creds.region == "us-east-1"
    region_call = mock_prompt.call_args_list[3]
    assert region_call[1].get("default") == "us-east-1"


@patch(
    "apollo_access_scanner.providers.aws.aws_provider.typer.prompt",
    side_effect=["", "AKIATEST", "secret", "us-east-1"],
)
def test_prompt_creds_secret_is_hidden(mock_prompt, provider):
    provider.prompt_creds()
    secret_call = mock_prompt.call_args_list[2]
    assert secret_call[1].get("hide_input") is True


@patch("apollo_access_scanner.providers.aws.aws_policy_collector.AWSPolicyCollector.scan_all_policies", return_value=[])
@patch("apollo_access_scanner.providers.aws.resources.iam.IAMService.from_creds")
def test_run_analysis_success(mock_from_creds, mock_scan_all, provider):
    mock_iam = mock_from_creds.return_value
    mock_iam.get_account_id.return_value = "123456789012"
    mock_iam.scan_policies_detailed.return_value = []

    result = provider.run_analysis(AWSCreds(profile="test"), output_dir="./test_reports")

    assert isinstance(result, ScanReport)
    assert result.provider == "AWS"
    assert result.account_id == "123456789012"
    assert result.issues_found == 0
    assert "aws_report" in result.report_path


@patch("apollo_access_scanner.providers.aws.resources.iam.IAMService.from_creds")
def test_run_analysis_credential_error_returns_report(mock_from_creds, provider):
    from botocore.exceptions import NoCredentialsError

    mock_from_creds.side_effect = NoCredentialsError()

    result = provider.run_analysis(AWSCreds(profile="bad"))
    assert isinstance(result, ScanReport)
    assert result.account_id == "unknown"
    assert result.issues_found == 1  # error finding
