"""Tests for AzureProvider."""

from unittest.mock import patch

import pytest

from apollo_access_scanner.core.reporting import ScanReport
from apollo_access_scanner.providers.azure import AzureProvider
from apollo_access_scanner.types.base import CloudProviderBase
from apollo_access_scanner.types.credentials import AzureCreds


@pytest.fixture
def provider():
    return AzureProvider()


def test_inherits_from_base(provider):
    assert isinstance(provider, CloudProviderBase)


def test_class_attributes(provider):
    assert provider.name == "Azure"
    assert provider.description == "Microsoft Azure"


@patch("apollo_access_scanner.providers.azure.typer.prompt", return_value="/path/to/creds.json")
def test_prompt_creds_with_file_path(mock_prompt, provider):
    creds = provider.prompt_creds()
    assert isinstance(creds, AzureCreds)
    assert creds.creds_path == "/path/to/creds.json"
    assert creds.client_id is None
    assert mock_prompt.call_count == 1


@patch(
    "apollo_access_scanner.providers.azure.typer.prompt",
    side_effect=["", "client-id", "secret", "tenant-id", "sub-id"],
)
def test_prompt_creds_with_manual_values(mock_prompt, provider):
    creds = provider.prompt_creds()
    assert isinstance(creds, AzureCreds)
    assert creds.creds_path is None
    assert creds.client_id == "client-id"
    assert creds.secret == "secret"
    assert creds.tenant_id == "tenant-id"
    assert creds.subscription_id == "sub-id"
    assert mock_prompt.call_count == 5


@patch(
    "apollo_access_scanner.providers.azure.typer.prompt",
    side_effect=["", "c", "s", "t", "sub"],
)
def test_prompt_creds_secret_is_hidden(mock_prompt, provider):
    provider.prompt_creds()
    secret_call = mock_prompt.call_args_list[2]
    assert secret_call[1].get("hide_input") is True


@patch(
    "apollo_access_scanner.providers.azure.typer.prompt",
    side_effect=["", "c", "s", "t", "sub"],
)
def test_prompt_creds_texts(mock_prompt, provider):
    provider.prompt_creds()
    prompts = [call[0][0] for call in mock_prompt.call_args_list[1:]]
    assert "Azure Client ID" in prompts[0]
    assert "Azure Client Secret" in prompts[1]
    assert "Azure Tenant ID" in prompts[2]
    assert "Azure Subscription ID" in prompts[3]


def test_run_analysis_returns_scan_report(provider):
    creds = AzureCreds(client_id="test-id")
    result = provider.run_analysis(creds)
    assert isinstance(result, ScanReport)
    assert result.provider == "Azure"
