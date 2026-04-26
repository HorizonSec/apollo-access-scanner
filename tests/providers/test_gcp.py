"""Tests for GCPProvider."""

from unittest.mock import patch

import pytest

from apollo_access_scanner.core.reporting import ScanReport
from apollo_access_scanner.providers.gcp import GCPProvider
from apollo_access_scanner.types.base import CloudProviderBase
from apollo_access_scanner.types.credentials import GCPCreds


@pytest.fixture
def provider():
    return GCPProvider()


def test_inherits_from_base(provider):
    assert isinstance(provider, CloudProviderBase)


def test_class_attributes(provider):
    assert provider.name == "GCP"
    assert provider.description == "Google Cloud Platform"


@patch("apollo_access_scanner.providers.gcp.typer.prompt", return_value="/path/to/sa.json")
def test_prompt_creds_with_file_path(mock_prompt, provider):
    creds = provider.prompt_creds()
    assert isinstance(creds, GCPCreds)
    assert creds.creds_path == "/path/to/sa.json"
    assert creds.creds_json is None
    assert mock_prompt.call_count == 1


@patch("apollo_access_scanner.providers.gcp.typer.prompt", side_effect=["", '{"type":"service_account"}'])
def test_prompt_creds_with_json(mock_prompt, provider):
    creds = provider.prompt_creds()
    assert isinstance(creds, GCPCreds)
    assert creds.creds_path is None
    assert creds.creds_json == '{"type":"service_account"}'
    assert mock_prompt.call_count == 2


@patch("apollo_access_scanner.providers.gcp.typer.prompt", return_value="/test/path.json")
def test_prompt_creds_first_prompt_mentions_service_account(mock_prompt, provider):
    provider.prompt_creds()
    prompt_text = mock_prompt.call_args_list[0][0][0]
    assert "GCP service account JSON file" in prompt_text
    assert "leave blank to paste JSON" in prompt_text


def test_run_analysis_returns_scan_report(provider):
    creds = GCPCreds(creds_path="/test/path.json")
    result = provider.run_analysis(creds)
    assert isinstance(result, ScanReport)
    assert result.provider == "GCP"
