"""Tests for apollo_access_scanner.cli."""

from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

from apollo_access_scanner.cli import cli_wrapper


@pytest.fixture
def runner():
    return CliRunner()


def test_cli_help(runner):
    result = runner.invoke(cli_wrapper.app, ["--help"])
    assert result.exit_code == 0


def test_version_command(runner):
    result = runner.invoke(cli_wrapper.app, ["version"])
    assert result.exit_code == 0


def test_scan_command_missing_provider(runner):
    result = runner.invoke(cli_wrapper.app, ["scan"])
    assert result.exit_code != 0


@patch("apollo_access_scanner.cli.ApolloScanner")
def test_scan_command_aws_profile(mock_scanner_cls, runner):
    mock_scanner = Mock()
    mock_scanner_cls.return_value = mock_scanner

    result = runner.invoke(cli_wrapper.app, ["scan", "--provider", "AWS", "--profile", "test-profile"])

    assert result.exit_code == 0
    mock_scanner_cls.assert_called_once()
    mock_scanner.run_single_provider.assert_called_once_with(
        "AWS",
        yes=False,
        profile="test-profile",
        access_key=None,
        secret_key=None,
        region=None,
        creds_path=None,
        creds_json=None,
        client_id=None,
        secret=None,
        tenant_id=None,
        subscription_id=None,
    )


@patch("apollo_access_scanner.cli.ApolloScanner")
def test_scan_command_passes_output_dir(mock_scanner_cls, runner):
    mock_scanner = Mock()
    mock_scanner_cls.return_value = mock_scanner

    runner.invoke(cli_wrapper.app, ["scan", "--provider", "AWS", "--profile", "p", "--output-dir", "/tmp/out"])

    mock_scanner_cls.assert_called_once_with(output_dir="/tmp/out")
