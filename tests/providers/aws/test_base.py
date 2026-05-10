"""Tests for AWSServiceBase."""

from unittest.mock import Mock, patch

import boto3
import pytest

from apollo_access_scanner.providers.aws.resources.base import AWSServiceBase
from apollo_access_scanner.types.credentials import AWSCreds


@pytest.fixture
def mock_session():
    return Mock(spec=boto3.Session)


@pytest.fixture
def service(mock_session):
    return AWSServiceBase(mock_session)


def test_init_sets_session(service, mock_session):
    assert service.session is mock_session


@patch("boto3.Session")
def test_from_creds_with_profile(mock_session_cls):
    creds = AWSCreds(profile="test-profile")
    AWSServiceBase.from_creds(creds)
    mock_session_cls.assert_called_once_with(profile_name="test-profile")


@patch("boto3.Session")
def test_from_creds_with_keys(mock_session_cls):
    creds = AWSCreds(access_key="AKIA123", secret_key="secret", region="us-west-2")
    AWSServiceBase.from_creds(creds)
    mock_session_cls.assert_called_once_with(
        aws_access_key_id="AKIA123",
        aws_secret_access_key="secret",
        region_name="us-west-2",
    )


@patch("boto3.Session")
def test_from_creds_default_region(mock_session_cls):
    creds = AWSCreds(access_key="AKIA123", secret_key="secret")
    AWSServiceBase.from_creds(creds)
    mock_session_cls.assert_called_once_with(
        aws_access_key_id="AKIA123",
        aws_secret_access_key="secret",
        region_name="us-east-1",
    )


def test_get_account_id(service, mock_session):
    mock_sts = Mock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_session.client.return_value = mock_sts

    assert service.get_account_id() == "123456789012"
    mock_session.client.assert_called_once_with("sts")
