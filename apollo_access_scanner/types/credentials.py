"""Credential models for cloud providers."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class AWSCreds:
    """AWS credentials configuration."""

    profile: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    region: Optional[str] = None


@dataclass
class GCPCreds:
    """GCP credentials configuration."""

    creds_path: Optional[str] = None
    creds_json: Optional[str] = None


@dataclass
class AzureCreds:
    """Azure credentials configuration."""

    creds_path: Optional[str] = None
    client_id: Optional[str] = None
    secret: Optional[str] = None
    tenant_id: Optional[str] = None
    subscription_id: Optional[str] = None
