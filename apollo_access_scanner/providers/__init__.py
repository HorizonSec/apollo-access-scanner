"""Cloud provider implementations."""

from typing import Dict, Type

from apollo_access_scanner.providers.aws.aws_provider import AWSProvider
from apollo_access_scanner.providers.azure import AzureProvider
from apollo_access_scanner.providers.gcp import GCPProvider
from apollo_access_scanner.types.base import CloudProviderBase

PROVIDER_CLASSES: Dict[str, Type[CloudProviderBase]] = {
    "AWS": AWSProvider,
    "GCP": GCPProvider,
    "Azure": AzureProvider,
}

__all__ = [
    "CloudProviderBase",
    "AWSProvider",
    "GCPProvider",
    "AzureProvider",
    "PROVIDER_CLASSES",
]
