"""Cloud provider implementations."""

from typing import Dict, Type

from apollo_access_scanner.providers.aws.aws_provider import AWSProvider
from apollo_access_scanner.types.base import CloudProviderBase

PROVIDER_CLASSES: Dict[str, Type[CloudProviderBase]] = {
    "AWS": AWSProvider,
}

__all__ = [
    "CloudProviderBase",
    "AWSProvider",
    "PROVIDER_CLASSES",
]
