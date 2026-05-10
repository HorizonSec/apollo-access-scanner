"""Tests for apollo_access_scanner.config.settings."""

from apollo_access_scanner.config.settings import CLOUD_PROVIDERS


def test_cloud_providers_is_dict():
    assert isinstance(CLOUD_PROVIDERS, dict)


def test_cloud_providers_keys():
    assert set(CLOUD_PROVIDERS.keys()) == {"AWS", "GCP", "Azure"}


def test_cloud_providers_values():
    assert CLOUD_PROVIDERS == {
        "AWS": "Amazon Web Services",
        "GCP": "Google Cloud Platform",
        "Azure": "Microsoft Azure",
    }


def test_cloud_providers_copy_does_not_mutate_original():
    original_count = len(CLOUD_PROVIDERS)
    copy = CLOUD_PROVIDERS.copy()
    copy["TEST"] = "Test Provider"
    assert len(CLOUD_PROVIDERS) == original_count
