"""Tests for apollo_access_scanner package-level exports."""

import apollo_access_scanner
from apollo_access_scanner import (
    PROVIDER_CLASSES,
    ApolloScanner,
    ScanReport,
    ScanReporter,
    __version__,
)


def test_version_is_string():
    assert isinstance(__version__, str)
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


def test_scanner_import():
    from apollo_access_scanner.core.scanner import ApolloScanner as _Scanner
    assert ApolloScanner is _Scanner


def test_scan_report_import():
    from apollo_access_scanner.core.reporting import ScanReport as _SR
    assert ScanReport is _SR


def test_scan_reporter_import():
    from apollo_access_scanner.core.reporting import ScanReporter as _SRp
    assert ScanReporter is _SRp


def test_provider_classes():
    assert isinstance(PROVIDER_CLASSES, dict)
    assert set(PROVIDER_CLASSES.keys()) == {"AWS", "GCP", "Azure"}


def test_all_exports_accessible():
    for name in apollo_access_scanner.__all__:
        assert hasattr(apollo_access_scanner, name)
