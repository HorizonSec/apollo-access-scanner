"""Tests for apollo_access_scanner.core.reporting."""

from datetime import datetime

from horizon_core.reporting.models.ocsf import ActivityID, SeverityID

from apollo_access_scanner.core.reporting import (
    ScanReport,
    ScanReporter,
    make_compliance_finding,
)


def _make_finding(severity="High"):
    return make_compliance_finding(
        resource_name="test-resource",
        resource_id="arn:aws:iam::123:policy/Test",
        issue_type="Excessive Permissions",
        severity=severity,
        description="Test description",
        recommendation="Test recommendation",
    )


class TestMakeComplianceFinding:
    def test_returns_compliance_finding(self):
        finding = _make_finding()
        from horizon_core.reporting.models.ocsf import ComplianceFinding
        assert isinstance(finding, ComplianceFinding)

    def test_severity_mapping_critical(self):
        finding = make_compliance_finding("r", "id", "t", "Critical", "d", "rec")
        assert finding.severity_id == SeverityID.CRITICAL

    def test_severity_mapping_high(self):
        assert _make_finding("High").severity_id == SeverityID.HIGH

    def test_severity_mapping_medium(self):
        assert _make_finding("Medium").severity_id == SeverityID.MEDIUM

    def test_severity_mapping_low(self):
        assert _make_finding("Low").severity_id == SeverityID.LOW

    def test_unknown_severity_falls_back(self):
        finding = make_compliance_finding("r", "id", "t", "BOGUS", "d", "rec")
        assert finding.severity_id == SeverityID.UNKNOWN

    def test_finding_info_fields(self):
        finding = make_compliance_finding(
            resource_name="my-bucket",
            resource_id="arn:aws:s3:::my-bucket",
            issue_type="Public Access",
            severity="Critical",
            description="Public S3 bucket",
            recommendation="Remove public access",
        )
        assert finding.finding_info.uid == "arn:aws:s3:::my-bucket"
        assert finding.finding_info.title == "my-bucket"
        assert finding.finding_info.desc == "Public S3 bucket"
        assert finding.finding_info.remediation == "Remove public access"
        assert "Public Access" in finding.finding_info.types

    def test_activity_id_is_create(self):
        assert _make_finding().activity_id == ActivityID.CREATE

    def test_type_uid_is_compliance_finding_create(self):
        assert _make_finding().type_uid == 200301

    def test_metadata_version(self):
        assert _make_finding().metadata.version == "1.3.0"


class TestScanReport:
    def test_issues_found_counts_findings(self):
        findings = [_make_finding(), _make_finding()]
        report = ScanReport(
            provider="AWS",
            account_id="123456789012",
            findings=findings,
            scan_time=datetime.utcnow(),
        )
        assert report.issues_found == 2

    def test_issues_found_empty(self):
        report = ScanReport(
            provider="AWS",
            account_id="123456789012",
            findings=[],
            scan_time=datetime.utcnow(),
        )
        assert report.issues_found == 0


class TestScanReporter:
    def test_add_report_increments_list(self):
        reporter = ScanReporter()
        report = ScanReport(
            provider="AWS",
            account_id="123456789012",
            findings=[_make_finding()],
            scan_time=datetime.utcnow(),
            report_path="",
        )
        reporter.add_report(report)
        assert len(reporter.reports) == 1

    def test_render_does_not_raise(self, capsys):
        reporter = ScanReporter()
        report = ScanReport(
            provider="AWS",
            account_id="123456789012",
            findings=[_make_finding()],
            scan_time=datetime.utcnow(),
            report_path="",
        )
        reporter.add_report(report)
        reporter.render()  # should not raise
