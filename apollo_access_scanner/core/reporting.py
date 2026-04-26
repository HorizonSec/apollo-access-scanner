"""Scan reporting — replaces lock-and-key's ScanResult/ScanSummary with OCSF ComplianceFinding."""

import dataclasses
import json
import os
from datetime import datetime
from enum import Enum
from typing import Any, List

from horizon_core.reporting.models.ocsf import (
    ActivityID,
    ComplianceFinding,
    FindingInfo,
    Metadata,
    SeverityID,
)
from rich.console import Console
from rich.table import Table

_METADATA = Metadata(
    version="1.3.0",
    product={"name": "Apollo Access Scanner", "version": "1.0.0"},
)

_SEVERITY_MAP = {
    "Critical": SeverityID.CRITICAL,
    "High": SeverityID.HIGH,
    "Medium": SeverityID.MEDIUM,
    "Low": SeverityID.LOW,
}


def make_compliance_finding(
    resource_name: str,
    resource_id: str,
    issue_type: str,
    severity: str,
    description: str,
    recommendation: str,
) -> ComplianceFinding:
    """Build a ComplianceFinding from flat IAM finding fields."""
    now = datetime.utcnow()
    return ComplianceFinding(
        metadata=_METADATA,
        severity_id=_SEVERITY_MAP.get(severity, SeverityID.UNKNOWN),
        time=now,
        type_uid=200301,  # Compliance Finding Create
        activity_id=ActivityID.CREATE,
        finding_info=FindingInfo(
            uid=resource_id,
            title=resource_name,
            desc=description,
            types=[issue_type],
            remediation=recommendation,
            created_time=now,
            data_sources=["Apollo Access Scanner"],
        ),
    )


class _FindingEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)


def _serialize_finding(finding: ComplianceFinding) -> dict:
    raw = dataclasses.asdict(finding)
    return json.loads(json.dumps(raw, cls=_FindingEncoder))


@dataclasses.dataclass
class ScanReport:
    """Aggregated result for a single cloud provider scan."""

    provider: str
    account_id: str
    findings: List[ComplianceFinding]
    scan_time: datetime
    report_path: str = ""
    error: str = ""

    @property
    def issues_found(self) -> int:
        return len(self.findings)


class ScanReporter:
    """Collects ScanReports, saves JSON files, and renders summary tables."""

    def __init__(self) -> None:
        self.reports: List[ScanReport] = []
        self.console = Console()

    def add_report(self, report: ScanReport) -> None:
        self.reports.append(report)
        self._save_report(report)

    def _save_report(self, report: ScanReport) -> None:
        if not report.report_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(report.report_path)), exist_ok=True)
        payload = {
            "provider": report.provider,
            "account_id": report.account_id,
            "scan_time": report.scan_time.isoformat(),
            "issues_found": report.issues_found,
            "findings": [_serialize_finding(f) for f in report.findings],
        }
        with open(report.report_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    def render(self) -> None:
        table = Table(title="Apollo Access Scanner — Scan Summary")
        table.add_column("Provider", style="cyan", no_wrap=True)
        table.add_column("Account ID", style="magenta")
        table.add_column("Issues Found", style="red")
        table.add_column("Report Path", style="blue")

        for report in self.reports:
            table.add_row(
                report.provider,
                report.account_id,
                str(report.issues_found),
                report.report_path or "—",
            )
        self.console.print(table)

        for report in self.reports:
            if report.error:
                self.console.print(f"[bold red]Error ({report.provider}):[/bold red] {report.error}")
