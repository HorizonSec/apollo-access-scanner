"""Abstract base class for cloud provider implementations."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from apollo_access_scanner.core.reporting import ScanReport, make_compliance_finding


class CloudProviderBase(ABC):
    """Base class for cloud provider implementations."""

    name: str
    description: str

    @abstractmethod
    def prompt_creds(self) -> Any:
        """Prompt user for credentials."""
        pass

    def run_analysis(self, creds: Any, output_dir: str = "./reports") -> ScanReport:
        """Run security analysis — override in concrete providers."""
        placeholder = make_compliance_finding(
            resource_name=f"{self.name} (placeholder)",
            resource_id="placeholder",
            issue_type="Placeholder",
            severity="Low",
            description=f"Placeholder finding for {self.name} — scanning not yet implemented.",
            recommendation="Implement provider-specific scanning logic.",
        )
        return ScanReport(
            provider=self.name,
            account_id="unknown",
            findings=[placeholder],
            scan_time=datetime.utcnow(),
            report_path=f"{output_dir}/{self.name.lower()}_report.json",
        )
