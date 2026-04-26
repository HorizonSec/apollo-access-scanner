"""GCP provider implementation (stub — scanning not yet implemented)."""

import typer

from apollo_access_scanner.types.base import CloudProviderBase
from apollo_access_scanner.types.credentials import GCPCreds


class GCPProvider(CloudProviderBase):
    """GCP cloud provider — credential prompting only; scanning coming soon."""

    name = "GCP"
    description = "Google Cloud Platform"

    def prompt_creds(self) -> GCPCreds:
        creds_path: str = typer.prompt(
            "Enter path to GCP service account JSON file (leave blank to paste JSON)",
            default="",
            show_default=False,
        )
        if creds_path:
            return GCPCreds(creds_path=creds_path)

        creds_json: str = typer.prompt("Paste your GCP service account JSON")
        return GCPCreds(creds_json=creds_json)
