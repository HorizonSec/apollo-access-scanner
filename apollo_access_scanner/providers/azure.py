"""Azure provider implementation (stub — scanning not yet implemented)."""

import typer

from apollo_access_scanner.types.base import CloudProviderBase
from apollo_access_scanner.types.credentials import AzureCreds


class AzureProvider(CloudProviderBase):
    """Azure cloud provider — credential prompting only; scanning coming soon."""

    name = "Azure"
    description = "Microsoft Azure"

    def prompt_creds(self) -> AzureCreds:
        creds_path: str = typer.prompt(
            "Enter path to Azure credentials file (leave blank to enter manually)",
            default="",
            show_default=False,
        )
        if creds_path:
            return AzureCreds(creds_path=creds_path)

        client_id: str = typer.prompt("Enter Azure Client ID")
        secret: str = typer.prompt("Enter Azure Client Secret", hide_input=True)
        tenant_id: str = typer.prompt("Enter Azure Tenant ID")
        subscription_id: str = typer.prompt("Enter Azure Subscription ID")

        return AzureCreds(
            client_id=client_id,
            secret=secret,
            tenant_id=tenant_id,
            subscription_id=subscription_id,
        )
