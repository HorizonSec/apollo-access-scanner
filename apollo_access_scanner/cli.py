"""Apollo Access Scanner CLI — powered by horizon-core CLIWrapper."""

from typing import Optional

import typer

from apollo_access_scanner.__about__ import __version__
from apollo_access_scanner.core.scanner import ApolloScanner
from horizon_core import create_cli

cli_wrapper = create_cli(
    app_name="Apollo",
    app_description="Access & IAM Security Scanner",
    version=__version__,
)


def _run_interactive_scan() -> None:
    """Run a guided cloud provider scan."""
    scanner = ApolloScanner()
    scanner.run_interactive_scan()


cli_wrapper.register_interactive_command("scan", _run_interactive_scan)


@cli_wrapper.add_command
def scan(
    provider: str = typer.Option(..., help="Cloud provider to scan (AWS, GCP, Azure)"),
    profile: Optional[str] = typer.Option(None, help="AWS profile name"),
    access_key: Optional[str] = typer.Option(None, help="AWS Access Key ID"),
    secret_key: Optional[str] = typer.Option(None, help="AWS Secret Access Key"),
    region: Optional[str] = typer.Option(None, help="AWS region"),
    creds_path: Optional[str] = typer.Option(None, help="Path to credentials file (GCP/Azure)"),
    creds_json: Optional[str] = typer.Option(None, help="GCP credentials JSON string"),
    client_id: Optional[str] = typer.Option(None, help="Azure Client ID"),
    secret: Optional[str] = typer.Option(None, help="Azure Client Secret"),
    tenant_id: Optional[str] = typer.Option(None, help="Azure Tenant ID"),
    subscription_id: Optional[str] = typer.Option(None, help="Azure Subscription ID"),
    output_dir: str = typer.Option("./reports", help="Output directory for scan reports"),
) -> None:
    """Run a single provider scan with supplied credentials."""
    scanner = ApolloScanner(output_dir=output_dir)
    scanner.run_single_provider(
        provider,
        profile=profile,
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        creds_path=creds_path,
        creds_json=creds_json,
        client_id=client_id,
        secret=secret,
        tenant_id=tenant_id,
        subscription_id=subscription_id,
    )


def main() -> None:
    cli_wrapper.run()


if __name__ == "__main__":
    main()
