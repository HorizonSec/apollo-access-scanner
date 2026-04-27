"""Core scanner orchestration."""

from typing import Any, Optional, Union

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from apollo_access_scanner.core.reporting import ScanReporter
from apollo_access_scanner.providers import PROVIDER_CLASSES
from apollo_access_scanner.types.credentials import AWSCreds, AzureCreds, GCPCreds


class ApolloScanner:
    """Orchestrates cloud provider scans and aggregates results."""

    def __init__(self, output_dir: str = "./reports") -> None:
        self.providers = PROVIDER_CLASSES
        self.reporter = ScanReporter()
        self.console = Console()
        self.output_dir = output_dir

    def select_cloud_provider(self) -> Optional[str]:
        """Prompt user to select a cloud provider by number."""
        provider_names = list(self.providers.keys())
        for idx, name in enumerate(provider_names, 1):
            self.console.print(f"[cyan]{idx}.[/cyan] {name} ({self.providers[name].description})")

        choice = typer.prompt("Select a provider by number", type=int)
        if 1 <= choice <= len(provider_names):
            return str(provider_names[choice - 1])
        return None

    def run_interactive_scan(self) -> None:
        """Run a single guided scan — called by the CLIWrapper interactive menu."""
        provider_name = self.select_cloud_provider()
        if not provider_name:
            self.console.print("[red]Invalid selection.[/red]")
            return

        provider_cls = self.providers[provider_name]
        provider = provider_cls()
        creds = provider.prompt_creds()

        if not typer.confirm(f"Proceed with {provider_name} scan?", default=True):
            self.console.print("[yellow]Scan cancelled.[/yellow]")
            return

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console
        ) as progress:
            task = progress.add_task(f"Scanning {provider_name}...", total=None)
            report = provider.run_analysis(creds, output_dir=self.output_dir)
            progress.update(task, completed=True)

        self.reporter.add_report(report)
        self.reporter.render()

    def run_single_provider(self, provider_name: str, **kwargs: Any) -> None:
        """Run scan for a single provider with credentials supplied as kwargs."""
        provider_cls = self.providers.get(provider_name)
        if not provider_cls:
            self.console.print(f"[red]Unknown provider: {provider_name}[/red]")
            return

        provider = provider_cls()
        creds = self._build_credentials(provider_name, **kwargs)
        if not creds:
            self.console.print("[red]Invalid credentials provided.[/red]")
            return

        if not typer.confirm(f"Proceed with {provider_name} scan?", default=True):
            self.console.print("[yellow]Scan cancelled.[/yellow]")
            return

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console
        ) as progress:
            task = progress.add_task(f"Scanning {provider_name}...", total=None)
            report = provider.run_analysis(creds, output_dir=self.output_dir)
            progress.update(task, completed=True)

        self.reporter.add_report(report)
        self.reporter.render()
        self.console.print("[bold cyan]Thank you for using Apollo Access Scanner![/bold cyan]")

    def _build_credentials(
        self,
        provider_name: str,
        **kwargs: Any,
    ) -> Union[AWSCreds, GCPCreds, AzureCreds, None]:
        if provider_name == "AWS":
            return AWSCreds(
                profile=kwargs.get("profile"),
                access_key=kwargs.get("access_key"),
                secret_key=kwargs.get("secret_key"),
                region=kwargs.get("region"),
            )
        elif provider_name == "GCP":
            return GCPCreds(
                creds_path=kwargs.get("creds_path"),
                creds_json=kwargs.get("creds_json"),
            )
        elif provider_name == "Azure":
            return AzureCreds(
                creds_path=kwargs.get("creds_path"),
                client_id=kwargs.get("client_id"),
                secret=kwargs.get("secret"),
                tenant_id=kwargs.get("tenant_id"),
                subscription_id=kwargs.get("subscription_id"),
            )
        return None
