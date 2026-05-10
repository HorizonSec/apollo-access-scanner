"""AWS provider implementation."""

from datetime import datetime

import typer
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from apollo_access_scanner.core.reporting import ScanReport, make_compliance_finding
from apollo_access_scanner.providers.aws.aws_policy_collector import AWSPolicyCollector
from apollo_access_scanner.providers.aws.resources.iam import IAMService
from apollo_access_scanner.types.base import CloudProviderBase
from apollo_access_scanner.types.credentials import AWSCreds


class AWSProvider(CloudProviderBase):
    """AWS cloud provider implementation."""

    name = "AWS"
    description = "Amazon Web Services"

    def prompt_creds(self) -> AWSCreds:
        profile: str = typer.prompt(
            "Enter AWS profile name (leave blank to enter keys)",
            default="",
            show_default=False,
        )
        if profile:
            return AWSCreds(profile=profile)

        access_key: str = typer.prompt("Enter AWS Access Key ID")
        secret_key: str = typer.prompt("Enter AWS Secret Access Key", hide_input=True)
        region: str = typer.prompt("Enter AWS Region", default="us-east-1")

        return AWSCreds(access_key=access_key, secret_key=secret_key, region=region)

    def run_analysis(self, creds: AWSCreds, output_dir: str = "./reports") -> ScanReport:
        try:
            iam_service = IAMService.from_creds(creds)
            collector = AWSPolicyCollector(iam_service.session)
            account_id = iam_service.get_account_id()

            all_findings = []
            all_findings.extend(iam_service.scan_policies_detailed(account_id))
            all_findings.extend(collector.scan_all_policies(account_id))

            return ScanReport(
                provider=self.name,
                account_id=account_id,
                findings=all_findings,
                scan_time=datetime.utcnow(),
                report_path=f"{output_dir}/aws_report_{account_id}.json",
            )

        except NoCredentialsError as e:
            error_msg = f"No AWS credentials found: {e}. Configure credentials via profile, env vars, or IAM role."
            recommendation = "Configure AWS credentials via profile, environment variables, or IAM role"
        except ClientError as e:
            error_msg = f"AWS API error: {e}"
            recommendation = "Verify credentials and IAM permissions"
        except BotoCoreError as e:
            sso_hint = " If your profile uses SSO, run 'aws sso login' first." if "login" in str(e).lower() else ""
            error_msg = f"AWS credential error: {e}{sso_hint}"
            recommendation = "Verify credentials and IAM permissions"

        error_finding = make_compliance_finding(
            resource_name="AWS Account",
            resource_id="unknown",
            issue_type="Scan Error",
            severity="High",
            description=error_msg,
            recommendation=recommendation,
        )
        return ScanReport(
            provider=self.name,
            account_id="unknown",
            findings=[error_finding],
            scan_time=datetime.utcnow(),
            report_path="",
            error=error_msg,
        )
