"""AWS IAM policy scanner."""

from typing import TYPE_CHECKING, Any, Dict, List, cast

from botocore.exceptions import ClientError

from apollo_access_scanner.core.reporting import ComplianceFinding, make_compliance_finding
from apollo_access_scanner.providers.aws.resources.base import AWSServiceBase
from apollo_access_scanner.providers.aws.resources.iam_policy_analyzer import IAMPolicyAnalyzer

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_iam.type_defs import PolicyTypeDef
else:
    IAMClient = Any
    PolicyTypeDef = Dict[str, Any]


class IAMService(AWSServiceBase):
    """AWS IAM service for policy analysis."""

    def scan_policies(self, account_id: str) -> List[str]:
        """Scan IAM policies and return string issue descriptions."""
        issues: List[str] = []
        iam: "IAMClient" = self.session.client("iam")
        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    issues.extend(self._analyze_policy(iam, policy, account_id))
        except ClientError:
            issues.append("Failed to list customer managed policies")
        return issues

    def scan_policies_detailed(self, account_id: str) -> List[ComplianceFinding]:
        """Scan IAM policies and return OCSF ComplianceFinding objects."""
        findings: List[ComplianceFinding] = []
        iam: "IAMClient" = self.session.client("iam")
        analyzer = IAMPolicyAnalyzer(account_id)

        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    policy_arn = policy.get("Arn")
                    version_id = policy.get("DefaultVersionId")
                    if not policy_arn or not version_id:
                        continue
                    try:
                        response = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                        policy_doc = cast(Dict[str, Any], response["PolicyVersion"]["Document"])
                        findings.extend(
                            analyzer.analyze_policy(
                                policy_doc,
                                policy.get("PolicyName", "MISSING"),
                                policy_arn,
                            )
                        )
                    except ClientError:
                        findings.append(
                            make_compliance_finding(
                                resource_name=policy.get("PolicyName", "MISSING"),
                                resource_id=policy_arn,
                                issue_type="Access Error",
                                severity="Low",
                                description="Failed to retrieve policy document",
                                recommendation="Ensure IAM permissions allow policy document access",
                            )
                        )
        except ClientError:
            findings.append(
                make_compliance_finding(
                    resource_name="IAM Policies",
                    resource_id="N/A",
                    issue_type="Access Error",
                    severity="Medium",
                    description="Failed to list customer managed policies",
                    recommendation="Ensure IAM permissions allow policy listing",
                )
            )

        return findings

    def _analyze_policy(self, iam: Any, policy: "PolicyTypeDef", account_id: str) -> List[str]:
        issues: List[str] = []
        policy_name = policy.get("PolicyName")
        try:
            response = iam.get_policy_version(
                PolicyArn=policy.get("Arn"),
                VersionId=policy.get("DefaultVersionId"),
            )
            policy_doc = response["PolicyVersion"]["Document"]
            raw_statements = policy_doc.get("Statement", [])
            statements = [raw_statements] if isinstance(raw_statements, dict) else raw_statements
            if not isinstance(statements, list):
                statements = []
            for statement in statements:
                if self._has_admin_permissions(statement):
                    issues.append(f"Policy {policy_name}: Administrative permissions (*:*) detected")
                if self._has_wildcard_resources(statement):
                    issues.append(f"Policy {policy_name}: Wildcard resources (*) detected")
                if self._has_privilege_escalation_risk(statement):
                    issues.append(f"Policy {policy_name}: Privilege escalation risk detected")
        except ClientError:
            issues.append(f"Policy {policy_name}: Failed to retrieve policy document")
        return issues

    def _has_admin_permissions(self, statement: Dict[str, Any]) -> bool:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        return "*" in actions or any("*:*" in action for action in actions)

    def _has_wildcard_resources(self, statement: Dict[str, Any]) -> bool:
        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        return "*" in resources

    def _has_privilege_escalation_risk(self, statement: Dict[str, Any]) -> bool:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        risky_actions = {
            "iam:CreateRole",
            "iam:AttachRolePolicy",
            "iam:PutRolePolicy",
            "iam:CreateUser",
            "iam:AttachUserPolicy",
            "iam:PutUserPolicy",
            "sts:AssumeRole",
        }
        return any(action in risky_actions for action in actions)
