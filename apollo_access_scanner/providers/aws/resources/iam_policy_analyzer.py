"""Unified IAM policy analyzer for AWS resource and identity policies."""

import json
from typing import Any, Dict, List, Union

from apollo_access_scanner.core.reporting import ComplianceFinding, make_compliance_finding


class IAMPolicyAnalyzer:
    """Unified analyzer for IAM policy structures (resource and identity policies)."""

    def __init__(self, account_id: str) -> None:
        self.account_id = account_id

    def analyze_policy(
        self,
        policy_data: Union[str, dict],
        resource_name: str,
        resource_id: str,
    ) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []

        try:
            policy = json.loads(policy_data) if isinstance(policy_data, str) else policy_data
            statements = policy.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]
            for statement in statements:
                findings.extend(self._analyze_statement(statement, resource_name, resource_id))
        except (json.JSONDecodeError, TypeError):
            findings.append(
                make_compliance_finding(
                    resource_name=resource_name,
                    resource_id=resource_id,
                    issue_type="Policy Parse Error",
                    severity="High",
                    description="Failed to parse policy JSON",
                    recommendation="Verify policy syntax and structure",
                )
            )

        return findings

    def _analyze_statement(
        self,
        statement: Dict[str, Any],
        resource_name: str,
        resource_id: str,
    ) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []

        if self._has_external_access(statement):
            findings.append(
                make_compliance_finding(
                    resource_name=resource_name,
                    resource_id=resource_id,
                    issue_type="External Access",
                    severity="High",
                    description="Policy allows access from external accounts",
                    recommendation="Restrict access to trusted accounts only",
                )
            )

        if self._has_public_access(statement):
            findings.append(
                make_compliance_finding(
                    resource_name=resource_name,
                    resource_id=resource_id,
                    issue_type="Public Access",
                    severity="Critical",
                    description="Policy allows public access (*)",
                    recommendation="Remove public access or add strict conditions",
                )
            )

        if self._has_overly_broad_permissions(statement):
            findings.append(
                make_compliance_finding(
                    resource_name=resource_name,
                    resource_id=resource_id,
                    issue_type="Overly Broad Access",
                    severity="Medium",
                    description="Policy uses wildcard actions or resources without conditions",
                    recommendation="Use specific actions and resources with appropriate conditions",
                )
            )

        if self._has_privilege_escalation_risk(statement):
            findings.append(
                make_compliance_finding(
                    resource_name=resource_name,
                    resource_id=resource_id,
                    issue_type="Privilege Escalation Risk",
                    severity="High",
                    description="Policy allows dangerous administrative actions",
                    recommendation="Restrict administrative permissions to specific use cases",
                )
            )

        return findings

    def _has_external_access(self, statement: Dict[str, Any]) -> bool:
        principals = statement.get("Principal", {})
        if isinstance(principals, dict):
            aws_principals = principals.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for principal in aws_principals:
                if isinstance(principal, str) and self.account_id not in principal and principal != "*":
                    return True
        return False

    def _has_public_access(self, statement: Dict[str, Any]) -> bool:
        principals = statement.get("Principal", {})
        if principals == "*":
            return True
        if isinstance(principals, dict):
            aws_principals = principals.get("AWS", [])
            if aws_principals == "*" or (isinstance(aws_principals, list) and "*" in aws_principals):
                return True
        return False

    def _has_overly_broad_permissions(self, statement: Dict[str, Any]) -> bool:
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        conditions = statement.get("Condition", {})
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        has_wildcard_action = any("*" in action for action in actions)
        has_wildcard_resource = any("*" in resource for resource in resources)
        return (has_wildcard_action or has_wildcard_resource) and not conditions

    def _has_privilege_escalation_risk(self, statement: Dict[str, Any]) -> bool:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        dangerous_actions = {
            "iam:*",
            "iam:CreateRole",
            "iam:AttachRolePolicy",
            "iam:PutRolePolicy",
            "iam:CreateUser",
            "iam:AttachUserPolicy",
            "iam:PutUserPolicy",
            "sts:AssumeRole",
            "*",
        }
        return any(action in dangerous_actions for action in actions)
