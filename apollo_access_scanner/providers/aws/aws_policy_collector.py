"""AWS policy collector for all resource-based services."""

from typing import TYPE_CHECKING, Any, Callable, Dict, List

from boto3 import Session
from botocore.exceptions import ClientError

from apollo_access_scanner.core.reporting import ComplianceFinding, make_compliance_finding
from apollo_access_scanner.providers.aws.resources.iam_policy_analyzer import IAMPolicyAnalyzer

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient
    from mypy_boto3_glue import GlueClient
    from mypy_boto3_lambda import LambdaClient
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sqs import SQSClient


class AWSPolicyCollector:
    """Collects and analyzes resource-based policies from AWS services."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.service_collectors: Dict[str, Callable[[str], List[Dict[str, Any]]]] = {
            "s3": self._collect_s3,
            "dynamodb": self._collect_dynamodb,
            "glue": self._collect_glue,
            "lambda": self._collect_lambda,
            "sns": self._collect_sns,
            "sqs": self._collect_sqs,
        }

    def scan_all_policies(self, account_id: str) -> List[ComplianceFinding]:
        """Scan all AWS resource policies and return ComplianceFinding objects."""
        findings: List[ComplianceFinding] = []
        analyzer = IAMPolicyAnalyzer(account_id)

        for service_name, collector_func in self.service_collectors.items():
            try:
                policies = collector_func(account_id)
                for policy_data in policies:
                    findings.extend(
                        analyzer.analyze_policy(
                            policy_data["policy"],
                            policy_data["resource_name"],
                            policy_data["resource_id"],
                        )
                    )
            except ClientError as exc:
                findings.append(
                    make_compliance_finding(
                        resource_name=f"AWS Service: {service_name}",
                        resource_id=f"aws:{service_name}",
                        issue_type="Scan Error",
                        severity="High",
                        description=f"AWS API error scanning '{service_name}': {exc}",
                        recommendation="Verify the scanning role has the required read permissions for this service",
                    )
                )
            except Exception as exc:
                findings.append(
                    make_compliance_finding(
                        resource_name=f"AWS Service: {service_name}",
                        resource_id=f"aws:{service_name}",
                        issue_type="Scan Error",
                        severity="High",
                        description=f"Unexpected error scanning '{service_name}': {exc}",
                        recommendation="Check network connectivity and service availability",
                    )
                )

        return findings

    def _collect_s3(self, account_id: str) -> List[Dict[str, Any]]:
        policies: List[Dict[str, Any]] = []
        s3: "S3Client" = self.session.client("s3")
        for bucket in s3.list_buckets()["Buckets"]:
            bucket_name: str = bucket["Name"]
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
                policies.append(
                    {
                        "resource_name": bucket_name,
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "policy": policy,
                    }
                )
            except ClientError:
                pass  # bucket has no resource policy
        return policies

    def _collect_dynamodb(self, account_id: str) -> List[Dict[str, Any]]:
        policies: List[Dict[str, Any]] = []
        dynamodb: "DynamoDBClient" = self.session.client("dynamodb")
        for page in dynamodb.get_paginator("list_tables").paginate():
            for table_name in page["TableNames"]:
                try:
                    table_arn = dynamodb.describe_table(TableName=table_name)["Table"]["TableArn"]
                    policy = dynamodb.get_resource_policy(ResourceArn=table_arn)["Policy"]
                    policies.append(
                        {
                            "resource_name": table_name,
                            "resource_id": table_arn,
                            "policy": policy,
                        }
                    )
                except ClientError:
                    pass  # table has no resource policy
        return policies

    def _collect_glue(self, account_id: str) -> List[Dict[str, Any]]:
        policies: List[Dict[str, Any]] = []
        glue: "GlueClient" = self.session.client("glue")
        region: str = self.session.region_name or "us-east-1"

        try:
            policy = glue.get_resource_policy()["PolicyInJson"]
            policies.append(
                {
                    "resource_name": "Glue Data Catalog",
                    "resource_id": f"arn:aws:glue:{region}:{account_id}:catalog",
                    "policy": policy,
                }
            )
        except ClientError:
            pass

        for page in glue.get_paginator("get_databases").paginate():
            for db in page["DatabaseList"]:
                db_name: str = db["Name"]
                db_arn = f"arn:aws:glue:{region}:{account_id}:database/{db_name}"
                try:
                    db_policy = glue.get_resource_policy(ResourceArn=db_arn)["PolicyInJson"]
                    policies.append({"resource_name": db_name, "resource_id": db_arn, "policy": db_policy})
                except ClientError:
                    pass  # database has no resource policy

        return policies

    def _collect_lambda(self, account_id: str) -> List[Dict[str, Any]]:
        policies: List[Dict[str, Any]] = []
        lambda_client: "LambdaClient" = self.session.client("lambda")
        for page in lambda_client.get_paginator("list_functions").paginate():
            for func in page["Functions"]:
                try:
                    policy = lambda_client.get_policy(FunctionName=func["FunctionName"])["Policy"]
                    policies.append(
                        {
                            "resource_name": func["FunctionName"],
                            "resource_id": func["FunctionArn"],
                            "policy": policy,
                        }
                    )
                except ClientError:
                    pass  # function has no resource-based policy
        return policies

    def _collect_sns(self, account_id: str) -> List[Dict[str, Any]]:
        policies: List[Dict[str, Any]] = []
        sns: "SNSClient" = self.session.client("sns")
        for page in sns.get_paginator("list_topics").paginate():
            for topic in page["Topics"]:
                topic_arn: str = topic["TopicArn"]
                try:
                    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
                    if "Policy" in attrs:
                        policies.append(
                            {
                                "resource_name": topic_arn.split(":")[-1],
                                "resource_id": topic_arn,
                                "policy": attrs["Policy"],
                            }
                        )
                except ClientError:
                    pass  # topic not accessible
        return policies

    def _collect_sqs(self, account_id: str) -> List[Dict[str, Any]]:
        policies: List[Dict[str, Any]] = []
        sqs: "SQSClient" = self.session.client("sqs")
        for queue_url in sqs.list_queues().get("QueueUrls", []):
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=["Policy", "QueueArn"],
                )["Attributes"]
                if "Policy" in attrs:
                    policies.append(
                        {
                            "resource_name": queue_url.split("/")[-1],
                            "resource_id": attrs.get("QueueArn", queue_url),
                            "policy": attrs["Policy"],
                        }
                    )
            except ClientError:
                pass  # queue not accessible
        return policies
