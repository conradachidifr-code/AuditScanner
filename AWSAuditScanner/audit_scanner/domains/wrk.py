"""WRK domain — workload controls."""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "WRK-02": "P0",
    "WRK-03": "P0",
    "WRK-04": "P0",
    "WRK-05": "P0",
    "WRK-06": "P0",
    "WRK-07": "P1",
    "WRK-08": "P0",
    "WRK-09": "P0",
    "WRK-10": "P0",
    "WRK-11": "P2",
    "WRK-12": "P2",
    "WRK-13": "P0",
    "WRK-14": "P0",
    "WRK-15": "P1",
    "WRK-16": "P0",
    "WRK-17": "P0",
    "WRK-18": "P0",
    "WRK-19": "P0",
    "WRK-20": "P0",
    "WRK-21": "P0",
    "WRK-22": "P0",
    "WRK-23": "P0",
    "WRK-24": "P0",
    "WRK-25": "P2",
    "WRK-26": "P0",
}

WRK_EOL_RUNTIMES = {"nodejs12.x", "nodejs10.x", "nodejs8.10", "python2.7", "ruby2.5"}


def _wrk_tagged_resource_summary(ctx: CheckContext) -> dict[str, Any] | None:
    resources: list[dict[str, Any]] = []
    pagination_token: str | None = None

    while True:
        arguments = ["resourcegroupstaggingapi", "get-resources"]
        if pagination_token:
            arguments.extend(["--pagination-token", pagination_token])
        data = ctx.invoke_aws_cli(arguments)
        if data is None:
            return None

        if has_property(data, "ResourceTagMappingList"):
            resources.extend(cli_array(data.get("ResourceTagMappingList")))

        pagination_token = None
        if has_property(data, "PaginationToken"):
            token = str(data.get("PaginationToken") or "").strip()
            if token:
                pagination_token = token
        if not pagination_token:
            break

    service_types: dict[str, int] = {}
    for resource in resources:
        arn = str(property_value(resource, ["ResourceARN"]) or "")
        match = re.search(r"arn:aws:([^:]+):", arn)
        if not match:
            continue
        service = match.group(1)
        service_types[service] = service_types.get(service, 0) + 1

    return {
        "resource_count": collection_count(resources),
        "service_types": service_types,
    }


def _wrk_ssm_string_parameter_count(ctx: CheckContext) -> int | None:
    data = ctx.invoke_aws_cli(["ssm", "describe-parameters"])
    if data is None:
        return None

    string_count = 0
    if has_property(data, "Parameters"):
        for parameter in cli_array(data.get("Parameters")):
            parameter_type = str(property_value(parameter, ["Type"]) or "")
            if parameter_type.lower() == "string":
                string_count += 1
    return string_count


def _wrk_active_access_key_count(ctx: CheckContext) -> int | None:
    user_data = ctx.invoke_aws_cli(["iam", "list-users", "--max-items", "1000"])
    if user_data is None:
        return None

    active_key_count = 0
    if has_property(user_data, "Users"):
        for user in cli_array(user_data.get("Users")):
            user_name = str(property_value(user, ["UserName"]) or "")
            key_data = ctx.invoke_aws_cli(["iam", "list-access-keys", "--user-name", user_name])
            if key_data is None or not has_property(key_data, "AccessKeyMetadata"):
                continue

            for key in cli_array(key_data.get("AccessKeyMetadata")):
                status = str(property_value(key, ["Status"]) or "")
                if status.lower() == "active":
                    active_key_count += 1
    return active_key_count


def _wrk_policy_allows_public_principal(policy_text: str) -> bool:
    if not policy_text or not policy_text.strip():
        return False
    return bool(
        re.search(r'"Principal"\s*:\s*"\*"', policy_text, re.IGNORECASE)
        and re.search(r'"Effect"\s*:\s*"Allow"', policy_text, re.IGNORECASE)
    )


def _wrk_lambda_functions(ctx: CheckContext) -> list[dict[str, Any]] | None:
    functions: list[dict[str, Any]] = []
    marker: str | None = None

    while True:
        arguments = ["lambda", "list-functions", "--max-items", "1000"]
        if marker:
            arguments.extend(["--marker", marker])
        data = ctx.invoke_aws_cli(arguments)
        if data is None:
            return None

        if has_property(data, "Functions"):
            functions.extend(cli_array(data.get("Functions")))

        marker = None
        if has_property(data, "NextMarker"):
            next_marker = str(data.get("NextMarker") or "").strip()
            if next_marker:
                marker = next_marker
        if not marker:
            break

    return functions


def _parse_lambda_last_modified(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(cid: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, cid, notes)

        return _check

    def wrk02(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        summary = _wrk_tagged_resource_summary(ctx)
        if summary is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-02")
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-02",
            "PARTIAL",
            {
                "resource_count": summary["resource_count"],
                "service_types": summary["service_types"],
            },
            "Inventory completeness depends on tagging compliance.",
        )

    checks["WRK-02"] = wrk02

    def wrk03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["iam", "list-roles", "--max-items", "1000"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-03")

        workload_roles: list[str] = []
        role_count = 0
        if has_property(data, "Roles"):
            roles = cli_array(data.get("Roles"))
            role_count = collection_count(roles)
            for role in roles:
                role_name = str(property_value(role, ["RoleName"]) or "")
                if re.search(r"workload|app|svc|service|lambda|ecs|eks", role_name, re.IGNORECASE):
                    if collection_count(workload_roles) < 10:
                        workload_roles.append(role_name)

        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-03",
            "PARTIAL",
            {
                "role_count": role_count,
                "workload_roles": workload_roles,
            },
            "Verify each Lambda, ECS task, EC2 instance profile is dedicated.",
        )

    checks["WRK-03"] = wrk03

    def wrk04(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        string_count = _wrk_ssm_string_parameter_count(ctx)
        key_count = _wrk_active_access_key_count(ctx)

        if string_count is None and key_count is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-04")

        if string_count is None:
            string_count = 0
        if key_count is None:
            key_count = 0

        evidence = {
            "ssm_string_parameter_count": string_count,
            "active_access_key_count": key_count,
        }
        if string_count > 0 or key_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-04",
                "FAIL",
                evidence,
                "String SSM parameters or service account access keys exist",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-04",
            "PASS",
            evidence,
            "No String SSM parameters or active access keys found",
        )

    checks["WRK-04"] = wrk04

    def wrk05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        rds_data = ctx.invoke_aws_cli(["rds", "describe-db-instances"])
        if rds_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-05")

        public_db_count = 0
        private_db_count = 0
        public_dbs: list[str] = []
        if has_property(rds_data, "DBInstances"):
            for instance in cli_array(rds_data.get("DBInstances")):
                is_public = bool(property_value(instance, ["PubliclyAccessible"]) is True)
                if is_public:
                    public_db_count += 1
                    if collection_count(public_dbs) < 5:
                        public_dbs.append(str(property_value(instance, ["DBInstanceIdentifier"]) or ""))
                else:
                    private_db_count += 1

        open_search_public_count = 0
        domain_data = ctx.invoke_aws_cli(["opensearch", "list-domain-names"])
        if domain_data and has_property(domain_data, "DomainNames"):
            for domain_entry in cli_array(domain_data.get("DomainNames")):
                domain_name = str(property_value(domain_entry, ["DomainName"]) or "")
                describe_data = ctx.invoke_aws_cli(
                    ["opensearch", "describe-domain", "--domain-name", domain_name]
                )
                if describe_data is None or not has_property(describe_data, "DomainStatus"):
                    continue
                domain_status = property_value(describe_data, ["DomainStatus"])
                vpc_options = property_value(domain_status, ["VPCOptions"])
                if not vpc_options or not has_property(vpc_options, "SubnetIds"):
                    open_search_public_count += 1

        evidence = {
            "public_rds_count": public_db_count,
            "private_rds_count": private_db_count,
            "public_rds_instances": public_dbs,
            "public_opensearch_count": open_search_public_count,
        }
        if public_db_count > 0 or open_search_public_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-05",
                "FAIL",
                evidence,
                "Publicly accessible managed data services found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-05",
            "PASS",
            evidence,
            "No publicly accessible databases detected",
        )

    checks["WRK-05"] = wrk05

    def wrk06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        functions = _wrk_lambda_functions(ctx)
        if functions is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-06")
        if collection_count(functions) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-06",
                "PARTIAL",
                {"lambda_count": 0},
                "No Lambda functions found in region",
            )

        with_vpc = 0
        without_vpc = 0
        for function in functions:
            function_name = str(property_value(function, ["FunctionName"]) or "")
            config_data = ctx.invoke_aws_cli(
                ["lambda", "get-function-configuration", "--function-name", function_name]
            )
            has_vpc = False
            if config_data:
                vpc_config = property_value(config_data, ["VpcConfig"])
                subnet_ids = property_value(vpc_config, ["SubnetIds"]) if vpc_config else None
                if collection_count(subnet_ids) > 0:
                    has_vpc = True
            if has_vpc:
                with_vpc += 1
            else:
                without_vpc += 1

        evidence = {
            "lambda_count": collection_count(functions),
            "with_vpc_count": with_vpc,
            "without_vpc_count": without_vpc,
        }
        if with_vpc > 0 and without_vpc == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-06",
                "PASS",
                evidence,
                "All Lambda functions use VPC configuration",
            )
        if with_vpc > 0 and without_vpc > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-06",
                "PARTIAL",
                evidence,
                "Some Lambda functions lack VPC configuration",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-06",
            "PARTIAL",
            evidence,
            "No Lambda functions configured with VPC access",
        )

    checks["WRK-06"] = wrk06
    checks["WRK-07"] = workshop("WRK-07", "Verify IAM role policies for workloads follow least privilege.")
    checks["WRK-08"] = workshop(
        "WRK-08", "Verify Macie active for workload S3 buckets. Link to DET-16/17."
    )

    def wrk09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["cloudwatch", "describe-alarms"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-09")

        all_alarms: list[dict[str, Any]] = []
        if has_property(data, "MetricAlarms"):
            all_alarms = cli_array(data.get("MetricAlarms"))

        matching_alarms: list[str] = []
        for alarm in all_alarms:
            alarm_name = str(property_value(alarm, ["AlarmName"]) or "")
            metric_name = str(property_value(alarm, ["MetricName"]) or "")
            namespace = str(property_value(alarm, ["Namespace"]) or "")
            combined = f"{alarm_name} {metric_name} {namespace}"
            if re.search(r"Error|Errors|Failed|Failure|Lambda|ECS|EKS", combined, re.IGNORECASE):
                if collection_count(matching_alarms) < 10:
                    matching_alarms.append(alarm_name)

        evidence = {
            "alarm_count": collection_count(all_alarms),
            "matching_alarms": matching_alarms,
        }
        if collection_count(matching_alarms) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-09",
                "PASS",
                evidence,
                "CloudWatch alarms exist for workload error monitoring",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-09",
            "FAIL",
            evidence,
            "No workload error alarms detected",
        )

    checks["WRK-09"] = wrk09
    checks["WRK-10"] = workshop(
        "WRK-10", "Verify Lambda, ECS, EKS events flow to QRadar via EventBridge."
    )

    def wrk11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-11",
            "PARTIAL",
            None,
            "Verify service quotas and Lambda concurrency limits configured.",
        )

    checks["WRK-11"] = wrk11
    checks["WRK-12"] = workshop("WRK-12", "Verify anomaly detection for service usage.")
    checks["WRK-13"] = workshop("WRK-13", "Verify service dependency map in DAT/SIPedia.")
    checks["WRK-14"] = workshop("WRK-14", "Verify runbooks for Lambda, ECS, EKS, RDS in DEX.")

    def wrk15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        functions = _wrk_lambda_functions(ctx)
        if functions is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-15")

        stale_count = 0
        stale_functions: list[str] = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=365)

        for function in functions:
            if not has_property(function, "LastModified"):
                continue
            last_modified_value = str(property_value(function, ["LastModified"]) or "")
            parsed = _parse_lambda_last_modified(last_modified_value)
            if parsed is None:
                continue
            comparable = parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            if comparable < cutoff:
                stale_count += 1
                if collection_count(stale_functions) < 10:
                    stale_functions.append(str(property_value(function, ["FunctionName"]) or ""))

        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-15",
            "PARTIAL",
            {
                "lambda_count": collection_count(functions),
                "stale_count": stale_count,
                "stale_functions": stale_functions,
            },
            "Flag Lambdas not modified in 12+ months for review.",
        )

    checks["WRK-15"] = wrk15

    def wrk16(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        functions = _wrk_lambda_functions(ctx)
        if functions is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-16")

        runtime_summary: dict[str, int] = {}
        eol_functions: list[dict[str, str]] = []
        for function in functions:
            runtime = str(property_value(function, ["Runtime"]) or "unknown")
            runtime_summary[runtime] = runtime_summary.get(runtime, 0) + 1
            if runtime in WRK_EOL_RUNTIMES and collection_count(eol_functions) < 10:
                eol_functions.append(
                    {
                        "name": str(property_value(function, ["FunctionName"]) or ""),
                        "runtime": runtime,
                    }
                )

        evidence = {
            "function_count": collection_count(functions),
            "runtimes": runtime_summary,
            "eol_functions": eol_functions,
        }
        if collection_count(eol_functions) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-16",
                "FAIL",
                evidence,
                "Lambda functions using EOL runtimes found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-16",
            "PASS",
            evidence,
            "No EOL Lambda runtimes found",
        )

    checks["WRK-16"] = wrk16

    def wrk17(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        list_data = ctx.invoke_aws_cli(
            ["ecs", "list-task-definitions", "--status", "ACTIVE", "--max-items", "100"]
        )
        if list_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-17")

        task_defs: list[str] = []
        if has_property(list_data, "taskDefinitionArns"):
            task_defs = cli_array(list_data.get("taskDefinitionArns"))
        if collection_count(task_defs) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-17",
                "PARTIAL",
                {"task_definition_count": 0},
                "No active ECS task definitions found",
            )

        with_role = 0
        without_role = 0
        missing_role_defs: list[str] = []
        for task_def_arn in task_defs:
            describe_data = ctx.invoke_aws_cli(
                ["ecs", "describe-task-definition", "--task-definition", str(task_def_arn)]
            )
            if describe_data is None or not has_property(describe_data, "taskDefinition"):
                continue
            task_definition = property_value(describe_data, ["taskDefinition"])
            task_role_arn = str(property_value(task_definition, ["taskRoleArn"]) or "")
            if task_role_arn:
                with_role += 1
            else:
                without_role += 1
                if collection_count(missing_role_defs) < 5:
                    missing_role_defs.append(str(property_value(task_definition, ["family"]) or ""))

        evidence = {
            "task_definition_count": collection_count(task_defs),
            "with_task_role_count": with_role,
            "without_task_role_count": without_role,
            "missing_role_families": missing_role_defs,
        }
        if without_role > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-17",
                "FAIL",
                evidence,
                "ECS task definitions without TaskRoleArn found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-17",
            "PASS",
            evidence,
            "All ECS task definitions have TaskRoleArn set",
        )

    checks["WRK-17"] = wrk17

    def wrk18(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        repo_data = ctx.invoke_aws_cli(["ecr", "describe-repositories", "--max-results", "1000"])
        registry_data = ctx.invoke_aws_cli(["ecr", "describe-registry"])
        if repo_data is None and registry_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-18")

        repo_count = 0
        if repo_data and has_property(repo_data, "repositories"):
            repo_count = collection_count(cli_array(repo_data.get("repositories")))

        scan_on_push = False
        if registry_data:
            scanning_configuration = property_value(registry_data, ["scanningConfiguration"])
            if scanning_configuration and property_value(scanning_configuration, ["scanOnPush"]) is True:
                scan_on_push = True

        evidence = {
            "repository_count": repo_count,
            "scan_on_push": scan_on_push,
        }
        if repo_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-18",
                "PARTIAL",
                evidence,
                "No ECR repositories found in region",
            )
        if scan_on_push:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-18",
                "PASS",
                evidence,
                "ECR scan on push enabled at registry level",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-18",
            "FAIL",
            evidence,
            "ECR scan on push is not enabled",
        )

    checks["WRK-18"] = wrk18

    def wrk19(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        list_data = ctx.invoke_aws_cli(["eks", "list-clusters"])
        if list_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-19")

        clusters: list[str] = []
        if has_property(list_data, "clusters"):
            clusters = cli_array(list_data.get("clusters"))
        if collection_count(clusters) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-19",
                "PARTIAL",
                {"cluster_count": 0},
                "No EKS clusters found in region",
            )

        cluster_evidence: list[dict[str, Any]] = []
        failing_clusters = 0
        for cluster_name in clusters:
            describe_data = ctx.invoke_aws_cli(["eks", "describe-cluster", "--name", str(cluster_name)])
            if describe_data is None or not has_property(describe_data, "cluster"):
                continue

            cluster = property_value(describe_data, ["cluster"])
            vpc_config = property_value(cluster, ["resourcesVpcConfig"]) if cluster else None
            public_access = False
            open_public = False
            public_cidrs: list[str] = []

            if vpc_config:
                if property_value(vpc_config, ["endpointPublicAccess"]) is True:
                    public_access = True
                if has_property(vpc_config, "publicAccessCidrs"):
                    public_cidrs = [str(c) for c in cli_array(property_value(vpc_config, ["publicAccessCidrs"]))]
                    for cidr in public_cidrs:
                        if cidr == "0.0.0.0/0":
                            open_public = True

            cluster_evidence.append(
                {
                    "cluster_name": str(cluster_name),
                    "endpoint_public_access": public_access,
                    "public_access_cidrs": public_cidrs,
                }
            )
            if public_access and open_public:
                failing_clusters += 1

        evidence = {
            "cluster_count": collection_count(clusters),
            "failing_clusters": failing_clusters,
            "clusters": cluster_evidence,
        }
        if failing_clusters > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-19",
                "FAIL",
                evidence,
                "EKS cluster public endpoint allows 0.0.0.0/0",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-19",
            "PASS",
            evidence,
            "EKS cluster endpoint access is restricted",
        )

    checks["WRK-19"] = wrk19

    def wrk20(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        list_data = ctx.invoke_aws_cli(["eks", "list-clusters"])
        if list_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-20")

        clusters: list[str] = []
        if has_property(list_data, "clusters"):
            clusters = cli_array(list_data.get("clusters"))
        if collection_count(clusters) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-20",
                "PARTIAL",
                {"cluster_count": 0},
                "No EKS clusters found in region",
            )

        required_types = {"api", "audit", "authenticator"}
        cluster_evidence: list[dict[str, Any]] = []
        failing_clusters = 0

        for cluster_name in clusters:
            describe_data = ctx.invoke_aws_cli(["eks", "describe-cluster", "--name", str(cluster_name)])
            if describe_data is None or not has_property(describe_data, "cluster"):
                continue

            cluster = property_value(describe_data, ["cluster"])
            logging_config = property_value(cluster, ["logging"]) if cluster else None
            cluster_logging = property_value(logging_config, ["clusterLogging"]) if logging_config else None
            enabled_types: list[str] = []

            for log_entry in cli_array(cluster_logging):
                enabled = property_value(log_entry, ["enabled"]) is True
                types = cli_array(property_value(log_entry, ["types"]))
                if enabled and types:
                    for log_type in types:
                        log_type_text = str(log_type)
                        if log_type_text not in enabled_types:
                            enabled_types.append(log_type_text)

            cluster_ok = all(required in enabled_types for required in required_types)
            if not cluster_ok:
                failing_clusters += 1

            cluster_evidence.append(
                {
                    "cluster_name": str(cluster_name),
                    "enabled_types": enabled_types,
                }
            )

        evidence = {
            "cluster_count": collection_count(clusters),
            "failing_clusters": failing_clusters,
            "clusters": cluster_evidence,
        }
        if failing_clusters > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-20",
                "FAIL",
                evidence,
                "One or more EKS clusters missing required control plane logs",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-20",
            "PASS",
            evidence,
            "EKS control plane logging enabled for api, audit, and authenticator",
        )

    checks["WRK-20"] = wrk20

    def wrk21(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        rds_data = ctx.invoke_aws_cli(["rds", "describe-db-instances"])
        if rds_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-21")

        public_count = 0
        private_count = 0
        public_instances: list[str] = []
        if has_property(rds_data, "DBInstances"):
            for instance in cli_array(rds_data.get("DBInstances")):
                if property_value(instance, ["PubliclyAccessible"]) is True:
                    public_count += 1
                    if collection_count(public_instances) < 5:
                        public_instances.append(str(property_value(instance, ["DBInstanceIdentifier"]) or ""))
                else:
                    private_count += 1

        evidence = {
            "public_count": public_count,
            "private_count": private_count,
            "public_instances": public_instances,
        }
        if public_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-21",
                "FAIL",
                evidence,
                "Publicly accessible RDS instances found",
            )
        if private_count == 0 and public_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-21",
                "PARTIAL",
                evidence,
                "No RDS instances found in region",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-21",
            "PASS",
            evidence,
            "All RDS instances are not publicly accessible",
        )

    checks["WRK-21"] = wrk21

    def wrk22(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        public_queue_count = 0
        queue_count = 0
        public_topic_count = 0
        topic_count = 0

        sqs_data = ctx.invoke_aws_cli(["sqs", "list-queues"])
        if sqs_data and has_property(sqs_data, "QueueUrls"):
            for queue_url in cli_array(sqs_data.get("QueueUrls")):
                queue_count += 1
                attr_data = ctx.invoke_aws_cli(
                    [
                        "sqs",
                        "get-queue-attributes",
                        "--queue-url",
                        str(queue_url),
                        "--attribute-names",
                        "Policy",
                    ]
                )
                attributes = property_value(attr_data, ["Attributes"]) if attr_data else None
                policy = str(property_value(attributes, ["Policy"]) or "")
                if policy and _wrk_policy_allows_public_principal(policy):
                    public_queue_count += 1

        sns_data = ctx.invoke_aws_cli(["sns", "list-topics"])
        if sns_data and has_property(sns_data, "Topics"):
            for topic in cli_array(sns_data.get("Topics")):
                if not has_property(topic, "TopicArn"):
                    continue
                topic_count += 1
                topic_arn = str(property_value(topic, ["TopicArn"]) or "")
                attr_data = ctx.invoke_aws_cli(["sns", "get-topic-attributes", "--topic-arn", topic_arn])
                attributes = property_value(attr_data, ["Attributes"]) if attr_data else None
                policy = str(property_value(attributes, ["Policy"]) or "")
                if policy and _wrk_policy_allows_public_principal(policy):
                    public_topic_count += 1

        if sqs_data is None and sns_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-22")

        evidence = {
            "queue_count": queue_count,
            "public_queue_count": public_queue_count,
            "topic_count": topic_count,
            "public_topic_count": public_topic_count,
        }
        if public_queue_count > 0 or public_topic_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-22",
                "FAIL",
                evidence,
                "Public SQS or SNS access policies found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-22",
            "PASS",
            evidence,
            "No public SQS or SNS policies detected",
        )

    checks["WRK-22"] = wrk22

    def wrk23(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        encrypted_queues = 0
        unencrypted_queues = 0
        encrypted_topics = 0
        unencrypted_topics = 0

        sqs_data = ctx.invoke_aws_cli(["sqs", "list-queues"])
        if sqs_data and has_property(sqs_data, "QueueUrls"):
            for queue_url in cli_array(sqs_data.get("QueueUrls")):
                attr_data = ctx.invoke_aws_cli(
                    [
                        "sqs",
                        "get-queue-attributes",
                        "--queue-url",
                        str(queue_url),
                        "--attribute-names",
                        "KmsMasterKeyId",
                        "SqsManagedSseEnabled",
                    ]
                )
                encrypted = False
                attributes = property_value(attr_data, ["Attributes"]) if attr_data else None
                if attributes:
                    kms_master_key_id = str(property_value(attributes, ["KmsMasterKeyId"]) or "")
                    sqs_managed_sse = str(property_value(attributes, ["SqsManagedSseEnabled"]) or "")
                    if kms_master_key_id:
                        encrypted = True
                    if sqs_managed_sse.lower() == "true":
                        encrypted = True
                if encrypted:
                    encrypted_queues += 1
                else:
                    unencrypted_queues += 1

        sns_data = ctx.invoke_aws_cli(["sns", "list-topics"])
        if sns_data and has_property(sns_data, "Topics"):
            for topic in cli_array(sns_data.get("Topics")):
                if not has_property(topic, "TopicArn"):
                    continue
                topic_arn = str(property_value(topic, ["TopicArn"]) or "")
                attr_data = ctx.invoke_aws_cli(["sns", "get-topic-attributes", "--topic-arn", topic_arn])
                encrypted = False
                attributes = property_value(attr_data, ["Attributes"]) if attr_data else None
                if attributes and property_value(attributes, ["KmsMasterKeyId"]):
                    encrypted = True
                if encrypted:
                    encrypted_topics += 1
                else:
                    unencrypted_topics += 1

        if sqs_data is None and sns_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-23")

        total_queues = encrypted_queues + unencrypted_queues
        total_topics = encrypted_topics + unencrypted_topics
        evidence = {
            "queue_count": total_queues,
            "encrypted_queue_count": encrypted_queues,
            "topic_count": total_topics,
            "encrypted_topic_count": encrypted_topics,
        }
        if total_queues == 0 and total_topics == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-23",
                "PARTIAL",
                evidence,
                "No SQS queues or SNS topics found in region",
            )
        if unencrypted_queues == 0 and unencrypted_topics == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-23",
                "PASS",
                evidence,
                "All queues and topics are encrypted",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-23",
            "FAIL",
            evidence,
            "One or more queues or topics are not encrypted",
        )

    checks["WRK-23"] = wrk23

    def wrk24(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        api_data = ctx.invoke_aws_cli(["apigateway", "get-rest-apis"])
        if api_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-24")

        apis: list[dict[str, Any]] = []
        if has_property(api_data, "items"):
            apis = cli_array(api_data.get("items"))
        if collection_count(apis) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-24",
                "PARTIAL",
                {"api_count": 0},
                "No REST APIs found in region",
            )

        unauthenticated_methods = 0
        method_count = 0
        for api in apis:
            api_id = str(property_value(api, ["id"]) or "")
            if not api_id:
                continue
            resource_data = ctx.invoke_aws_cli(["apigateway", "get-resources", "--rest-api-id", api_id])
            if resource_data is None or not has_property(resource_data, "items"):
                continue
            for resource in cli_array(resource_data.get("items")):
                if not has_property(resource, "resourceMethods"):
                    continue
                resource_methods = property_value(resource, ["resourceMethods"])
                if not isinstance(resource_methods, dict):
                    continue
                resource_id = str(property_value(resource, ["id"]) or "")
                for method_name in resource_methods.keys():
                    method_count += 1
                    method_data = ctx.invoke_aws_cli(
                        [
                            "apigateway",
                            "get-method",
                            "--rest-api-id",
                            api_id,
                            "--resource-id",
                            resource_id,
                            "--http-method",
                            str(method_name),
                        ]
                    )
                    authorization_type = str(property_value(method_data, ["authorizationType"]) or "")
                    if authorization_type.lower() == "none":
                        unauthenticated_methods += 1

        evidence = {
            "api_count": collection_count(apis),
            "method_count": method_count,
            "unauthenticated_method_count": unauthenticated_methods,
        }
        if unauthenticated_methods > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-24",
                "FAIL",
                evidence,
                "Unauthenticated API Gateway methods found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-24",
            "PASS",
            evidence,
            "No API methods with authorizationType NONE found",
        )

    checks["WRK-24"] = wrk24

    def wrk25(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        api_data = ctx.invoke_aws_cli(["apigateway", "get-rest-apis"])
        if api_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-25")

        apis: list[dict[str, Any]] = []
        if has_property(api_data, "items"):
            apis = cli_array(api_data.get("items"))
        if collection_count(apis) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-25",
                "PARTIAL",
                {"api_count": 0},
                "No REST APIs found in region",
            )

        stage_count = 0
        stages_with_throttling = 0
        for api in apis:
            api_id = str(property_value(api, ["id"]) or "")
            if not api_id:
                continue
            stage_data = ctx.invoke_aws_cli(["apigateway", "get-stages", "--rest-api-id", api_id])
            if stage_data is None or not has_property(stage_data, "item"):
                continue

            for stage in cli_array(stage_data.get("item")):
                stage_count += 1
                has_throttling = False

                method_settings = property_value(stage, ["methodSettings"])
                if isinstance(method_settings, dict):
                    for setting in method_settings.values():
                        burst = property_value(setting, ["throttlingBurstLimit"])
                        rate = property_value(setting, ["throttlingRateLimit"])
                        if burst or rate:
                            has_throttling = True
                            break

                default_route_settings = property_value(stage, ["defaultRouteSettings"])
                if default_route_settings:
                    burst = property_value(default_route_settings, ["throttlingBurstLimit"])
                    rate = property_value(default_route_settings, ["throttlingRateLimit"])
                    if burst or rate:
                        has_throttling = True

                if has_throttling:
                    stages_with_throttling += 1

        evidence = {
            "api_count": collection_count(apis),
            "stage_count": stage_count,
            "stages_with_throttling": stages_with_throttling,
        }
        if stage_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-25",
                "PARTIAL",
                evidence,
                "No API stages found",
            )
        if stages_with_throttling == stage_count:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-25",
                "PASS",
                evidence,
                "All API stages have throttling configured",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-25",
            "FAIL",
            evidence,
            "One or more API stages lack throttling configuration",
        )

    checks["WRK-25"] = wrk25

    def wrk26(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        list_data = ctx.invoke_aws_cli(["cognito-idp", "list-user-pools", "--max-results", "10"])
        if list_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "WRK-26")

        pools: list[dict[str, Any]] = []
        if has_property(list_data, "UserPools"):
            pools = cli_array(list_data.get("UserPools"))
        if collection_count(pools) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-26",
                "PARTIAL",
                {"user_pool_count": 0},
                "No Cognito user pools found in region",
            )

        pool_evidence: list[dict[str, str]] = []
        failing_pools = 0
        for pool in pools:
            pool_id = str(property_value(pool, ["Id"]) or "")
            if not pool_id:
                continue
            describe_data = ctx.invoke_aws_cli(
                ["cognito-idp", "describe-user-pool", "--user-pool-id", pool_id]
            )
            mfa_config = "OFF"
            user_pool = property_value(describe_data, ["UserPool"]) if describe_data else None
            mfa_value = str(property_value(user_pool, ["MfaConfiguration"]) or "")
            if mfa_value:
                mfa_config = mfa_value

            pool_evidence.append(
                {
                    "pool_id": pool_id,
                    "pool_name": str(property_value(pool, ["Name"]) or ""),
                    "mfa_configuration": mfa_config,
                }
            )
            if mfa_config.lower() == "off":
                failing_pools += 1

        evidence = {
            "user_pool_count": collection_count(pools),
            "failing_pools": failing_pools,
            "pools": pool_evidence,
        }
        if failing_pools > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "WRK-26",
                "FAIL",
                evidence,
                "One or more Cognito user pools have MFA disabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "WRK-26",
            "PASS",
            evidence,
            "Cognito user pools have MFA enabled",
        )

    checks["WRK-26"] = wrk26

    return DomainModule(code="WRK", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
