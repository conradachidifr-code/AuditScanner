"""CIC domain — CI/CD and IaC controls."""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "CIC-01": "P0",
    "CIC-02": "P0",
    "CIC-03": "P0",
    "CIC-04": "P0",
    "CIC-05": "P0",
    "CIC-06": "P0",
    "CIC-07": "P0",
    "CIC-08": "P1",
    "CIC-09": "P0",
    "CIC-10": "P1",
    "CIC-11": "P1",
    "CIC-12": "P1",
    "CIC-13": "P0",
    "CIC-14": "P0",
    "CIC-15": "P0",
    "CIC-16": "P1",
    "CIC-17": "P0",
    "CIC-18": "P1",
    "CIC-19": "P0",
}


def _get_cic_s3_bucket_names(ctx: CheckContext) -> list[str] | None:
    data = ctx.invoke_aws_cli(["s3api", "list-buckets"])
    if data is None:
        return None

    bucket_names: list[str] = []
    if has_property(data, "Buckets"):
        for bucket in cli_array(property_value(data, ["Buckets"])):
            if has_property(bucket, "Name"):
                bucket_names.append(str(property_value(bucket, ["Name"]) or ""))
    return bucket_names


def _test_cic_s3_bucket_encrypted(ctx: CheckContext, bucket_name: str) -> bool:
    data = ctx.invoke_aws_cli(["s3api", "get-bucket-encryption", "--bucket", bucket_name])
    if data is None:
        return False
    return property_value(data, ["ServerSideEncryptionConfiguration"]) is not None


def _test_cic_s3_bucket_kms_encrypted(ctx: CheckContext, bucket_name: str) -> bool:
    data = ctx.invoke_aws_cli(["s3api", "get-bucket-encryption", "--bucket", bucket_name])
    if data is None:
        return False
    rules_container = property_value(data, ["ServerSideEncryptionConfiguration"])
    rules = property_value(rules_container, ["Rules"]) if isinstance(rules_container, dict) else None
    for rule in cli_array(rules):
        default = property_value(rule, ["ApplyServerSideEncryptionByDefault"])
        if not isinstance(default, dict):
            continue
        algorithm = str(property_value(default, ["SSEAlgorithm"]) or "")
        if algorithm.lower() == "aws:kms":
            return True
    return False


def _get_cic_terraform_state_buckets(bucket_names: list[str]) -> list[str]:
    return [name for name in bucket_names if re.search(r"terraform|tfstate", name.lower())]


def _get_cic_terraform_lock_tables(ctx: CheckContext) -> list[str] | None:
    data = ctx.invoke_aws_cli(["dynamodb", "list-tables"])
    if data is None:
        return None
    tables: list[str] = []
    if has_property(data, "TableNames"):
        for table_name in cli_array(property_value(data, ["TableNames"])):
            name = str(table_name)
            if re.search(r"terraform|tfstate|lock", name.lower()):
                tables.append(name)
    return tables


def _cic_cloudtrail_event_matches(ctx: CheckContext, lookup: list[str], patterns: list[str]) -> dict[str, object]:
    end_time = datetime.now(timezone.utc).isoformat()
    start_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    data = ctx.invoke_aws_cli(
        [
            "cloudtrail",
            "lookup-events",
            *lookup,
            "--start-time",
            start_time,
            "--end-time",
            end_time,
            "--max-results",
            "50",
        ]
    )
    if data is None:
        return {"api_available": False, "event_count": 0, "matching_event_count": 0, "sample_event_names": []}

    matching_names: list[str] = []
    events = cli_array(property_value(data, ["Events"])) if has_property(data, "Events") else []
    for event in events:
        if not isinstance(event, dict):
            continue
        event_name = str(property_value(event, ["EventName"]) or "")
        event_blob = str(property_value(event, ["CloudTrailEvent"]) or "")
        if any(re.search(pattern, event_blob, re.IGNORECASE) or re.search(pattern, event_name, re.IGNORECASE) for pattern in patterns):
            if collection_count(matching_names) < 10:
                matching_names.append(event_name)

    return {
        "api_available": True,
        "event_count": collection_count(events),
        "matching_event_count": collection_count(matching_names),
        "sample_event_names": list(matching_names),
    }


def _get_cic_pipeline_roles(ctx: CheckContext) -> list[dict[str, str]] | None:
    data = ctx.invoke_aws_cli(["iam", "list-roles", "--max-items", "1000"])
    if data is None:
        return None
    roles: list[dict[str, str]] = []
    if has_property(data, "Roles"):
        for role in cli_array(property_value(data, ["Roles"])):
            role_name = str(property_value(role, ["RoleName"]) or "")
            if re.search(r"pipeline|deploy|cicd|terraform", role_name, re.IGNORECASE):
                roles.append({"role_name": role_name, "arn": str(property_value(role, ["Arn"]) or "")})
    return roles


def _get_cic_pipeline_users_with_active_keys(ctx: CheckContext) -> tuple[list[str], list[str]] | None:
    user_data = ctx.invoke_aws_cli(["iam", "list-users", "--max-items", "1000"])
    if user_data is None:
        return None
    pipeline_users: list[str] = []
    users_with_active_keys: list[str] = []
    if has_property(user_data, "Users"):
        for user in cli_array(property_value(user_data, ["Users"])):
            user_name = str(property_value(user, ["UserName"]) or "")
            if not re.search(r"pipeline|deploy|ci|gitlab", user_name, re.IGNORECASE):
                continue
            pipeline_users.append(user_name)
            key_data = ctx.invoke_aws_cli(["iam", "list-access-keys", "--user-name", user_name])
            if key_data is None or not has_property(key_data, "AccessKeyMetadata"):
                continue
            for key in cli_array(property_value(key_data, ["AccessKeyMetadata"])):
                if str(property_value(key, ["Status"]) or "") == "Active":
                    users_with_active_keys.append(user_name)
                    break
    return pipeline_users, users_with_active_keys


def _test_cic_s3_bucket_public_access_blocked(ctx: CheckContext, bucket_name: str) -> bool:
    data = ctx.invoke_aws_cli(["s3api", "get-public-access-block", "--bucket", bucket_name])
    if data is None:
        return False
    if not has_property(data, "PublicAccessBlockConfiguration"):
        return False

    config = property_value(data, ["PublicAccessBlockConfiguration"])
    return (
        property_value(config, ["BlockPublicAcls"]) is True
        and property_value(config, ["IgnorePublicAcls"]) is True
        and property_value(config, ["BlockPublicPolicy"]) is True
        and property_value(config, ["RestrictPublicBuckets"]) is True
    )


def _test_cic_s3_bucket_versioning_enabled(ctx: CheckContext, bucket_name: str) -> bool:
    data = ctx.invoke_aws_cli(["s3api", "get-bucket-versioning", "--bucket", bucket_name])
    if data is None:
        return False
    if has_property(data, "Status"):
        return str(property_value(data, ["Status"]) or "") == "Enabled"
    return False


def _get_cic_ssm_string_parameter_count(ctx: CheckContext) -> dict[str, int] | None:
    data = ctx.invoke_aws_cli(["ssm", "describe-parameters"])
    if data is None:
        return None

    string_count = 0
    secure_string_count = 0
    if has_property(data, "Parameters"):
        for parameter in cli_array(property_value(data, ["Parameters"])):
            param_type = str(property_value(parameter, ["Type"]) or "")
            if param_type == "String":
                string_count += 1
            if param_type == "SecureString":
                secure_string_count += 1

    return {
        "string_count": string_count,
        "secure_string_count": secure_string_count,
    }


def _get_cic_active_access_key_count(ctx: CheckContext) -> dict[str, object] | None:
    user_data = ctx.invoke_aws_cli(["iam", "list-users", "--max-items", "1000"])
    if user_data is None:
        return None

    active_key_count = 0
    users_with_keys: list[str] = []
    if has_property(user_data, "Users"):
        for user in cli_array(property_value(user_data, ["Users"])):
            user_name = str(property_value(user, ["UserName"]) or "")
            key_data = ctx.invoke_aws_cli(["iam", "list-access-keys", "--user-name", user_name])
            if key_data is None:
                continue
            if not has_property(key_data, "AccessKeyMetadata"):
                continue

            for key in cli_array(property_value(key_data, ["AccessKeyMetadata"])):
                if str(property_value(key, ["Status"]) or "") == "Active":
                    active_key_count += 1
                    if collection_count(users_with_keys) < 5:
                        users_with_keys.append(user_name)

    return {
        "active_access_key_count": active_key_count,
        "users_with_keys": list(users_with_keys),
    }


def _get_cic_cloudformation_stack_count(ctx: CheckContext) -> int | None:
    data = ctx.invoke_aws_cli(
        [
            "cloudformation",
            "list-stacks",
            "--stack-status-filter",
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
        ]
    )
    if data is None:
        return None
    if has_property(data, "StackSummaries"):
        return collection_count(property_value(data, ["StackSummaries"]))
    return 0


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(control_id: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, control_id, notes)

        return _check

    checks["CIC-01"] = workshop(
        "CIC-01", "Verify IaC-only deployment. No untracked console-created resources."
    )

    def cic01(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        bucket_names = _get_cic_s3_bucket_names(ctx)
        if bucket_names is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-01")

        state_buckets = _get_cic_terraform_state_buckets(bucket_names)
        cf_stack_count = _get_cic_cloudformation_stack_count(ctx)
        evidence = {
            "terraform_state_bucket_count": collection_count(state_buckets),
            "terraform_state_buckets": list(state_buckets[:10]),
            "cloudformation_stack_count": cf_stack_count,
        }
        if collection_count(state_buckets) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-01",
                "PASS",
                evidence,
                "Terraform state buckets found as IaC deployment evidence",
            )
        if cf_stack_count is not None and cf_stack_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-01",
                "PARTIAL",
                evidence,
                "CloudFormation stacks found but no Terraform state buckets identified",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-01",
            "PARTIAL",
            evidence,
            "No Terraform state buckets or CloudFormation stacks found; verify IaC-only deployment manually",
        )

    checks["CIC-01"] = cic01
    checks["CIC-02"] = workshop("CIC-02", "Verify IaC repos versioned via GitLab tags/releases.")
    checks["CIC-03"] = workshop("CIC-03", "Verify merge request process with peer review. Check GitLab branch protection.")
    checks["CIC-04"] = workshop("CIC-04", "Verify separate pipeline definitions for prod vs non-prod.")

    def cic05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = ctx.results.global_control_gate(account_id, account_name, region, "CIC-05")
        if gate:
            return gate
        roles = _get_cic_pipeline_roles(ctx)
        pipeline_user_data = _get_cic_pipeline_users_with_active_keys(ctx)
        oidc_data = ctx.invoke_aws_cli(["iam", "list-open-id-connect-providers"])
        if roles is None and pipeline_user_data is None and oidc_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-05")

        pipeline_users: list[str] = []
        users_with_active_keys: list[str] = []
        if pipeline_user_data is not None:
            pipeline_users, users_with_active_keys = pipeline_user_data

        oidc_providers: list[str] = []
        if oidc_data and has_property(oidc_data, "OpenIDConnectProviderList"):
            for provider in cli_array(property_value(oidc_data, ["OpenIDConnectProviderList"])):
                oidc_providers.append(str(property_value(provider, ["Arn"]) or ""))

        evidence = {
            "pipeline_role_count": collection_count(roles or []),
            "pipeline_roles": list(roles or [])[:10],
            "pipeline_user_count": collection_count(pipeline_users),
            "pipeline_users_with_active_keys": list(users_with_active_keys),
            "oidc_provider_count": collection_count(oidc_providers),
            "oidc_providers": list(oidc_providers),
        }
        if collection_count(users_with_active_keys) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-05",
                "FAIL",
                evidence,
                "Pipeline-related IAM users have active access keys",
            )
        if collection_count(roles or []) > 0 and collection_count(oidc_providers) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-05",
                "PASS",
                evidence,
                "Dedicated pipeline roles and OIDC federation are present without static pipeline user keys",
            )
        if collection_count(roles or []) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-05",
                "PARTIAL",
                evidence,
                "Pipeline roles found but OIDC federation not evidenced",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-05",
            "PARTIAL",
            evidence,
            "No dedicated pipeline roles identified; verify STS/OIDC pipeline identities manually",
        )

    checks["CIC-05"] = cic05

    def cic06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        ssm_stats = _get_cic_ssm_string_parameter_count(ctx)
        key_stats = _get_cic_active_access_key_count(ctx)
        if ssm_stats is None and key_stats is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-06")

        string_param_count = int(property_value(ssm_stats, ["string_count"]) or 0) if ssm_stats else 0
        active_key_count = int(property_value(key_stats, ["active_access_key_count"]) or 0) if key_stats else 0

        evidence = {
            "ssm_string_parameter_count": string_param_count,
            "active_access_key_count": active_key_count,
            "users_with_keys": [],
        }
        if key_stats and has_property(key_stats, "users_with_keys"):
            evidence["users_with_keys"] = list(cli_array(property_value(key_stats, ["users_with_keys"])))

        if string_param_count > 0 or active_key_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-06",
                "PARTIAL",
                evidence,
                "SSM String parameters or IAM access keys found; review whether they store pipeline secrets",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-06",
            "PASS",
            evidence,
            "No SSM String parameters or active IAM access keys found",
        )

    checks["CIC-06"] = cic06
    checks["CIC-07"] = workshop("CIC-07", "Verify Checkov/KICS integrated in GitLab CI pipeline.")
    checks["CIC-08"] = workshop(
        "CIC-08",
        "Verify security gates block non-compliant IaC deployments. Check policy-as-code enforcement status in pipeline.",
    )

    def cic09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        bucket_names = _get_cic_s3_bucket_names(ctx)
        if bucket_names is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-09")

        state_buckets = _get_cic_terraform_state_buckets(bucket_names)
        lock_tables = _get_cic_terraform_lock_tables(ctx)

        if collection_count(state_buckets) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-09",
                "PARTIAL",
                {"state_bucket_count": 0, "lock_table_count": collection_count(lock_tables or [])},
                "No Terraform state bucket found by naming (may use CloudFormation)",
            )

        bucket_evidence: list[dict[str, object]] = []
        all_pass = True
        for bucket_name in state_buckets:
            encrypted = _test_cic_s3_bucket_encrypted(ctx, bucket_name)
            kms_encrypted = _test_cic_s3_bucket_kms_encrypted(ctx, bucket_name)
            private = _test_cic_s3_bucket_public_access_blocked(ctx, bucket_name)
            versioned = _test_cic_s3_bucket_versioning_enabled(ctx, bucket_name)
            bucket_evidence.append(
                {
                    "bucket_name": bucket_name,
                    "encrypted": encrypted,
                    "kms_encrypted": kms_encrypted,
                    "public_blocked": private,
                    "versioning": versioned,
                }
            )
            if not (kms_encrypted and private and versioned):
                all_pass = False

        evidence = {
            "state_bucket_count": collection_count(state_buckets),
            "lock_table_count": collection_count(lock_tables or []),
            "lock_tables": list(lock_tables or []),
            "buckets": list(bucket_evidence),
        }
        if all_pass and collection_count(lock_tables or []) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-09",
                "PASS",
                evidence,
                "Terraform state buckets use SSE-KMS, are private and versioned with lock tables present",
            )
        if all_pass:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-09",
                "PARTIAL",
                evidence,
                "Terraform state buckets are protected but DynamoDB state lock tables were not found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-09",
            "FAIL",
            evidence,
            "Terraform state bucket missing encryption, public access blocks, or versioning",
        )

    checks["CIC-09"] = cic09

    def cic10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        assume_role_events = _cic_cloudtrail_event_matches(
            ctx,
            [
                "--lookup-attributes",
                "AttributeKey=EventName,AttributeValue=AssumeRole",
            ],
            [r"terraform", r"deploy", r"pipeline", r"gitlab"],
        )
        s3_state_events = _cic_cloudtrail_event_matches(
            ctx,
            [
                "--lookup-attributes",
                "AttributeKey=EventSource,AttributeValue=s3.amazonaws.com",
            ],
            [r"tfstate", r"terraform"],
        )
        cf_events = _cic_cloudtrail_event_matches(
            ctx,
            [
                "--lookup-attributes",
                "AttributeKey=EventSource,AttributeValue=cloudformation.amazonaws.com",
            ],
            [r"cloudformation"],
        )
        if not assume_role_events["api_available"] and not s3_state_events["api_available"]:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-10")

        matching_count = (
            int(assume_role_events["matching_event_count"])
            + int(s3_state_events["matching_event_count"])
            + int(cf_events["matching_event_count"])
        )
        evidence = {
            "assume_role_events": assume_role_events,
            "s3_state_events": s3_state_events,
            "cloudformation_events": cf_events,
        }
        if matching_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-10",
                "PASS",
                evidence,
                "Deployment activity evidenced in CloudTrail via Terraform, state access, or CloudFormation",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-10",
            "PARTIAL",
            evidence,
            "No deployment events found in CloudTrail sample; verify GitLab/Terraform traceability manually",
        )

    checks["CIC-10"] = cic10
    checks["CIC-11"] = workshop("CIC-11", "Verify rollback procedure exists and has been tested.")

    def cic12(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        status_data = ctx.invoke_aws_cli(["configservice", "describe-configuration-recorder-status"])
        if status_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-12")

        recorder_active = False
        recorder_names: list[str] = []
        if has_property(status_data, "ConfigurationRecordersStatus"):
            for status in cli_array(property_value(status_data, ["ConfigurationRecordersStatus"])):
                name = str(property_value(status, ["name"]) or "")
                if name:
                    recorder_names.append(name)
                if property_value(status, ["recording"]) is True:
                    recorder_active = True

        rules_data = ctx.invoke_aws_cli(["configservice", "describe-config-rules"])
        events_data = ctx.invoke_aws_cli(["events", "list-rules"])
        config_rules: list[str] = []
        if rules_data and has_property(rules_data, "ConfigRules"):
            for rule in cli_array(property_value(rules_data, ["ConfigRules"])):
                rule_name = str(property_value(rule, ["ConfigRuleName"]) or "")
                if rule_name:
                    config_rules.append(rule_name)

        config_event_rules: list[str] = []
        if events_data and has_property(events_data, "Rules"):
            for rule in cli_array(property_value(events_data, ["Rules"])):
                rule_name = str(property_value(rule, ["Name"]) or "")
                event_pattern = str(property_value(rule, ["EventPattern"]) or "")
                state = str(property_value(rule, ["State"]) or "")
                if state == "ENABLED" and re.search(r"config", event_pattern, re.IGNORECASE):
                    config_event_rules.append(rule_name)

        evidence = {
            "recorder_active": recorder_active,
            "recorder_names": recorder_names,
            "config_rule_count": collection_count(config_rules),
            "config_rule_names": list(config_rules[:10]),
            "config_event_rule_names": list(config_event_rules),
        }
        if recorder_active and collection_count(config_rules) > 0 and collection_count(config_event_rules) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-12",
                "PASS",
                evidence,
                "AWS Config recorder, rules and config-change alerting are active",
            )
        if recorder_active:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-12",
                "PARTIAL",
                evidence,
                "AWS Config recorder is active but drift alerting or config rules are incomplete",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-12",
            "FAIL",
            evidence,
            "AWS Config recorder is not active",
        )

    checks["CIC-12"] = cic12
    checks["CIC-13"] = workshop("CIC-13", "Verify GitLab repo access controls and merge rights.")
    checks["CIC-14"] = workshop("CIC-14", "Verify main/master branches protected in GitLab.")

    checks["CIC-15"] = workshop(
        "CIC-15",
        "Manual console changes allowed but tracked via CloudTrail. Verify IaC enforcement policy.",
    )
    checks["CIC-16"] = workshop("CIC-16", "Verify test stage in pipeline (Checkov, KICS, cfn-lint).")

    def cic17(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["logs", "describe-log-groups"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-17")

        pipeline_groups: list[dict[str, object]] = []
        groups_without_retention: list[str] = []
        if has_property(data, "logGroups"):
            for log_group in cli_array(property_value(data, ["logGroups"])):
                name = str(property_value(log_group, ["logGroupName"]) or "")
                if not re.search(r"pipeline|codebuild|codepipeline|gitlab", name.lower()):
                    continue

                retention = None
                if has_property(log_group, "retentionInDays"):
                    retention = property_value(log_group, ["retentionInDays"])

                pipeline_groups.append(
                    {
                        "log_group_name": name,
                        "retention_in_days": retention,
                    }
                )
                if retention is None and collection_count(groups_without_retention) < 5:
                    groups_without_retention.append(name)

        evidence = {
            "pipeline_log_group_count": collection_count(pipeline_groups),
            "pipeline_log_groups": list(pipeline_groups),
            "groups_without_retention": list(groups_without_retention),
        }
        if collection_count(pipeline_groups) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-17",
                "PARTIAL",
                evidence,
                "No pipeline-related CloudWatch log groups identified",
            )
        if collection_count(groups_without_retention) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-17",
                "PASS",
                evidence,
                "Pipeline log groups found with retention configured",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-17",
            "FAIL",
            evidence,
            "Pipeline log groups found without retention configured",
        )

    checks["CIC-17"] = cic17
    checks["CIC-18"] = workshop("CIC-18", "Verify periodic review and cleanup of unused GitLab pipelines.")

    def cic19(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        pipeline_events = _cic_cloudtrail_event_matches(
            ctx,
            [
                "--lookup-attributes",
                "AttributeKey=EventSource,AttributeValue=codepipeline.amazonaws.com",
            ],
            [r"codepipeline"],
        )
        terraform_events = _cic_cloudtrail_event_matches(
            ctx,
            [
                "--lookup-attributes",
                "AttributeKey=EventName,AttributeValue=AssumeRole",
            ],
            [r"terraform", r"deploy", r"pipeline", r"gitlab"],
        )
        state_events = _cic_cloudtrail_event_matches(
            ctx,
            [
                "--lookup-attributes",
                "AttributeKey=EventSource,AttributeValue=s3.amazonaws.com",
            ],
            [r"tfstate", r"terraform"],
        )
        if not pipeline_events["api_available"] and not terraform_events["api_available"]:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-19")

        matching_count = (
            int(pipeline_events["matching_event_count"])
            + int(terraform_events["matching_event_count"])
            + int(state_events["matching_event_count"])
        )
        evidence = {
            "codepipeline_events": pipeline_events,
            "terraform_assume_role_events": terraform_events,
            "terraform_state_events": state_events,
        }
        if matching_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-19",
                "PASS",
                evidence,
                "CI/CD activity evidenced in CloudTrail via CodePipeline, Terraform or state access",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-19",
            "PARTIAL",
            evidence,
            "No CI/CD events found in CloudTrail sample; verify GitLab pipeline auditability manually",
        )

    checks["CIC-19"] = cic19

    if len(checks) != 19:
        raise RuntimeError(f"get_domain expected 19 CIC controls but defined {len(checks)}")

    return DomainModule(code="CIC", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
