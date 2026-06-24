"""LOG domain — logging and monitoring controls."""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "LOG-01": "P0",
    "LOG-02": "P0",
    "LOG-03": "P0",
    "LOG-04": "P0",
    "LOG-05": "P0",
    "LOG-06": "P1",
    "LOG-07": "P0",
    "LOG-08": "P0",
    "LOG-09": "P0",
    "LOG-10": "P0",
    "LOG-11": "P0",
    "LOG-12": "P1",
    "LOG-13": "P0",
    "LOG-14": "P0",
    "LOG-15": "P0",
    "LOG-16": "P0",
    "LOG-17": "P2",
    "LOG-18": "P0",
    "LOG-19": "P1",
    "LOG-20": "P1",
    "LOG-21": "P0",
    "LOG-22": "P0",
}


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return _string(value).lower() == "true"


def _log_cloud_trails(ctx: CheckContext) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["cloudtrail", "describe-trails", "--include-shadow-trails"])
    if data is None:
        return None
    if has_property(data, "trailList"):
        return cli_array(property_value(data, ["trailList"]))
    return []


def _log_trail_status(ctx: CheckContext, trail_name: str) -> dict[str, Any] | None:
    data = ctx.invoke_aws_cli(["cloudtrail", "get-trail-status", "--name", trail_name])
    if isinstance(data, dict):
        return data
    return data if data is None else {}


def _log_organization_trail(trails: list[dict[str, Any]]) -> dict[str, Any] | None:
    for trail in trails:
        if _truthy(property_value(trail, ["IsOrganizationTrail"])):
            return trail
    return None


def _log_trail_identifier(trail: dict[str, Any]) -> str | None:
    if has_property(trail, "TrailARN"):
        value = _string(property_value(trail, ["TrailARN"]))
        return value or None
    if has_property(trail, "Name"):
        value = _string(property_value(trail, ["Name"]))
        return value or None
    return None


def _log_cloudtrail_log_group_name(trail: dict[str, Any]) -> str | None:
    if not has_property(trail, "CloudWatchLogsLogGroupArn"):
        return None
    arn = _string(property_value(trail, ["CloudWatchLogsLogGroupArn"]))
    match = re.search(r"log-group:([^:*]+)", arn)
    if match:
        return match.group(1)
    return None


def _test_log_s3_bucket_sse_kms(ctx: CheckContext, bucket_name: str) -> bool:
    data = ctx.invoke_aws_cli(["s3api", "get-bucket-encryption", "--bucket", bucket_name])
    if data is None:
        return False
    config = property_value(data, ["ServerSideEncryptionConfiguration"])
    if not isinstance(config, dict):
        return False
    rules = property_value(config, ["Rules"])
    if rules is None:
        return False
    for rule in cli_array(rules):
        default = property_value(rule, ["ApplyServerSideEncryptionByDefault"])
        if isinstance(default, dict):
            algorithm = _string(property_value(default, ["SSEAlgorithm"]))
            if algorithm == "aws:kms":
                return True
    return False


def _test_log_s3_bucket_public_access_blocked(ctx: CheckContext, bucket_name: str) -> bool:
    data = ctx.invoke_aws_cli(["s3api", "get-public-access-block", "--bucket", bucket_name])
    if data is None:
        return False
    config = property_value(data, ["PublicAccessBlockConfiguration"])
    if not isinstance(config, dict):
        return False
    return (
        _truthy(property_value(config, ["BlockPublicAcls"]))
        and _truthy(property_value(config, ["IgnorePublicAcls"]))
        and _truthy(property_value(config, ["BlockPublicPolicy"]))
        and _truthy(property_value(config, ["RestrictPublicBuckets"]))
    )


def _test_log_s3_bucket_versioning_enabled(ctx: CheckContext, bucket_name: str) -> bool:
    data = ctx.invoke_aws_cli(["s3api", "get-bucket-versioning", "--bucket", bucket_name])
    if data is None:
        return False
    if has_property(data, "Status"):
        return _string(property_value(data, ["Status"])) == "Enabled"
    return False


def _test_log_bucket_policy_public_read(ctx: CheckContext, bucket_name: str) -> bool:
    data = ctx.invoke_aws_cli(["s3api", "get-bucket-policy", "--bucket", bucket_name])
    if data is None:
        return False
    if not has_property(data, "Policy"):
        return False
    policy_text = _string(property_value(data, ["Policy"]))
    if (
        re.search(r'"Principal"\s*:\s*"\*"', policy_text)
        and re.search(r"s3:GetObject", policy_text)
        and re.search(r'"Effect"\s*:\s*"Allow"', policy_text)
    ):
        return True
    return False


def _log_cis_metric_pattern_definitions() -> list[dict[str, str]]:
    return [
        {"Id": "CIS-3.1", "Match": r"UnauthorizedOperation|AccessDenied\*|\$\.errorCode"},
        {"Id": "CIS-3.2", "Match": r"ConsoleLogin|MFAUsed"},
        {"Id": "CIS-3.3", "Match": r"Root|\$\.userIdentity\.type"},
        {
            "Id": "CIS-3.4",
            "Match": (
                r"PutGroupPolicy|PutRolePolicy|PutUserPolicy|AttachGroupPolicy|AttachRolePolicy|AttachUserPolicy|"
                r"DeleteGroupPolicy|DeleteRolePolicy|DeleteUserPolicy|DetachGroupPolicy|DetachRolePolicy|DetachUserPolicy"
            ),
        },
        {"Id": "CIS-3.5", "Match": r"CreateTrail|UpdateTrail|DeleteTrail|StartLogging|StopLogging"},
        {"Id": "CIS-3.6", "Match": r"ConsoleLogin|Failed authentication|errorMessage"},
        {"Id": "CIS-3.7", "Match": r"DisableKey|ScheduleKeyDeletion"},
        {"Id": "CIS-3.8", "Match": r"PutBucketPolicy|DeleteBucketPolicy|PutBucketAcl|PutObjectAcl"},
        {"Id": "CIS-3.9", "Match": r"PutConfigurationRecorder|DeleteDeliveryChannel|StopConfigurationRecorder"},
        {
            "Id": "CIS-3.10",
            "Match": (
                r"AuthorizeSecurityGroupIngress|AuthorizeSecurityGroupEgress|RevokeSecurityGroupIngress|"
                r"RevokeSecurityGroupEgress|CreateSecurityGroup|DeleteSecurityGroup"
            ),
        },
        {
            "Id": "CIS-3.11",
            "Match": r"CreateNetworkAcl|DeleteNetworkAcl|CreateNetworkAclEntry|DeleteNetworkAclEntry|ReplaceNetworkAclEntry",
        },
        {
            "Id": "CIS-3.12",
            "Match": (
                r"CreateCustomerGateway|DeleteCustomerGateway|AttachInternetGateway|CreateInternetGateway|"
                r"DeleteInternetGateway|DetachInternetGateway"
            ),
        },
        {"Id": "CIS-3.13", "Match": r"CreateRoute|DeleteRoute|ReplaceRoute|AssociateRouteTable|DisassociateRouteTable"},
        {"Id": "CIS-3.14", "Match": r"CreateVpc|DeleteVpc|ModifyVpcAttribute"},
    ]


def _log_cis_metric_filter_assessment(ctx: CheckContext, log_group_name: str) -> dict[str, Any] | None:
    filter_data = ctx.invoke_aws_cli(["logs", "describe-metric-filters", "--log-group-name", log_group_name])
    if filter_data is None:
        return None

    filter_patterns: list[str] = []
    if has_property(filter_data, "metricFilters"):
        for metric_filter in cli_array(property_value(filter_data, ["metricFilters"])):
            if has_property(metric_filter, "filterPattern"):
                filter_patterns.append(_string(property_value(metric_filter, ["filterPattern"])))

    matched: list[str] = []
    missing: list[str] = []
    for definition in _log_cis_metric_pattern_definitions():
        found = False
        expression = definition["Match"]
        for pattern in filter_patterns:
            if re.search(expression, pattern):
                found = True
                break
        if found:
            matched.append(definition["Id"])
        else:
            missing.append(definition["Id"])

    return {
        "matched_patterns": list(matched),
        "missing_patterns": list(missing),
        "matched_count": collection_count(matched),
        "missing_count": collection_count(missing),
        "filter_count": collection_count(filter_patterns),
    }


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(control_id: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, control_id, notes)

        return _check

    def log01(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-01")
        if collection_count(trails) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "LOG-01", "FAIL", {"trail_count": 0}, "No CloudTrail trails found"
            )

        active_trails: list[dict[str, Any]] = []
        for trail in trails:
            trail_id = _log_trail_identifier(trail)
            if not trail_id:
                continue
            status = _log_trail_status(ctx, trail_id)
            is_logging = bool(status and _truthy(property_value(status, ["IsLogging"])))
            if is_logging:
                active_trails.append(
                    {
                        "name": _string(property_value(trail, ["Name"])),
                        "is_logging": True,
                        "home_region": _string(property_value(trail, ["HomeRegion"])),
                    }
                )

        evidence = {"trail_count": collection_count(trails), "active_trails": list(active_trails)}
        if collection_count(active_trails) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-01",
                "PASS",
                evidence,
                "At least one CloudTrail trail has IsLogging=true",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "LOG-01", "FAIL", evidence, "No trails with IsLogging=true"
        )

    checks["LOG-01"] = log01

    def log02(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-02")

        matching_trails: list[dict[str, Any]] = []
        for trail in trails:
            is_multi = _truthy(property_value(trail, ["IsMultiRegionTrail"]))
            is_org = _truthy(property_value(trail, ["IsOrganizationTrail"]))
            if is_multi and is_org:
                matching_trails.append(
                    {
                        "name": _string(property_value(trail, ["Name"])),
                        "is_multi_region_trail": True,
                        "is_organization_trail": True,
                    }
                )

        evidence = {"matching_trail_count": collection_count(matching_trails), "trails": list(matching_trails)}
        if collection_count(matching_trails) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-02",
                "PASS",
                evidence,
                "Multi-region organization CloudTrail trail found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-02",
            "FAIL",
            evidence,
            "No multi-region organization CloudTrail trail found",
        )

    checks["LOG-02"] = log02

    def log03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-03")

        org_trail = _log_organization_trail(trails)
        if org_trail is None and collection_count(trails) > 0:
            org_trail = trails[0]

        if org_trail is None:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-03",
                "FAIL",
                None,
                "No CloudTrail trail available for event selector review",
            )

        trail_id = _log_trail_identifier(org_trail)
        selector_data = (
            ctx.invoke_aws_cli(["cloudtrail", "get-event-selectors", "--trail-name", trail_id]) if trail_id else None
        )
        if selector_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-03")

        pass_found = False
        selector_evidence: list[dict[str, Any]] = []
        if has_property(selector_data, "EventSelectors"):
            for selector in cli_array(property_value(selector_data, ["EventSelectors"])):
                read_write_type = _string(property_value(selector, ["ReadWriteType"]))
                include_management = _truthy(property_value(selector, ["IncludeManagementEvents"]))
                selector_evidence.append(
                    {
                        "read_write_type": read_write_type,
                        "include_management_events": include_management,
                    }
                )
                if include_management and read_write_type == "All":
                    pass_found = True

        evidence = {
            "trail_name": _string(property_value(org_trail, ["Name"])),
            "event_selectors": list(selector_evidence),
        }
        if pass_found:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-03",
                "PASS",
                evidence,
                "Management events included with ReadWriteType=All",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-03",
            "FAIL",
            evidence,
            "Management events not fully configured (ReadWriteType=All required)",
        )

    checks["LOG-03"] = log03

    def log04(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-04")

        org_trail = _log_organization_trail(trails)
        if org_trail is None and collection_count(trails) > 0:
            org_trail = trails[0]

        if org_trail is None:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-04",
                "FAIL",
                None,
                "No CloudTrail trail available for data event review",
            )

        trail_id = _log_trail_identifier(org_trail)
        selector_data = (
            ctx.invoke_aws_cli(["cloudtrail", "get-event-selectors", "--trail-name", trail_id]) if trail_id else None
        )
        if selector_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-04")

        s3_data_resources: list[dict[str, Any]] = []
        lambda_data_resources: list[dict[str, Any]] = []
        if has_property(selector_data, "EventSelectors"):
            for selector in cli_array(property_value(selector_data, ["EventSelectors"])):
                if not has_property(selector, "DataResources"):
                    continue
                for resource in cli_array(property_value(selector, ["DataResources"])):
                    resource_type = _string(property_value(resource, ["Type"]))
                    values = []
                    if has_property(resource, "Values"):
                        values = list(cli_array(property_value(resource, ["Values"])))
                    if resource_type == "AWS::S3::Object":
                        s3_data_resources.append({"type": resource_type, "values": list(values)})
                    if resource_type == "AWS::Lambda::Function":
                        lambda_data_resources.append({"type": resource_type, "values": list(values)})

        evidence = {
            "trail_name": _string(property_value(org_trail, ["Name"])),
            "s3_data_resources": list(s3_data_resources),
            "lambda_data_resources": list(lambda_data_resources),
            "s3_data_resources": list(s3_data_resources),
            "s3_data_resource_count": collection_count(s3_data_resources),
            "lambda_data_resource_count": collection_count(lambda_data_resources),
        }
        if collection_count(s3_data_resources) > 0 or collection_count(lambda_data_resources) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-04",
                "PASS",
                evidence,
                "S3 or Lambda data events configured on CloudTrail",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "LOG-04", "FAIL", evidence, "No S3 or Lambda data events configured"
        )

    checks["LOG-04"] = log04

    def log05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-05")

        org_trail = _log_organization_trail(trails)
        if org_trail is None:
            return ctx.results.audit_result(
                account_id, account_name, region, "LOG-05", "FAIL", None, "No organization CloudTrail trail found"
            )

        validation_enabled = _truthy(property_value(org_trail, ["LogFileValidationEnabled"]))
        evidence = {
            "trail_name": _string(property_value(org_trail, ["Name"])),
            "log_file_validation_enabled": validation_enabled,
        }
        if validation_enabled:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-05",
                "PASS",
                evidence,
                "Log file validation enabled on organization trail",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-05",
            "FAIL",
            evidence,
            "Log file validation disabled on organization trail",
        )

    checks["LOG-05"] = log05

    def log06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-06")

        org_trail = _log_organization_trail(trails)
        if org_trail is None:
            return ctx.results.audit_result(
                account_id, account_name, region, "LOG-06", "FAIL", None, "No organization CloudTrail trail found"
            )

        kms_key_id = _string(property_value(org_trail, ["KMSKeyId"])) if has_property(org_trail, "KMSKeyId") else ""
        evidence = {
            "trail_name": _string(property_value(org_trail, ["Name"])),
            "kms_key_id": kms_key_id if kms_key_id else None,
        }
        if kms_key_id.strip():
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-06",
                "PASS",
                evidence,
                "Organization CloudTrail encrypted with CMK",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-06",
            "FAIL",
            evidence,
            "Organization CloudTrail KMSKeyId is null",
        )

    checks["LOG-06"] = log06

    def log07(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-07")

        org_trail = _log_organization_trail(trails)
        if org_trail is None and collection_count(trails) > 0:
            org_trail = trails[0]

        bucket_name = _string(property_value(org_trail, ["S3BucketName"])) if org_trail else ""
        if not bucket_name:
            return ctx.results.audit_result(
                account_id, account_name, region, "LOG-07", "FAIL", None, "No CloudTrail log bucket configured"
            )

        sse_kms = _test_log_s3_bucket_sse_kms(ctx, bucket_name)
        public_blocked = _test_log_s3_bucket_public_access_blocked(ctx, bucket_name)
        versioning = _test_log_s3_bucket_versioning_enabled(ctx, bucket_name)
        cloudtrail_write_only = False
        policy_data = ctx.invoke_aws_cli(["s3api", "get-bucket-policy", "--bucket", bucket_name])
        if policy_data and has_property(policy_data, "Policy"):
            policy_text = str(property_value(policy_data, ["Policy"]) or "")
            if re.search(r"cloudtrail\.amazonaws\.com", policy_text) and not re.search(
                r'"Principal"\s*:\s*"\*"', policy_text
            ):
                cloudtrail_write_only = True
        evidence = {
            "bucket_name": bucket_name,
            "sse_kms": sse_kms,
            "public_blocked": public_blocked,
            "versioning": versioning,
            "cloudtrail_write_policy": cloudtrail_write_only,
        }
        if sse_kms and public_blocked and versioning and cloudtrail_write_only:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-07",
                "PASS",
                evidence,
                "Log bucket hardened with SSE-KMS, public access blocks, and versioning",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-07",
            "FAIL",
            evidence,
            "Log bucket missing one or more hardening controls",
        )

    checks["LOG-07"] = log07

    def log08(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-08")

        org_trail = _log_organization_trail(trails)
        if org_trail is None and collection_count(trails) > 0:
            org_trail = trails[0]

        bucket_name = _string(property_value(org_trail, ["S3BucketName"])) if org_trail else ""
        if not bucket_name:
            return ctx.results.audit_result(
                account_id, account_name, region, "LOG-08", "FAIL", None, "No CloudTrail log bucket configured"
            )

        lock_data = ctx.invoke_aws_cli(["s3api", "get-object-lock-configuration", "--bucket", bucket_name])
        if lock_data is None:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-08",
                "FAIL",
                {"bucket_name": bucket_name, "object_lock_enabled": False},
                "Object Lock not enabled on log bucket",
            )

        enabled = False
        mode: str | None = None
        retention: str | None = None
        lock_config = property_value(lock_data, ["ObjectLockConfiguration"])
        if isinstance(lock_config, dict):
            enabled_value = property_value(lock_config, ["ObjectLockEnabled"])
            if enabled_value is not None:
                enabled = _string(enabled_value) == "Enabled"
            rule = property_value(lock_config, ["Rule"])
            if isinstance(rule, dict):
                default_retention = property_value(rule, ["DefaultRetention"])
                if isinstance(default_retention, dict):
                    mode_value = property_value(default_retention, ["Mode"])
                    days_value = property_value(default_retention, ["Days"])
                    mode = _string(mode_value) if mode_value is not None else None
                    retention = _string(days_value) if days_value is not None and _string(days_value) else None

        evidence = {
            "bucket_name": bucket_name,
            "object_lock_enabled": enabled,
            "mode": mode,
            "retention_days": retention,
        }
        if enabled and mode in {"COMPLIANCE", "GOVERNANCE"}:
            return ctx.results.audit_result(
                account_id, account_name, region, "LOG-08", "PASS", evidence, "Object Lock enabled on log bucket"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "LOG-08", "FAIL", evidence, "Object Lock not enabled on log bucket"
        )

    checks["LOG-08"] = log08

    def log09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["logs", "describe-log-groups"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-09")

        log_groups = cli_array(property_value(data, ["logGroups"])) if has_property(data, "logGroups") else []
        null_retention_count = 0
        short_retention_count = 0
        null_retention_names: list[str] = []
        short_retention_names: list[str] = []

        for log_group in log_groups:
            has_retention = False
            retention_days = 0
            if has_property(log_group, "retentionInDays"):
                retention = property_value(log_group, ["retentionInDays"])
                if retention is not None:
                    has_retention = True
                    retention_days = int(retention)
            group_name = _string(property_value(log_group, ["logGroupName"]))
            if not has_retention:
                null_retention_count += 1
                if collection_count(null_retention_names) < 5:
                    null_retention_names.append(group_name)
            elif retention_days < 90:
                short_retention_count += 1
                if collection_count(short_retention_names) < 5:
                    short_retention_names.append(group_name)

        evidence = {
            "log_group_count": collection_count(log_groups),
            "null_retention_count": null_retention_count,
            "short_retention_count": short_retention_count,
            "null_retention_names": list(null_retention_names),
            "short_retention_names": list(short_retention_names),
        }
        if null_retention_count == 0 and short_retention_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-09",
                "PASS",
                evidence,
                "All log groups have retention configured",
            )
        if short_retention_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-09",
                "FAIL",
                evidence,
                "One or more log groups have retention below 90 days",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "LOG-09", "FAIL", evidence, "One or more log groups have null retention"
        )

    checks["LOG-09"] = log09

    def log10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["logs", "describe-log-groups"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-10")

        cloudtrail_groups: list[str] = []
        flow_log_groups: list[str] = []
        groups_without_kms: list[str] = []
        if has_property(data, "logGroups"):
            for log_group in cli_array(property_value(data, ["logGroups"])):
                name = _string(property_value(log_group, ["logGroupName"]))
                lower_name = name.lower()
                kms_key = _string(property_value(log_group, ["kmsKeyId"]))
                if re.search(r"cloudtrail|aws-cloudtrail", lower_name):
                    cloudtrail_groups.append(name)
                    if not kms_key:
                        groups_without_kms.append(name)
                if re.search(r"flow|vpc", lower_name):
                    flow_log_groups.append(name)
                    if not kms_key:
                        groups_without_kms.append(name)

        evidence = {
            "cloudtrail_log_groups": list(cloudtrail_groups),
            "flow_log_groups": list(flow_log_groups),
            "groups_without_kms": list(groups_without_kms[:10]),
        }
        if collection_count(groups_without_kms) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-10",
                "PARTIAL",
                evidence,
                "Critical log groups found but some lack kmsKeyId encryption",
            )
        if collection_count(cloudtrail_groups) > 0 and collection_count(flow_log_groups) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-10",
                "PASS",
                evidence,
                "CloudTrail and VPC Flow Logs log groups found",
            )
        if collection_count(cloudtrail_groups) > 0 or collection_count(flow_log_groups) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-10",
                "PARTIAL",
                evidence,
                "Only CloudTrail or VPC Flow Logs log group found",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "LOG-10", "FAIL", evidence, "No critical log groups found"
        )

    checks["LOG-10"] = log10

    def log11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-11")

        org_trail = _log_organization_trail(trails)
        if org_trail is None and collection_count(trails) > 0:
            org_trail = trails[0]

        bucket_name = _string(property_value(org_trail, ["S3BucketName"])) if org_trail else ""
        if not bucket_name:
            return ctx.results.audit_result(
                account_id, account_name, region, "LOG-11", "FAIL", None, "No CloudTrail log bucket configured"
            )

        public_read = _test_log_bucket_policy_public_read(ctx, bucket_name)
        delete_allowed = False
        policy_data = ctx.invoke_aws_cli(["s3api", "get-bucket-policy", "--bucket", bucket_name])
        if policy_data and has_property(policy_data, "Policy"):
            policy_text = str(property_value(policy_data, ["Policy"]) or "")
            if re.search(r"s3:DeleteObject", policy_text, re.IGNORECASE):
                delete_allowed = True
        evidence = {
            "bucket_name": bucket_name,
            "public_read_allow": public_read,
            "delete_object_allowed": delete_allowed,
        }
        if public_read or delete_allowed:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-11",
                "FAIL",
                evidence,
                "Log bucket policy allows public read or object deletion",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-11",
            "PASS",
            evidence,
            "No public read access found on log bucket policy",
        )

    checks["LOG-11"] = log11

    def log12(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        vpc_data = ctx.invoke_aws_cli(["ec2", "describe-vpcs"])
        flow_data = ctx.invoke_aws_cli(["ec2", "describe-flow-logs"])
        if vpc_data is None or flow_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-12")

        vpcs = cli_array(property_value(vpc_data, ["Vpcs"])) if has_property(vpc_data, "Vpcs") else []
        flow_logs = cli_array(property_value(flow_data, ["FlowLogs"])) if has_property(flow_data, "FlowLogs") else []

        vpc_with_all_flow_logs: dict[str, bool] = {}
        vpc_with_partial_flow_logs: dict[str, str] = {}
        for flow_log in flow_logs:
            if _string(property_value(flow_log, ["FlowLogStatus"])) != "ACTIVE":
                continue
            if not has_property(flow_log, "ResourceId"):
                continue
            resource_id = _string(property_value(flow_log, ["ResourceId"]))
            traffic_type = _string(property_value(flow_log, ["TrafficType"]))
            if traffic_type == "ALL":
                vpc_with_all_flow_logs[resource_id] = True
            else:
                vpc_with_partial_flow_logs[resource_id] = traffic_type

        missing_vpc_ids: list[str] = []
        partial_vpc_ids: list[str] = []
        for vpc in vpcs:
            vpc_id = _string(property_value(vpc, ["VpcId"]))
            if vpc_id in vpc_with_all_flow_logs:
                continue
            if vpc_id in vpc_with_partial_flow_logs:
                if collection_count(partial_vpc_ids) < 10:
                    partial_vpc_ids.append(vpc_id)
                continue
            if collection_count(missing_vpc_ids) < 10:
                missing_vpc_ids.append(vpc_id)

        evidence = {
            "vpc_count": collection_count(vpcs),
            "vpcs_with_all_flow_logs": len(vpc_with_all_flow_logs),
            "missing_vpc_ids": list(missing_vpc_ids),
            "partial_traffic_vpc_ids": list(partial_vpc_ids),
        }
        if collection_count(missing_vpc_ids) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-12",
                "FAIL",
                evidence,
                "One or more VPCs missing active Flow Logs",
            )
        if collection_count(partial_vpc_ids) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-12",
                "PARTIAL",
                evidence,
                "Flow Logs exist but TrafficType is not ALL on some VPCs",
            )
        if collection_count(vpcs) == 0:
            return ctx.results.not_applicable_no_resources(
                account_id, account_name, region, "LOG-12", evidence, "No resources found"
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-12",
            "PASS",
            evidence,
            "All VPCs have active Flow Logs with TrafficType=ALL",
        )

    checks["LOG-12"] = log12

    def _log_alb_access_log_evidence(ctx: CheckContext) -> dict[str, Any]:
        lb_data = ctx.invoke_aws_cli(["elbv2", "describe-load-balancers"])
        if lb_data is None:
            return {"api_available": False, "alb_count": 0, "with_access_logs": 0, "without_access_logs": []}

        load_balancers = (
            cli_array(property_value(lb_data, ["LoadBalancers"])) if has_property(lb_data, "LoadBalancers") else []
        )
        with_access_logs = 0
        without_access_logs: list[str] = []
        for load_balancer in load_balancers:
            lb_arn = _string(property_value(load_balancer, ["LoadBalancerArn"]))
            lb_name = _string(property_value(load_balancer, ["LoadBalancerName"]))
            if not lb_arn:
                continue
            attr_data = ctx.invoke_aws_cli(
                ["elbv2", "describe-load-balancer-attributes", "--load-balancer-arn", lb_arn]
            )
            enabled = False
            if attr_data is not None and has_property(attr_data, "Attributes"):
                for attribute in cli_array(property_value(attr_data, ["Attributes"])):
                    key = _string(property_value(attribute, ["Key"]))
                    value = _string(property_value(attribute, ["Value"]))
                    if key == "access_logs.s3.enabled" and value == "true":
                        enabled = True
                        break
            if enabled:
                with_access_logs += 1
            elif collection_count(without_access_logs) < 10:
                without_access_logs.append(lb_name)
        return {
            "api_available": True,
            "alb_count": collection_count(load_balancers),
            "with_access_logs": with_access_logs,
            "without_access_logs": list(without_access_logs),
        }

    def _log_waf_logging_evidence(ctx: CheckContext, scope: str) -> dict[str, Any]:
        data = ctx.invoke_aws_cli(["wafv2", "list-web-acls", "--scope", scope])
        if data is None:
            return {
                "api_available": False,
                "scope": scope,
                "web_acl_count": 0,
                "with_logging": 0,
                "without_logging": [],
            }

        web_acls = cli_array(property_value(data, ["WebACLs"])) if has_property(data, "WebACLs") else []
        with_logging = 0
        without_logging: list[str] = []
        for web_acl in web_acls:
            acl_name = _string(property_value(web_acl, ["Name"]))
            acl_arn = _string(property_value(web_acl, ["ARN"]))
            if not acl_arn:
                continue
            logging_data = ctx.invoke_aws_cli(["wafv2", "get-logging-configuration", "--resource-arn", acl_arn])
            destinations = []
            if logging_data is not None and has_property(logging_data, "LoggingConfiguration"):
                destinations = cli_array(
                    property_value(property_value(logging_data, ["LoggingConfiguration"]), ["LogDestinationConfigs"])
                )
            if collection_count(destinations) > 0:
                with_logging += 1
            elif collection_count(without_logging) < 10:
                without_logging.append(acl_name)
        return {
            "api_available": True,
            "scope": scope,
            "web_acl_count": collection_count(web_acls),
            "with_logging": with_logging,
            "without_logging": list(without_logging),
        }

    def _log_cloudfront_logging_evidence(ctx: CheckContext) -> dict[str, Any]:
        data = ctx.invoke_aws_cli(["cloudfront", "list-distributions"])
        if data is None:
            return {"api_available": False, "distribution_count": 0, "with_logging": 0, "without_logging": []}

        items: list[dict[str, Any]] = []
        if has_property(data, "DistributionList") and has_property(property_value(data, ["DistributionList"]), ["Items"]):
            items = [
                item
                for item in cli_array(property_value(property_value(data, ["DistributionList"]), ["Items"]))
                if isinstance(item, dict)
            ]
        with_logging = 0
        without_logging: list[str] = []
        for distribution in items:
            domain_name = _string(property_value(distribution, ["DomainName"]))
            logging_config = property_value(distribution, ["Logging"])
            enabled = _truthy(property_value(logging_config, ["Enabled"])) if isinstance(logging_config, dict) else False
            if enabled:
                with_logging += 1
            elif collection_count(without_logging) < 10:
                without_logging.append(domain_name)
        return {
            "api_available": True,
            "distribution_count": collection_count(items),
            "with_logging": with_logging,
            "without_logging": list(without_logging),
        }

    def log13(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        alb_evidence = _log_alb_access_log_evidence(ctx)
        waf_regional_evidence = _log_waf_logging_evidence(ctx, "REGIONAL")
        waf_cloudfront_evidence = _log_waf_logging_evidence(ctx, "CLOUDFRONT")
        cloudfront_evidence = _log_cloudfront_logging_evidence(ctx)

        if (
            not alb_evidence["api_available"]
            and not waf_regional_evidence["api_available"]
            and not waf_cloudfront_evidence["api_available"]
            and not cloudfront_evidence["api_available"]
        ):
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-13")

        resource_counts = {
            "alb_count": alb_evidence["alb_count"],
            "regional_waf_count": waf_regional_evidence["web_acl_count"],
            "cloudfront_waf_count": waf_cloudfront_evidence["web_acl_count"],
            "cloudfront_distribution_count": cloudfront_evidence["distribution_count"],
        }
        evidence = {
            "resource_counts": resource_counts,
            "alb_access_logs": alb_evidence,
            "waf_regional_logging": waf_regional_evidence,
            "waf_cloudfront_logging": waf_cloudfront_evidence,
            "cloudfront_logging": cloudfront_evidence,
        }
        if sum(resource_counts.values()) == 0:
            return ctx.results.not_applicable_no_resources(account_id, account_name, region, "LOG-13", evidence)

        issues: list[str] = []
        if alb_evidence["alb_count"] > 0 and collection_count(alb_evidence["without_access_logs"]) > 0:
            issues.append("ALB access logs missing")
        if (
            waf_regional_evidence["web_acl_count"] > 0
            and collection_count(waf_regional_evidence["without_logging"]) > 0
        ):
            issues.append("Regional WAF logging missing")
        if (
            waf_cloudfront_evidence["web_acl_count"] > 0
            and collection_count(waf_cloudfront_evidence["without_logging"]) > 0
        ):
            issues.append("CloudFront WAF logging missing")
        if (
            cloudfront_evidence["distribution_count"] > 0
            and collection_count(cloudfront_evidence["without_logging"]) > 0
        ):
            issues.append("CloudFront access logging missing")

        if collection_count(issues) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-13",
                "FAIL",
                evidence,
                "; ".join(issues),
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-13",
            "PASS",
            evidence,
            "ALB, WAF and CloudFront logging requirements are satisfied for in-scope resources",
        )

    checks["LOG-13"] = log13

    def log14(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        rules_data = ctx.invoke_aws_cli(["events", "list-rules"])
        alarms_data = ctx.invoke_aws_cli(["cloudwatch", "describe-alarms"])
        if rules_data is None and alarms_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-14")

        iam_patterns = r"CreateUser|DeleteUser|DeleteRole|AttachRolePolicy|DeactivateMFADevice|ConsoleLogin|CreateAccessKey|Root|iam\.amazonaws\.com"
        matching_rules: list[str] = []
        matching_alarms: list[str] = []

        if rules_data is not None and has_property(rules_data, "Rules"):
            for rule in cli_array(property_value(rules_data, ["Rules"])):
                rule_name = _string(property_value(rule, ["Name"]))
                event_pattern = _string(property_value(rule, ["EventPattern"]))
                if re.search(iam_patterns, event_pattern) or re.search(r"IAM|Root|ConsoleLogin", rule_name):
                    matching_rules.append(rule_name)

        if alarms_data is not None and has_property(alarms_data, "MetricAlarms"):
            for alarm in cli_array(property_value(alarms_data, ["MetricAlarms"])):
                alarm_name = _string(property_value(alarm, ["AlarmName"]))
                if re.search(r"IAM|Root|ConsoleLogin|CreateUser|DeleteUser|CreateAccessKey", alarm_name):
                    matching_alarms.append(alarm_name)

        evidence = {"matching_rule_names": list(matching_rules), "matching_alarm_names": list(matching_alarms)}
        if collection_count(matching_rules) > 0 or collection_count(matching_alarms) > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "LOG-14", "PASS", evidence, "IAM alerting rules or alarms found"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "LOG-14", "FAIL", evidence, "No IAM alerting rules or alarms found"
        )

    checks["LOG-14"] = log14

    def log15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-15")

        log_group_name: str | None = None
        for trail in trails:
            log_group_name = _log_cloudtrail_log_group_name(trail)
            if log_group_name:
                break

        if not log_group_name:
            log_group_data = ctx.invoke_aws_cli(["logs", "describe-log-groups"])
            if log_group_data is not None and has_property(log_group_data, "logGroups"):
                for log_group in cli_array(property_value(log_group_data, ["logGroups"])):
                    name = _string(property_value(log_group, ["logGroupName"]))
                    if re.search(r"CloudTrail|cloudtrail", name):
                        log_group_name = name
                        break

        if not log_group_name:
            return ctx.results.audit_result(
                account_id, account_name, region, "LOG-15", "FAIL", None, "CloudTrail log group not found"
            )

        assessment = _log_cis_metric_filter_assessment(ctx, log_group_name)
        if assessment is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-15")

        required_cis_ids = ("CIS-3.5", "CIS-3.8")
        missing_required: list[str] = []
        matched_list = list(cli_array(assessment.get("matched_patterns")))
        for cis_id in required_cis_ids:
            if cis_id not in matched_list:
                missing_required.append(cis_id)

        evidence = {
            "log_group_name": log_group_name,
            "matched_count": assessment["matched_count"],
            "missing_patterns": list(cli_array(assessment.get("missing_patterns"))),
            "matched_patterns": list(cli_array(assessment.get("matched_patterns"))),
            "missing_required_patterns": list(missing_required),
        }
        if collection_count(missing_required) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-15",
                "FAIL",
                evidence,
                "One or more required CloudTrail protection patterns are missing from metric filters",
            )
        matched_count = int(assessment.get("matched_count", 0))
        if matched_count >= 10:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-15",
                "PASS",
                evidence,
                "Ten or more CIS metric filter patterns matched",
            )
        if matched_count >= 5:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-15",
                "PARTIAL",
                evidence,
                "Five to nine CIS metric filter patterns matched",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-15",
            "FAIL",
            evidence,
            "Fewer than five CIS metric filter patterns matched",
        )

    checks["LOG-15"] = log15
    checks["LOG-16"] = workshop(
        "LOG-16",
        "Verify analysts can query CloudTrail via Athena, CloudTrail Lake, or QRadar. Check investigation time SLA.",
    )
    checks["LOG-17"] = workshop(
        "LOG-17", "Verify log freeze procedure exists for incident evidence preservation. Check forensics policy."
    )
    checks["LOG-18"] = workshop(
        "LOG-18",
        "Verify SOC runbooks reference CloudTrail, VPC Flow Logs, WAF for incident investigation. Check DEX.",
    )
    checks["LOG-19"] = workshop(
        "LOG-19", "Verify periodic tests confirm alarms trigger correctly. Ask for last test date and results."
    )

    def log20(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trails = _log_cloud_trails(ctx)
        if trails is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-20")

        bucket_names: list[str] = []
        prefixes: list[str] = []
        for trail in trails:
            if has_property(trail, "S3BucketName"):
                bucket = _string(property_value(trail, ["S3BucketName"]))
                if bucket and bucket not in bucket_names:
                    bucket_names.append(bucket)
            if has_property(trail, "S3KeyPrefix"):
                prefix = _string(property_value(trail, ["S3KeyPrefix"]))
                if prefix and prefix not in prefixes:
                    prefixes.append(prefix)

        account_lower = account_name.lower()
        is_prod = bool(re.search(r"prod", account_lower))
        is_nonprod = bool(re.search(r"dev|test|uat|sandbox|nonprod|non-prod|shared", account_lower))
        evidence = {
            "account_name": account_name,
            "bucket_names": list(bucket_names),
            "s3_prefixes": list(prefixes),
            "appears_prod": is_prod,
            "appears_nonprod": is_nonprod,
        }
        if collection_count(bucket_names) > 1:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-20",
                "PASS",
                evidence,
                "Distinct CloudTrail log buckets found in account",
            )
        if collection_count(bucket_names) == 1 and collection_count(prefixes) > 1:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-20",
                "PARTIAL",
                evidence,
                "Same bucket with different prefixes may separate environments",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-20",
            "PARTIAL",
            evidence,
            "Cross-account prod/non-prod bucket separation requires aggregate review across accounts",
        )

    checks["LOG-20"] = log20

    def log21(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["events", "list-rules"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "LOG-21")

        matched_rules: list[str] = []
        rules_without_targets: list[str] = []
        if has_property(data, "Rules"):
            for rule in cli_array(property_value(data, ["Rules"])):
                if not isinstance(rule, dict):
                    continue
                rule_name = str(property_value(rule, ["Name"]) or "")
                event_pattern = str(property_value(rule, ["EventPattern"]) or "")
                if not re.search(r"DeleteLogGroup|PutRetentionPolicy", event_pattern):
                    continue
                matched_rules.append(rule_name)
                target_data = ctx.invoke_aws_cli(["events", "list-targets-by-rule", "--rule", rule_name])
                has_target = False
                if target_data and has_property(target_data, "Targets"):
                    for target in cli_array(property_value(target_data, ["Targets"])):
                        target_arn = str(property_value(target, ["Arn"]) or "")
                        if re.search(r":sns:|:lambda:|:sqs:", target_arn):
                            has_target = True
                            break
                if not has_target:
                    rules_without_targets.append(rule_name)

        evidence = {
            "log_deletion_rule_count": collection_count(matched_rules),
            "matched_rules": list(matched_rules[:10]),
            "rules_without_targets": list(rules_without_targets[:10]),
        }
        if collection_count(matched_rules) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-21",
                "FAIL",
                evidence,
                "No EventBridge rules found for DeleteLogGroup or PutRetentionPolicy",
            )
        if collection_count(rules_without_targets) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "LOG-21",
                "PARTIAL",
                evidence,
                "Log deletion rules exist but some have no SNS, Lambda or SQS targets",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "LOG-21",
            "PASS",
            evidence,
            "EventBridge rules alert on CloudWatch log group deletion or retention changes",
        )

    checks["LOG-21"] = log21
    checks["LOG-22"] = workshop(
        "LOG-22",
        "Verify logs are queryable and exportable for external audit: Athena/CloudTrail Lake, S3 export, SIEM integration and retention compliance.",
    )

    return DomainModule(code="LOG", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
