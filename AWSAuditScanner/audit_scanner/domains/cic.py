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

    def cic01(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        stack_count = _get_cic_cloudformation_stack_count(ctx)
        if stack_count is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-01")
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-01",
            "PARTIAL",
            {"stack_count": stack_count},
            "IaC-only deployment to verify during workshop. Verify no untracked console-created resources.",
        )

    checks["CIC-01"] = cic01
    checks["CIC-02"] = workshop("CIC-02", "Verify IaC repos versioned via GitLab tags/releases.")
    checks["CIC-03"] = workshop("CIC-03", "Verify merge request process with peer review. Check GitLab branch protection.")
    checks["CIC-04"] = workshop("CIC-04", "Verify separate pipeline definitions for prod vs non-prod.")

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
                "FAIL",
                evidence,
                "SSM String parameters or IAM access keys found",
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
    checks["CIC-08"] = workshop("CIC-08", "GitLab Ultimate enforcement planned October 2026. Verify current status.")

    def cic09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        bucket_names = _get_cic_s3_bucket_names(ctx)
        if bucket_names is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-09")

        state_buckets: list[str] = []
        for bucket_name in bucket_names:
            if re.search(r"tfstate|terraform|iac-state|cloudformation", bucket_name.lower()):
                state_buckets.append(bucket_name)

        if collection_count(state_buckets) == 0:
            stack_count = _get_cic_cloudformation_stack_count(ctx)
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-09",
                "PARTIAL",
                {
                    "state_bucket_count": 0,
                    "stack_count": stack_count,
                },
                "CloudFormation used (stateless) or state bucket not identified by naming",
            )

        bucket_evidence: list[dict[str, object]] = []
        all_pass = True
        for bucket_name in state_buckets:
            encrypted = _test_cic_s3_bucket_encrypted(ctx, bucket_name)
            private = _test_cic_s3_bucket_public_access_blocked(ctx, bucket_name)
            versioned = _test_cic_s3_bucket_versioning_enabled(ctx, bucket_name)
            bucket_evidence.append(
                {
                    "bucket_name": bucket_name,
                    "encrypted": encrypted,
                    "public_blocked": private,
                    "versioning": versioned,
                }
            )
            if not (encrypted and private and versioned):
                all_pass = False

        evidence = {
            "state_bucket_count": collection_count(state_buckets),
            "buckets": list(bucket_evidence),
        }
        if all_pass:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-09",
                "PASS",
                evidence,
                "IaC state bucket encrypted, private, and versioned",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-09",
            "FAIL",
            evidence,
            "IaC state bucket missing encryption, public access blocks, or versioning",
        )

    checks["CIC-09"] = cic09

    def cic10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        end_time = datetime.now(timezone.utc).isoformat()
        start_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        data = ctx.invoke_aws_cli(
            [
                "cloudtrail",
                "lookup-events",
                "--lookup-attributes",
                "AttributeKey=EventSource,AttributeValue=cloudformation.amazonaws.com",
                "--start-time",
                start_time,
                "--end-time",
                end_time,
                "--max-results",
                "50",
            ]
        )
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-10")

        event_count = 0
        if has_property(data, "Events"):
            event_count = collection_count(property_value(data, ["Events"]))
        evidence = {"cloudformation_event_count_last_30_days": event_count}
        if event_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-10",
                "PASS",
                evidence,
                "CloudFormation events visible in CloudTrail",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-10",
            "FAIL",
            evidence,
            "No CloudFormation events found in CloudTrail sample",
        )

    checks["CIC-10"] = cic10
    checks["CIC-11"] = workshop("CIC-11", "Verify rollback procedure exists and has been tested.")

    def cic12(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        status_data = ctx.invoke_aws_cli(["config", "describe-configuration-recorder-status"])
        recorder_data = ctx.invoke_aws_cli(["config", "describe-configuration-recorders"])
        if status_data is None and recorder_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-12")

        recorder_active = False
        recorder_names: list[str] = []
        if status_data and has_property(status_data, "ConfigurationRecordersStatus"):
            for status in cli_array(property_value(status_data, ["ConfigurationRecordersStatus"])):
                if has_property(status, "name"):
                    recorder_names.append(str(property_value(status, ["name"]) or ""))
                if property_value(status, ["recording"]) is True:
                    recorder_active = True

        resource_types: list[str] = []
        if recorder_data and has_property(recorder_data, "ConfigurationRecorders"):
            for recorder in cli_array(property_value(recorder_data, ["ConfigurationRecorders"])):
                recording_group = property_value(recorder, ["recordingGroup"])
                if recording_group and property_value(recording_group, ["allSupported"]) is True:
                    resource_types.append("ALL_SUPPORTED")
                elif recording_group and has_property(recording_group, "resourceTypes"):
                    for resource_type in cli_array(property_value(recording_group, ["resourceTypes"])):
                        resource_types.append(str(resource_type))

        evidence = {
            "recorder_active": recorder_active,
            "recorder_names": list(recorder_names),
            "resource_types": list(resource_types),
        }
        if recorder_active:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-12",
                "PASS",
                evidence,
                "AWS Config recorder is active for drift detection",
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

    def cic15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        end_time = datetime.now(timezone.utc).isoformat()
        start_time = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        data = ctx.invoke_aws_cli(
            [
                "cloudtrail",
                "lookup-events",
                "--start-time",
                start_time,
                "--end-time",
                end_time,
                "--max-results",
                "50",
            ]
        )
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-15")

        sampled_event_count = 0
        console_like_events = 0
        sample_event_names: list[str] = []
        if has_property(data, "Events"):
            events = cli_array(property_value(data, ["Events"]))
            sampled_event_count = collection_count(events)
            for event in events:
                event_text = str(property_value(event, ["CloudTrailEvent"]) or "")
                if re.search(r"console\.amazonaws\.com|AWS Console|Console", event_text):
                    console_like_events += 1
                    if collection_count(sample_event_names) < 5 and has_property(event, "EventName"):
                        sample_event_names.append(str(property_value(event, ["EventName"]) or ""))

        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-15",
            "PARTIAL",
            {
                "sampled_event_count": sampled_event_count,
                "console_like_events": console_like_events,
                "sample_event_names": list(sample_event_names),
            },
            "Manual actions allowed but tracked via CloudTrail. Verify IaC enforcement policy.",
        )

    checks["CIC-15"] = cic15
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
                if not re.search(r"pipeline|codebuild|codepipeline|gitlab|ci/|/ci", name.lower()):
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
                "No pipeline-related log groups identified by naming",
            )
        if collection_count(groups_without_retention) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-17",
                "PASS",
                evidence,
                "Pipeline log groups have retention configured",
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
        end_time = datetime.now(timezone.utc).isoformat()
        start_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        data = ctx.invoke_aws_cli(
            [
                "cloudtrail",
                "lookup-events",
                "--lookup-attributes",
                "AttributeKey=EventSource,AttributeValue=codepipeline.amazonaws.com",
                "--start-time",
                start_time,
                "--end-time",
                end_time,
                "--max-results",
                "50",
            ]
        )
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "CIC-19")

        event_count = 0
        if has_property(data, "Events"):
            event_count = collection_count(property_value(data, ["Events"]))
        evidence = {"pipeline_event_count_last_30_days": event_count}
        if event_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "CIC-19",
                "PASS",
                evidence,
                "CodePipeline events visible in CloudTrail",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "CIC-19",
            "FAIL",
            evidence,
            "No CodePipeline events found in CloudTrail sample",
        )

    checks["CIC-19"] = cic19

    return DomainModule(code="CIC", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
