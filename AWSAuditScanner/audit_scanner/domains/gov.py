"""GOV domain controls."""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "GOV-01": "P0",
    "GOV-02": "P0",
    "GOV-03": "P0",
    "GOV-04": "P0",
    "GOV-05": "P0",
    "GOV-06": "P0",
    "GOV-07": "P1",
    "GOV-08": "P2",
    "GOV-09": "P0",
    "GOV-10": "P0",
    "GOV-11": "P0",
    "GOV-12": "P0",
    "GOV-13": "P1",
    "GOV-14": "P0",
    "GOV-15": "P0",
    "GOV-16": "P1",
    "GOV-17": "P0",
    "GOV-18": "P0",
    "GOV-19": "P0",
    "GOV-20": "P0",
}


def _gov_scp_summaries(ctx: CheckContext) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["organizations", "list-policies", "--filter", "SERVICE_CONTROL_POLICY"])
    if data is None:
        return None
    if has_property(data, "Policies"):
        return [item for item in cli_array(property_value(data, ["Policies"])) if isinstance(item, dict)]
    return []


def _gov_policy_document_text(ctx: CheckContext, policy_id: str) -> str | None:
    data = ctx.invoke_aws_cli(["organizations", "describe-policy", "--policy-id", policy_id])
    if data is None:
        return None
    if not has_property(data, "Policy"):
        return None
    policy = property_value(data, ["Policy"])
    if not isinstance(policy, dict):
        return None
    if not has_property(policy, "Content"):
        return None
    content = property_value(policy, ["Content"])
    if content is None:
        return None
    return str(content)


def _gov_tagged_resource_stats(ctx: CheckContext) -> dict[str, Any] | None:
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
            for resource in cli_array(property_value(data, ["ResourceTagMappingList"])):
                if isinstance(resource, dict):
                    resources.append(resource)
        pagination_token = None
        if has_property(data, "PaginationToken"):
            token_text = str(property_value(data, ["PaginationToken"]) or "")
            if token_text.strip():
                pagination_token = token_text
        if not pagination_token:
            break
    total_count = collection_count(resources)
    owner_tagged_count = 0
    for resource in resources:
        has_owner_tag = False
        if has_property(resource, "Tags"):
            for tag in cli_array(property_value(resource, ["Tags"])):
                if not isinstance(tag, dict):
                    continue
                key = str(property_value(tag, ["Key"]) or "")
                if key in ("Owner", "owner"):
                    value = str(property_value(tag, ["Value"]) or "")
                    if value.strip():
                        has_owner_tag = True
                        break
        if has_owner_tag:
            owner_tagged_count += 1
    percent_with_owner = 0.0
    if total_count > 0:
        percent_with_owner = round((owner_tagged_count / total_count) * 100, 2)
    return {
        "total_resources": total_count,
        "resources_with_owner": owner_tagged_count,
        "percent_with_owner": percent_with_owner,
    }


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(cid: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, cid, notes)

        return _check

    checks["GOV-01"] = workshop(
        "GOV-01",
        "Verify a cloud governance framework exists: policies, roles, RACI, change management and compliance scope.",
    )
    checks["GOV-02"] = workshop(
        "GOV-02", "Verify RACI matrix exists covering AWS/CCoE/Clients per domain. Check DEX/DAT documentation."
    )
    checks["GOV-03"] = workshop(
        "GOV-03", "Verify RACI Build/Run/Sec document exists and is current. Check Confluence."
    )
    checks["GOV-04"] = workshop(
        "GOV-04", "Verify RSIS policies exist covering IAM, network, logging, data, backups, CI/CD. Check Confluence."
    )

    def gov05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = ctx.results.global_control_gate(account_id, account_name, region, "GOV-05")
        if gate:
            return gate
        scps = _gov_scp_summaries(ctx)
        if scps is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "GOV-05")
        policy_names: list[str] = []
        for policy in scps:
            if has_property(policy, "Name"):
                policy_names.append(str(property_value(policy, ["Name"]) or ""))
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "GOV-05",
            "PARTIAL",
            {"scp_count": collection_count(scps), "policy_names": list(policy_names)},
            "Verify derogation process and exception registry during workshop.",
        )

    checks["GOV-05"] = gov05

    def gov06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        event_count = 0
        for event_name in (
            "CreateStack",
            "UpdateStack",
            "DeleteStack",
            "CreateChangeSet",
            "ExecuteChangeSet",
        ):
            data = ctx.invoke_aws_cli(
                [
                    "cloudtrail",
                    "lookup-events",
                    "--lookup-attributes",
                    f"AttributeKey=EventName,AttributeValue={event_name}",
                    "--max-results",
                    "20",
                ]
            )
            if data is None:
                continue
            if has_property(data, "Events"):
                event_count += collection_count(property_value(data, ["Events"]))
        if event_count == 0:
            data = ctx.invoke_aws_cli(
                [
                    "cloudtrail",
                    "lookup-events",
                    "--lookup-attributes",
                    "AttributeKey=EventName,AttributeValue=UpdateTrail",
                    "--max-results",
                    "20",
                ]
            )
            if data is None:
                return ctx.results.null_api_partial(account_id, account_name, region, "GOV-06")
            if has_property(data, "Events"):
                event_count = collection_count(property_value(data, ["Events"]))
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "GOV-06",
            "PARTIAL",
            {"change_event_count": event_count},
            "RFC/CAB process must be verified during workshop.",
        )

    checks["GOV-06"] = gov06

    def gov07(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        stats = _gov_tagged_resource_stats(ctx)
        if stats is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "GOV-07")
        evidence = {
            "total_resources": stats["total_resources"],
            "resources_with_owner": stats["resources_with_owner"],
            "percent_with_owner": stats["percent_with_owner"],
        }
        if stats["total_resources"] == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-07",
                "PARTIAL",
                evidence,
                "No taggable resources returned for inventory assessment",
            )
        if stats["percent_with_owner"] > 80:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-07",
                "PASS",
                evidence,
                "More than 80% of resources have an Owner tag",
            )
        if stats["percent_with_owner"] < 50:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-07",
                "FAIL",
                evidence,
                "Less than 50% of resources have an Owner tag",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "GOV-07",
            "PARTIAL",
            evidence,
            "Between 50% and 80% of resources have an Owner tag",
        )

    checks["GOV-07"] = gov07

    def gov08(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = ctx.results.global_control_gate(account_id, account_name, region, "GOV-08")
        if gate:
            return gate
        tag_policy_data = ctx.invoke_aws_cli(["organizations", "list-policies", "--filter", "TAG_POLICY"])
        if tag_policy_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "GOV-08")
        tag_policies: list[dict[str, Any]] = []
        if has_property(tag_policy_data, "Policies"):
            tag_policies = [item for item in cli_array(property_value(tag_policy_data, ["Policies"])) if isinstance(item, dict)]
        tag_policy_names: list[str] = []
        for policy in tag_policies:
            policy_id = str(property_value(policy, ["Id"]) or "")
            policy_detail = None
            if policy_id.strip():
                policy_detail = ctx.invoke_aws_cli(["organizations", "describe-policy", "--policy-id", policy_id])
            if policy_detail and has_property(policy_detail, "Policy"):
                detail_policy = property_value(policy_detail, ["Policy"])
                if isinstance(detail_policy, dict) and has_property(detail_policy, "Name"):
                    tag_policy_names.append(str(property_value(detail_policy, ["Name"]) or ""))
                    continue
            if has_property(policy, "Name"):
                tag_policy_names.append(str(property_value(policy, ["Name"]) or ""))
        if collection_count(tag_policy_names) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-08",
                "PASS",
                {"tag_policy_count": collection_count(tag_policy_names), "policy_names": list(tag_policy_names)},
                "Tag policy exists at organization level",
            )
        scps = _gov_scp_summaries(ctx)
        if scps is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "GOV-08")
        tag_related_scp_count = 0
        for scp in scps:
            if not has_property(scp, "Id"):
                continue
            content = _gov_policy_document_text(ctx, str(property_value(scp, ["Id"]) or ""))
            if content is None:
                continue
            if re.search(r"aws:TagKeys|aws:RequestTag|aws:ResourceTag|tag", content):
                tag_related_scp_count += 1
        if tag_related_scp_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-08",
                "PARTIAL",
                {
                    "tag_policy_count": 0,
                    "tag_related_scp_count": tag_related_scp_count,
                    "scp_count": collection_count(scps),
                },
                "Tags exist via SCP but no formal tag policy",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "GOV-08",
            "FAIL",
            {"tag_policy_count": 0, "tag_related_scp_count": 0, "scp_count": collection_count(scps)},
            "No tag governance found",
        )

    checks["GOV-08"] = gov08
    checks["GOV-09"] = workshop(
        "GOV-09", "Verify risk analysis document exists for AWS socle. Ask for last review date."
    )
    checks["GOV-10"] = workshop(
        "GOV-10",
        "Verify cloud security baseline and hardening standards are documented and communicated.",
    )

    def gov11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = ctx.results.global_control_gate(account_id, account_name, region, "GOV-11")
        if gate:
            return gate
        scps = _gov_scp_summaries(ctx)
        if scps is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "GOV-11")
        if collection_count(scps) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "GOV-11", "FAIL", {"scp_count": 0, "targets": []}, "No SCPs found"
            )
        targets_evidence: list[dict[str, Any]] = []
        has_root_or_ou_target = False
        deny_root_scp_count = 0
        deny_iam_scp_count = 0
        for scp in scps:
            if not has_property(scp, "Id"):
                continue
            policy_id = str(property_value(scp, ["Id"]) or "")
            content = _gov_policy_document_text(ctx, policy_id)
            if content:
                if re.search(r"organizations:LeaveOrganization|organizations:DeleteOrganization", content):
                    deny_root_scp_count += 1
                if re.search(r"iam:CreateUser|iam:CreateAccessKey|iam:CreateLoginProfile", content):
                    deny_iam_scp_count += 1
            target_data = ctx.invoke_aws_cli(
                [
                    "organizations",
                    "list-targets-for-policy",
                    "--policy-id",
                    str(property_value(scp, ["Id"]) or ""),
                ]
            )
            if target_data is None or not has_property(target_data, "Targets"):
                continue
            for target in cli_array(property_value(target_data, ["Targets"])):
                if not isinstance(target, dict):
                    continue
                target_type = None
                if has_property(target, "Type"):
                    target_type = str(property_value(target, ["Type"]) or "")
                targets_evidence.append(
                    {
                        "policy_id": str(property_value(scp, ["Id"]) or ""),
                        "policy_name": str(property_value(scp, ["Name"]) or ""),
                        "target_id": str(property_value(target, ["TargetId"]) or ""),
                        "target_type": target_type,
                        "target_name": str(property_value(target, ["Name"]) or ""),
                    }
                )
                if target_type in ("ROOT", "ORGANIZATIONAL_UNIT"):
                    has_root_or_ou_target = True
        if has_root_or_ou_target:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-11",
                "PASS",
                {
                    "scp_count": collection_count(scps),
                    "targets": list(targets_evidence),
                    "deny_root_scp_count": deny_root_scp_count,
                    "deny_iam_scp_count": deny_iam_scp_count,
                },
                "SCPs exist targeting OU root or management",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "GOV-11",
            "FAIL",
            {
                "scp_count": collection_count(scps),
                "targets": list(targets_evidence),
                "deny_root_scp_count": deny_root_scp_count,
                "deny_iam_scp_count": deny_iam_scp_count,
            },
            "No SCP targets found on OU root or organizational units",
        )

    checks["GOV-11"] = gov11

    def gov12(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = ctx.results.global_control_gate(account_id, account_name, region, "GOV-12")
        if gate:
            return gate
        scps = _gov_scp_summaries(ctx)
        if scps is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "GOV-12")
        if collection_count(scps) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-12",
                "FAIL",
                {"scp_count": 0, "region_restricted_scp_count": 0},
                "No region restriction found in any SCP",
            )
        region_restricted_count = 0
        unreadable_policy_count = 0
        matched_policy_names: list[str] = []
        for scp in scps:
            if not has_property(scp, "Id"):
                continue
            content = _gov_policy_document_text(ctx, str(property_value(scp, ["Id"]) or ""))
            if content is None:
                unreadable_policy_count += 1
                continue
            if re.search(r"aws:RequestedRegion", content):
                region_restricted_count += 1
                if has_property(scp, "Name"):
                    matched_policy_names.append(str(property_value(scp, ["Name"]) or ""))
        if region_restricted_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-12",
                "PASS",
                {
                    "scp_count": collection_count(scps),
                    "region_restricted_scp_count": region_restricted_count,
                    "policy_names": list(matched_policy_names),
                },
                "At least one SCP contains region restriction condition",
            )
        if unreadable_policy_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-12",
                "PARTIAL",
                {
                    "scp_count": collection_count(scps),
                    "region_restricted_scp_count": 0,
                    "unreadable_policy_count": unreadable_policy_count,
                },
                "Cannot read SCP content",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "GOV-12",
            "FAIL",
            {"scp_count": collection_count(scps), "region_restricted_scp_count": 0},
            "No region restriction found in any SCP",
        )

    checks["GOV-12"] = gov12
    checks["GOV-13"] = workshop(
        "GOV-13", "Verify RTO/RPO defined per critical component in SIPedia/PCA. Check DIMA objectives."
    )
    checks["GOV-14"] = workshop(
        "GOV-14",
        "Verify cloud service catalog and approved AWS services list exist with ownership and review cadence.",
    )
    checks["GOV-15"] = workshop(
        "GOV-15", "Verify security KPI dashboard exists (Wiz/Security Hub). Check review cadence."
    )

    def gov16(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        deprecated_runtimes = [
            "nodejs12.x",
            "nodejs14.x",
            "nodejs10.x",
            "nodejs8.10",
            "python2.7",
            "python3.6",
            "python3.7",
            "python3.8",
            "ruby2.5",
            "ruby2.7",
            "dotnetcore2.1",
            "dotnetcore3.1",
            "java8",
            "go1.x",
        ]
        data = ctx.invoke_aws_cli(["lambda", "list-functions", "--max-items", "1000"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "GOV-16")
        functions: list[dict[str, Any]] = []
        if has_property(data, "Functions"):
            functions = [item for item in cli_array(property_value(data, ["Functions"])) if isinstance(item, dict)]
        runtime_summary: dict[str, int] = {}
        deprecated_functions: list[dict[str, str]] = []
        for function in functions:
            runtime = "unknown"
            if has_property(function, "Runtime"):
                runtime = str(property_value(function, ["Runtime"]) or "")
            if runtime not in runtime_summary:
                runtime_summary[runtime] = 0
            runtime_summary[runtime] = runtime_summary[runtime] + 1
            if runtime in deprecated_runtimes:
                function_name = ""
                if has_property(function, "FunctionName"):
                    function_name = str(property_value(function, ["FunctionName"]) or "")
                deprecated_functions.append({"name": function_name, "runtime": runtime})
        evidence = {
            "function_count": collection_count(functions),
            "runtimes": runtime_summary,
            "deprecated_functions": list(deprecated_functions),
        }
        if collection_count(deprecated_functions) > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "GOV-16", "FAIL", evidence, "Lambda functions with EOL runtimes found"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "GOV-16", "PASS", evidence, "No EOL Lambda runtimes found"
        )

    checks["GOV-16"] = gov16
    checks["GOV-17"] = workshop(
        "GOV-17", "Verify technical debt backlog exists on Confluence. Check last update date and owner."
    )

    def gov18(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        trail_data = ctx.invoke_aws_cli(["cloudtrail", "describe-trails"])
        if trail_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "GOV-18")
        trail_count = 0
        active_trail_count = 0
        if has_property(trail_data, "trailList"):
            trails = cli_array(property_value(trail_data, ["trailList"]))
            trail_count = collection_count(trails)
            for trail in trails:
                if not isinstance(trail, dict) or not has_property(trail, "Name"):
                    continue
                status_data = ctx.invoke_aws_cli(
                    ["cloudtrail", "get-trail-status", "--name", str(property_value(trail, ["Name"]) or "")]
                )
                if status_data is None:
                    continue
                if property_value(status_data, ["IsLogging"]) is True:
                    active_trail_count += 1
        cloudtrail_active = active_trail_count > 0
        recorder_data = ctx.invoke_aws_cli(["configservice", "describe-configuration-recorders"])
        config_recorder_active = False
        recorder_count = 0
        if recorder_data is not None and has_property(recorder_data, "ConfigurationRecorders"):
            recorders = cli_array(property_value(recorder_data, ["ConfigurationRecorders"]))
            recorder_count = collection_count(recorders)
            if recorder_count > 0:
                recorder_names: list[str] = []
                for recorder in recorders:
                    if isinstance(recorder, dict) and has_property(recorder, "Name"):
                        recorder_names.append(str(property_value(recorder, ["Name"]) or ""))
                if collection_count(recorder_names) > 0:
                    status_args = ["configservice", "describe-configuration-recorder-status"]
                    for recorder_name in recorder_names:
                        status_args.extend(["--configuration-recorder-names", recorder_name])
                    recorder_status_data = ctx.invoke_aws_cli(status_args)
                    if recorder_status_data is not None and has_property(
                        recorder_status_data, "ConfigurationRecordersStatus"
                    ):
                        for recorder_status in cli_array(
                            property_value(recorder_status_data, ["ConfigurationRecordersStatus"])
                        ):
                            if (
                                isinstance(recorder_status, dict)
                                and has_property(recorder_status, "recording")
                                and property_value(recorder_status, ["recording"]) is True
                            ):
                                config_recorder_active = True
                                break
        evidence = {
            "trail_count": trail_count,
            "active_trail_count": active_trail_count,
            "cloudtrail_active": cloudtrail_active,
            "recorder_count": recorder_count,
            "config_recorder_active": config_recorder_active,
        }
        if cloudtrail_active and config_recorder_active:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-18",
                "PASS",
                evidence,
                "CloudTrail active and Config recorder active",
            )
        if cloudtrail_active or config_recorder_active:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "GOV-18",
                "PARTIAL",
                evidence,
                "Only one of CloudTrail or Config recorder is active",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "GOV-18",
            "FAIL",
            evidence,
            "Neither CloudTrail nor Config recorder is active",
        )

    checks["GOV-18"] = gov18

    def gov19(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        secrets_data = ctx.invoke_aws_cli(["secretsmanager", "list-secrets", "--max-results", "100"])
        secrets_count = 0
        rotation_enabled_count = 0
        if secrets_data is not None and has_property(secrets_data, "SecretList"):
            for secret in cli_array(property_value(secrets_data, ["SecretList"])):
                if not isinstance(secret, dict):
                    continue
                secrets_count += 1
                if property_value(secret, ["RotationEnabled"]) is True:
                    rotation_enabled_count += 1
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "GOV-19",
            "PARTIAL",
            {
                "secrets_count": secrets_count,
                "rotation_enabled_count": rotation_enabled_count,
            },
            "Verify secrets governance policy and rotation coverage during workshop.",
        )

    checks["GOV-19"] = gov19
    checks["GOV-20"] = workshop(
        "GOV-20", "Verify incident RACI for cloud incidents exists. Check INC domain playbooks."
    )

    return DomainModule(code="GOV", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
