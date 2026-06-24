"""INC domain — incident response controls."""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

from audit_scanner.domains.base import CheckContext, CheckFn, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {f"INC-{index:02d}": level for index, level in [
    (1, "P0"), (2, "P0"), (3, "P0"), (4, "P0"), (5, "P1"), (6, "P0"), (7, "P0"),
    (8, "P0"), (9, "P1"), (10, "P0"), (11, "P0"), (12, "P0"), (13, "P0"), (14, "P0"), (15, "P0"),
]}

WORKSHOP_NOTES: dict[str, str] = {
    "INC-01": "Verify cloud incident management policy exists and is current.",
    "INC-02": "Verify RACI for cloud incidents across platform, SOC, business and security teams.",
    "INC-04": "Verify incident severity matrix exists for cloud incidents.",
    "INC-05": "Verify playbooks exist for compromised account, data breach, DDoS, and ransomware.",
    "INC-07": "Verify isolation security group or quarantine SCP exists for compromised resources.",
    "INC-08": "Verify rapid revocation: Identity Center access revokable within minutes.",
    "INC-10": "Verify on-call rotation exists with escalation path.",
    "INC-11": "Verify crisis communication plan for internal and external stakeholders.",
    "INC-12": "Verify AWS Support plan and escalation process to AWS DRT/TAM is documented.",
    "INC-13": "Verify tabletop or live exercises have been performed.",
    "INC-14": "Verify RETEX exists for at least one major cloud incident. Check action items tracked to closure.",
}


def _workshop(control_id: str) -> CheckFn:
    notes = WORKSHOP_NOTES[control_id]

    def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        return ctx.results.audit_result(
            account_id, account_name, region, control_id, "NOT_TESTED", None, notes,
        )

    return _check


def _organization_roots(ctx: CheckContext) -> list[dict] | None:
    data = ctx.invoke_aws_cli(["organizations", "list-roots"])
    if data is None:
        return None
    if has_property(data, "Roots"):
        return cli_array(data.get("Roots"))
    return []


def _organizational_units(ctx: CheckContext, parent_id: str) -> list[dict] | None:
    units: list[dict] = []
    token = None
    while True:
        args = ["organizations", "list-organizational-units-for-parent", "--parent-id", parent_id]
        if token:
            args.extend(["--next-token", token])
        data = ctx.invoke_aws_cli(args)
        if data is None:
            return None
        if has_property(data, "OrganizationalUnits"):
            units.extend(cli_array(data.get("OrganizationalUnits")))
        token = None
        if has_property(data, "NextToken"):
            next_token = str(data.get("NextToken") or "")
            if next_token:
                token = next_token
        if not token:
            break
    return units


def _quarantine_ou_name(name: str) -> bool:
    return bool(re.search(r"quarantine|isolate|isolation|containment|sandbox-incident|incident", name.lower()))


def _cloudtrail_active(ctx: CheckContext) -> bool:
    trail_data = ctx.invoke_aws_cli(["cloudtrail", "describe-trails", "--include-shadow-trails"])
    if not trail_data or not has_property(trail_data, "trailList"):
        return False
    for trail in cli_array(trail_data.get("trailList")):
        if not has_property(trail, "Name"):
            continue
        status = ctx.invoke_aws_cli(["cloudtrail", "get-trail-status", "--name", str(trail.get("Name", ""))])
        if status and status.get("IsLogging") is True:
            return True
    return False


def _rule_has_active_targets(ctx: CheckContext, rule_name: str) -> bool:
    target_data = ctx.invoke_aws_cli(["events", "list-targets-by-rule", "--rule", rule_name])
    if target_data is None or not has_property(target_data, "Targets"):
        return False
    for target in cli_array(property_value(target_data, ["Targets"])):
        target_arn = str(property_value(target, ["Arn"]) or "")
        if re.search(r":sns:|:lambda:|:sqs:", target_arn):
            return True
    return False


def _quarantine_ou_has_deny_scp(ctx: CheckContext, ou_id: str) -> bool:
    policy_data = ctx.invoke_aws_cli(
        ["organizations", "list-policies-for-target", "--target-id", ou_id, "--filter", "SERVICE_CONTROL_POLICY"]
    )
    if policy_data is None or not has_property(policy_data, "Policies"):
        return False
    for policy in cli_array(property_value(policy_data, ["Policies"])):
        if not isinstance(policy, dict) or not has_property(policy, "Id"):
            continue
        detail = ctx.invoke_aws_cli(
            ["organizations", "describe-policy", "--policy-id", str(property_value(policy, ["Id"]) or "")]
        )
        if detail is None or not has_property(detail, "Policy"):
            continue
        content = str(property_value(property_value(detail, ["Policy"]), ["Content"]) or "")
        if re.search(r'"Effect"\s*:\s*"Deny"', content, re.IGNORECASE) and re.search(
            r'"Action"\s*:\s*"\*"', content
        ):
            return True
    return False


def _forensics_bucket_names(ctx: CheckContext) -> list[str] | None:
    data = ctx.invoke_aws_cli(["s3api", "list-buckets"])
    if data is None:
        return None
    buckets: list[str] = []
    if has_property(data, "Buckets"):
        for bucket in cli_array(property_value(data, ["Buckets"])):
            if not isinstance(bucket, dict):
                continue
            bucket_name = str(property_value(bucket, ["Name"]) or "").lower()
            if re.search(r"forensic|forensics|evidence|incident|chain-of-custody", bucket_name):
                buckets.append(str(property_value(bucket, ["Name"]) or ""))
    return buckets


def _inc03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
    data = ctx.invoke_aws_cli(["events", "list-rules"])
    if data is None:
        return ctx.results.null_api_partial(account_id, account_name, region, "INC-03")

    guardduty_rules: list[str] = []
    cloudtrail_rules: list[str] = []
    config_rules: list[str] = []
    securityhub_rules: list[str] = []
    rules_without_targets: list[str] = []
    if has_property(data, "Rules"):
        for rule in cli_array(data.get("Rules")):
            rule_name = str(rule.get("Name", ""))
            event_pattern = str(property_value(rule, ["EventPattern"]) or "")
            schedule = str(property_value(rule, ["ScheduleExpression"]) or "")
            combined = f"{rule_name} {event_pattern} {schedule}"
            matched = False
            if re.search(r"guardduty|aws\.guardduty", combined, re.IGNORECASE):
                guardduty_rules.append(rule_name)
                matched = True
            if re.search(r"cloudtrail|aws\.cloudtrail", combined, re.IGNORECASE):
                cloudtrail_rules.append(rule_name)
                matched = True
            if re.search(r"config|aws\.config|ComplianceChangeNotification", combined, re.IGNORECASE):
                config_rules.append(rule_name)
                matched = True
            if re.search(r"securityhub|security-hub|aws\.securityhub", combined, re.IGNORECASE):
                securityhub_rules.append(rule_name)
                matched = True
            if matched and not _rule_has_active_targets(ctx, rule_name):
                rules_without_targets.append(rule_name)

    all_rules = guardduty_rules + cloudtrail_rules + config_rules + securityhub_rules
    evidence = {
        "guardduty_rules": guardduty_rules,
        "cloudtrail_rules": cloudtrail_rules,
        "config_rules": config_rules,
        "securityhub_rules": securityhub_rules,
        "incident_rule_count": collection_count(all_rules),
        "rules_without_targets": rules_without_targets,
    }
    if not all_rules:
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-03", "FAIL", evidence,
            "No incident detection EventBridge rules found",
        )
    if collection_count(rules_without_targets) > 0:
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-03", "PARTIAL", evidence,
            "Incident EventBridge rules exist but some have no SNS, Lambda or SQS targets",
        )
    return ctx.results.audit_result(
        account_id, account_name, region, "INC-03", "PASS", evidence,
        "EventBridge rules found for GuardDuty, CloudTrail, Config or Security Hub with active targets",
    )


def _inc06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
    gate = ctx.results.global_control_gate(account_id, account_name, region, "INC-06")
    if gate:
        return gate

    roots = _organization_roots(ctx)
    if roots is None:
        return ctx.results.null_api_partial(account_id, account_name, region, "INC-06")
    if not roots:
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-06", "FAIL", {"root_count": 0},
            "No organization roots found",
        )

    all_ou_names: list[str] = []
    quarantine_ous: list[dict] = []
    for root in roots:
        if not has_property(root, "Id"):
            continue
        units = _organizational_units(ctx, str(root["Id"]))
        if units is None:
            continue
        for unit in units:
            ou_name = str(unit.get("Name", ""))
            ou_id = str(unit.get("Id", ""))
            all_ou_names.append(ou_name)
            if _quarantine_ou_name(ou_name):
                quarantine_ous.append(
                    {
                        "id": ou_id,
                        "name": ou_name,
                        "deny_all_scp": _quarantine_ou_has_deny_scp(ctx, ou_id) if ou_id else False,
                    }
                )

    evidence = {
        "ou_count": collection_count(all_ou_names),
        "ou_names": all_ou_names,
        "quarantine_ous": quarantine_ous,
    }
    if not quarantine_ous:
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-06", "FAIL", evidence, "No quarantine OU found",
        )
    if any(item.get("deny_all_scp") for item in quarantine_ous):
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "INC-06",
            "PASS",
            evidence,
            "Quarantine OU found with deny-all SCP attached",
        )
    return ctx.results.audit_result(
        account_id,
        account_name,
        region,
        "INC-06",
        "PARTIAL",
        evidence,
        "Quarantine OU detected; verify associated SCP applies deny-all on target accounts",
    )


def _inc09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
    buckets = _forensics_bucket_names(ctx)
    if buckets is None:
        return ctx.results.null_api_partial(account_id, account_name, region, "INC-09")
    evidence = {"forensics_bucket_count": collection_count(buckets), "forensics_buckets": list(buckets[:10])}
    if collection_count(buckets) > 0:
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "INC-09",
            "PARTIAL",
            evidence,
            "Forensics S3 buckets detected; verify chain-of-custody procedure and snapshot capability",
        )
    return ctx.results.audit_result(
        account_id,
        account_name,
        region,
        "INC-09",
        "FAIL",
        evidence,
        "No forensics buckets found; verify forensics procedure exists",
    )


def _inc15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=30)
    data = ctx.invoke_aws_cli([
        "cloudtrail", "lookup-events",
        "--lookup-attributes", "AttributeKey=EventName,AttributeValue=AssumeRole",
        "--start-time", start_time.isoformat(),
        "--end-time", end_time.isoformat(),
        "--max-results", "50",
    ])
    if data is None:
        return ctx.results.null_api_partial(account_id, account_name, region, "INC-15")

    assume_role_count = 0
    break_glass_count = 0
    if has_property(data, "Events"):
        events = cli_array(data.get("Events"))
        assume_role_count = collection_count(events)
        for event in events:
            event_text = str(event.get("CloudTrailEvent", ""))
            if re.search(r"BreakGlass|Emergency|Incident|Quarantine", event_text, re.IGNORECASE):
                break_glass_count += 1

    forensic_snapshot_count = 0
    snapshot_data = ctx.invoke_aws_cli(["ec2", "describe-snapshots", "--owner-ids", account_id])
    if snapshot_data and has_property(snapshot_data, "Snapshots"):
        for snapshot in cli_array(property_value(snapshot_data, ["Snapshots"])):
            description = str(property_value(snapshot, ["Description"]) or "").lower()
            if re.search(r"forensic|incident|evidence", description):
                forensic_snapshot_count += 1

    cloudtrail_active = _cloudtrail_active(ctx)
    evidence = {
        "assume_role_event_count": assume_role_count,
        "break_glass_event_count": break_glass_count,
        "forensic_snapshot_count": forensic_snapshot_count,
        "cloudtrail_active": cloudtrail_active,
    }
    if break_glass_count > 0 or forensic_snapshot_count > 0:
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "INC-15",
            "PARTIAL",
            evidence,
            "Incident-related CloudTrail or forensic snapshot signals found; verify full audit trail in workshop",
        )
    if cloudtrail_active:
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "INC-15",
            "PARTIAL",
            evidence,
            "CloudTrail active but no incident-specific activity found in sample",
        )
    return ctx.results.audit_result(
        account_id,
        account_name,
        region,
        "INC-15",
        "FAIL",
        evidence,
        "No active CloudTrail logging detected",
    )


def get_domain() -> DomainModule:
    checks: OrderedDict[str, CheckFn] = OrderedDict(
        [
            ("INC-01", _workshop("INC-01")),
            ("INC-02", _workshop("INC-02")),
            ("INC-03", _inc03),
            ("INC-04", _workshop("INC-04")),
            ("INC-05", _workshop("INC-05")),
            ("INC-06", _inc06),
            ("INC-07", _workshop("INC-07")),
            ("INC-08", _workshop("INC-08")),
            ("INC-09", _inc09),
            ("INC-10", _workshop("INC-10")),
            ("INC-11", _workshop("INC-11")),
            ("INC-12", _workshop("INC-12")),
            ("INC-13", _workshop("INC-13")),
            ("INC-14", _workshop("INC-14")),
            ("INC-15", _inc15),
        ]
    )
    return DomainModule(code="INC", severity=SEVERITY, checks=checks)
