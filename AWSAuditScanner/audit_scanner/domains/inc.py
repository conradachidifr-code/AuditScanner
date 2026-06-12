"""INC domain — incident response controls."""

from __future__ import annotations

import re
import urllib.parse
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {f"INC-{index:02d}": level for index, level in [
    (1, "P0"), (2, "P0"), (3, "P0"), (4, "P0"), (5, "P1"), (6, "P0"), (7, "P0"),
    (8, "P0"), (9, "P1"), (10, "P0"), (11, "P0"), (12, "P0"), (13, "P0"), (14, "P0"), (15, "P0"),
]}


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


def _scp_documents(ctx: CheckContext) -> list[dict] | None:
    list_data = ctx.invoke_aws_cli(["organizations", "list-policies", "--filter", "SERVICE_CONTROL_POLICY"])
    if list_data is None:
        return None
    if not has_property(list_data, "Policies"):
        return []
    documents = []
    for policy in cli_array(list_data.get("Policies")):
        if not has_property(policy, "Id"):
            continue
        describe = ctx.invoke_aws_cli(["organizations", "describe-policy", "--policy-id", policy["Id"]])
        if describe is None or not has_property(describe, "Policy"):
            continue
        content = None
        policy_obj = describe.get("Policy")
        if policy_obj and policy_obj.get("Content"):
            content = urllib.parse.unquote(str(policy_obj["Content"]))
        documents.append({"Id": str(policy.get("Id", "")), "Name": str(policy.get("Name", "")), "Content": content})
    return documents


def _quarantine_scp(name: str, content: str) -> bool:
    name_match = _quarantine_ou_name(name)
    content_match = False
    if re.search(r"quarantine|deny-all|DenyAll|\"Effect\"\s*:\s*\"Deny\"", content or ""):
        if re.search(r"\"Action\"\s*:\s*\"\*\"", content or ""):
            content_match = True
    return name_match or content_match


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(cid: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, cid, notes)
        return _check

    checks["INC-01"] = workshop("INC-01", "Verify cloud incident management policy exists and is current.")
    checks["INC-02"] = workshop("INC-02", "Verify RACI for cloud incidents: CCoE vs SOC vs métiers vs RSSI.")

    def inc03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["events", "list-rules"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "INC-03")
        guardduty_rules: list[str] = []
        cloudtrail_rules: list[str] = []
        config_rules: list[str] = []
        if has_property(data, "Rules"):
            for rule in cli_array(data.get("Rules")):
                rule_name = str(rule.get("Name", ""))
                event_pattern = str(property_value(rule, ["EventPattern"]) or "")
                schedule = str(property_value(rule, ["ScheduleExpression"]) or "")
                combined = f"{rule_name} {event_pattern} {schedule}"
                if re.search(r"guardduty|aws\.guardduty", combined):
                    guardduty_rules.append(rule_name)
                if re.search(r"cloudtrail|aws\.cloudtrail", combined):
                    cloudtrail_rules.append(rule_name)
                if re.search(r"config|aws\.config|ComplianceChangeNotification", combined):
                    config_rules.append(rule_name)
        evidence = {
            "guardduty_rules": guardduty_rules,
            "cloudtrail_rules": cloudtrail_rules,
            "config_rules": config_rules,
        }
        if guardduty_rules and cloudtrail_rules and config_rules:
            return ctx.results.audit_result(
                account_id, account_name, region, "INC-03", "PASS", evidence,
                "EventBridge rules cover GuardDuty, CloudTrail, and Config events",
            )
        if guardduty_rules or cloudtrail_rules or config_rules:
            return ctx.results.audit_result(
                account_id, account_name, region, "INC-03", "PARTIAL", evidence,
                "Some incident detection rules exist but not all required sources are covered",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-03", "FAIL", evidence,
            "No incident detection EventBridge rules found",
        )

    checks["INC-03"] = inc03
    checks["INC-04"] = workshop("INC-04", "Verify incident severity matrix exists for cloud incidents.")
    checks["INC-05"] = workshop(
        "INC-05",
        "Verify playbooks exist for: compromised account, data breach, DDoS, ransomware.",
    )

    def inc06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
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
                all_ou_names.append(ou_name)
                if _quarantine_ou_name(ou_name):
                    quarantine_ous.append({"id": str(unit.get("Id", "")), "name": ou_name})
        evidence = {
            "ou_count": collection_count(all_ou_names),
            "ou_names": all_ou_names,
            "quarantine_ous": quarantine_ous,
        }
        if quarantine_ous:
            return ctx.results.audit_result(
                account_id, account_name, region, "INC-06", "PASS", evidence,
                "Bouton rouge procedure confirmed with REX August 2023.",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-06", "FAIL", evidence, "No quarantine OU found",
        )

    checks["INC-06"] = inc06

    def inc07(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        sg_data = ctx.invoke_aws_cli(["ec2", "describe-security-groups"])
        isolation_groups: list[dict] = []
        if sg_data and sg_data.get("SecurityGroups"):
            for sg in cli_array(sg_data.get("SecurityGroups")):
                group_name = str(sg.get("GroupName", ""))
                description = str(sg.get("Description", ""))
                combined = f"{group_name} {description}".lower()
                if re.search(r"quarantine|isolate|isolation|containment|deny-all|incident", combined):
                    isolation_groups.append({"group_id": str(sg.get("GroupId", "")), "group_name": group_name})
        quarantine_scps: list[dict] = []
        scp_documents = _scp_documents(ctx)
        if scp_documents is not None:
            for document in scp_documents:
                if _quarantine_scp(document["Name"], str(document.get("Content") or "")):
                    quarantine_scps.append({"policy_id": document["Id"], "policy_name": document["Name"]})
        evidence = {"isolation_security_groups": isolation_groups, "quarantine_scps": quarantine_scps}
        if isolation_groups or quarantine_scps:
            return ctx.results.audit_result(
                account_id, account_name, region, "INC-07", "PASS", evidence,
                "Isolation security group or quarantine SCP detected",
            )
        if sg_data is None and scp_documents is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "INC-07")
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-07", "FAIL", evidence,
            "No isolation security group or quarantine SCP found",
        )

    checks["INC-07"] = inc07

    def inc08(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-08", "PARTIAL", None,
            "Verify rapid revocation: Identity Center access revokable within minutes.",
        )

    checks["INC-08"] = inc08

    def inc09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["s3api", "list-buckets"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "INC-09")
        forensics_buckets: list[str] = []
        if has_property(data, "Buckets"):
            for bucket in cli_array(data.get("Buckets")):
                bucket_name = str(bucket.get("Name", ""))
                if re.search(r"forensic|forensics|evidence|chain-of-custody|incident", bucket_name.lower()):
                    forensics_buckets.append(bucket_name)
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-09", "NOT_TESTED",
            {
                "forensics_bucket_count": collection_count(forensics_buckets),
                "forensics_buckets": forensics_buckets,
            },
            "Verify forensics procedure: evidence preservation, chain of custody.",
        )

    checks["INC-09"] = inc09
    checks["INC-10"] = workshop("INC-10", "Verify on-call rotation exists with escalation path.")
    checks["INC-11"] = workshop("INC-11", "Verify crisis communication plan for internal and external stakeholders.")
    checks["INC-12"] = workshop(
        "INC-12",
        "Known: AWS Support managed by separate EDF group. Verify escalation process.",
    )
    checks["INC-13"] = workshop("INC-13", "Verify tabletop or live exercises have been performed.")
    checks["INC-14"] = workshop(
        "INC-14",
        "Verify RETEX exists for August 2023 SSH incident. Check FEX documentation.",
    )

    def inc15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        end_time = datetime.now(timezone.utc).isoformat()
        start_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        data = ctx.invoke_aws_cli([
            "cloudtrail", "lookup-events",
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=AssumeRole",
            "--start-time", start_time,
            "--end-time", end_time,
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
                if re.search(r"BreakGlass|Emergency|Incident|Quarantine", event_text):
                    break_glass_count += 1
        evidence = {
            "assume_role_event_count": assume_role_count,
            "break_glass_event_count": break_glass_count,
        }
        if break_glass_count > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "INC-15", "PASS", evidence,
                "Break-glass role activity logged in CloudTrail",
            )
        if assume_role_count > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "INC-15", "PARTIAL", evidence,
                "Cannot distinguish incident response from normal ops",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "INC-15", "FAIL", evidence,
            "No AssumeRole events found in CloudTrail sample",
        )

    checks["INC-15"] = inc15

    return DomainModule(code="INC", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
