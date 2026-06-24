"""DET domain — detection (GuardDuty, Security Hub, Detective, Macie, WAF)."""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "DET-01": "P0",
    "DET-02": "P0",
    "DET-03": "P0",
    "DET-04": "P0",
    "DET-05": "P0",
    "DET-06": "P0",
    "DET-07": "P0",
    "DET-08": "P0",
    "DET-09": "P0",
    "DET-10": "P0",
    "DET-11": "P0",
    "DET-12": "P0",
    "DET-13": "P0",
    "DET-14": "P1",
    "DET-15": "P1",
    "DET-16": "P0",
    "DET-17": "P0",
    "DET-18": "P0",
    "DET-19": "P0",
    "DET-20": "P0",
    "DET-21": "P0",
    "DET-22": "P0",
    "DET-23": "P0",
    "DET-24": "P0",
    "DET-25": "P1",
    "DET-26": "P0",
    "DET-27": "P1",
    "DET-28": "P0",
}


def _guardduty_detector_id(ctx: CheckContext) -> str | None:
    data = ctx.invoke_aws_cli(["guardduty", "list-detectors"])
    if data is None or not has_property(data, "DetectorIds"):
        return None
    detector_ids = cli_array(property_value(data, ["DetectorIds"]))
    if collection_count(detector_ids) == 0:
        return None
    return str(detector_ids[0])


def _waf_web_acls(ctx: CheckContext, scope: str) -> list[dict[str, Any]]:
    data = ctx.invoke_aws_cli(["wafv2", "list-web-acls", "--scope", scope])
    if data is None or not has_property(data, "WebACLs"):
        return []
    return [item for item in cli_array(property_value(data, ["WebACLs"])) if isinstance(item, dict)]


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(control_id: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, control_id, notes)

        return _check

    def det01(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        detector_id = _guardduty_detector_id(ctx)
        if detector_id is None:
            data = ctx.invoke_aws_cli(["guardduty", "list-detectors"])
            if data is None:
                return ctx.results.null_api_partial(account_id, account_name, region, "DET-01")
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-01",
                "FAIL",
                {"detector_count": 0},
                "No GuardDuty detector found in region",
            )
        status_data = ctx.invoke_aws_cli(["guardduty", "get-detector", "--detector-id", detector_id])
        status = str(property_value(status_data, ["Status"]) or "") if status_data else ""
        if status == "ENABLED":
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-01",
                "PASS",
                {"detector_id": detector_id, "status": status},
                "GuardDuty detector is enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-01",
            "FAIL",
            {"detector_id": detector_id, "status": status or "unknown"},
            "GuardDuty detector is not enabled",
        )

    checks["DET-01"] = det01

    def det02(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        detector_id = _guardduty_detector_id(ctx)
        if detector_id is None:
            data = ctx.invoke_aws_cli(["guardduty", "list-detectors"])
            if data is None:
                return ctx.results.null_api_partial(account_id, account_name, region, "DET-02")
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-02",
                "FAIL",
                {"detector_count": 0},
                "GuardDuty is not enabled in this region",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-02",
            "PASS",
            {"detector_id": detector_id},
            "GuardDuty detector present in region",
        )

    checks["DET-02"] = det02

    def det03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = ctx.results.global_control_gate(account_id, account_name, region, "DET-03")
        if gate:
            return gate
        data = ctx.invoke_aws_cli(["guardduty", "describe-organization-configuration"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-03")
        auto_enable = property_value(data, ["AutoEnable"]) is True
        member_auto = property_value(data, ["AutoEnableOrganizationMembers"]) == "ALL"
        if auto_enable or member_auto:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-03",
                "PASS",
                {
                    "auto_enable": auto_enable,
                    "auto_enable_organization_members": property_value(data, ["AutoEnableOrganizationMembers"]),
                },
                "GuardDuty organization auto-enable is configured",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-03",
            "FAIL",
            {
                "auto_enable": auto_enable,
                "auto_enable_organization_members": property_value(data, ["AutoEnableOrganizationMembers"]),
            },
            "GuardDuty organization auto-enable is not configured",
        )

    checks["DET-03"] = det03

    def det04(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        detector_id = _guardduty_detector_id(ctx)
        if detector_id is None:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-04",
                "FAIL",
                {"feature_count": 0},
                "No GuardDuty detector to assess features",
            )
        data = ctx.invoke_aws_cli(["guardduty", "get-detector", "--detector-id", detector_id])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-04")
        features = property_value(data, ["Features"])
        enabled_features: list[str] = []
        if isinstance(features, list):
            for feature in features:
                if not isinstance(feature, dict):
                    continue
                if property_value(feature, ["Status"]) == "ENABLED":
                    enabled_features.append(str(property_value(feature, ["Name"]) or ""))
        if collection_count(enabled_features) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-04",
                "PASS",
                {"enabled_features": enabled_features},
                "GuardDuty extended features are enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-04",
            "PARTIAL",
            {"enabled_features": enabled_features},
            "No extended GuardDuty features enabled; verify baseline protection",
        )

    checks["DET-04"] = det04

    def det05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        detector_id = _guardduty_detector_id(ctx)
        if detector_id is None:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-05",
                "FAIL",
                None,
                "No GuardDuty detector to assess data sources",
            )
        data = ctx.invoke_aws_cli(["guardduty", "get-detector", "--detector-id", detector_id])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-05")
        data_sources = property_value(data, ["DataSources"])
        enabled_sources: list[str] = []
        if isinstance(data_sources, dict):
            for source_name, source_value in data_sources.items():
                if isinstance(source_value, dict) and property_value(source_value, ["Status"]) == "ENABLED":
                    enabled_sources.append(str(source_name))
        if collection_count(enabled_sources) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-05",
                "PASS",
                {"enabled_data_sources": enabled_sources},
                "GuardDuty data sources are enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-05",
            "PARTIAL",
            {"enabled_data_sources": enabled_sources},
            "No GuardDuty data sources reported as enabled",
        )

    checks["DET-05"] = det05

    def det06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        detector_id = _guardduty_detector_id(ctx)
        if detector_id is None:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-06",
                "FAIL",
                {"filter_count": 0},
                "No GuardDuty detector to assess filters",
            )
        data = ctx.invoke_aws_cli(["guardduty", "list-filters", "--detector-id", detector_id])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-06")
        filter_names = cli_array(property_value(data, ["FilterNames"])) if has_property(data, "FilterNames") else []
        filter_count = collection_count(filter_names)
        if filter_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-06",
                "PASS",
                {"filter_count": 0},
                "No GuardDuty suppression filters configured",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-06",
            "PARTIAL",
            {"filter_count": filter_count, "filter_names": [str(name) for name in filter_names[:10]]},
            "GuardDuty filters exist; verify they are justified and documented",
        )

    checks["DET-06"] = det06

    def det07(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["events", "list-rules"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-07")
        guardduty_rules: list[str] = []
        for rule in cli_array(property_value(data, ["Rules"])):
            if not isinstance(rule, dict):
                continue
            rule_name = str(property_value(rule, ["Name"]) or "")
            if re.search(r"guardduty|GuardDuty", rule_name, re.IGNORECASE):
                guardduty_rules.append(rule_name)
        if collection_count(guardduty_rules) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-07",
                "PASS",
                {"guardduty_rule_count": collection_count(guardduty_rules), "rules": guardduty_rules[:10]},
                "EventBridge rules exist for GuardDuty findings",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-07",
            "FAIL",
            {"guardduty_rule_count": 0},
            "No EventBridge rules found for GuardDuty alerting",
        )

    checks["DET-07"] = det07
    checks["DET-08"] = workshop(
        "DET-08",
        "Verify SOC runbooks and escalation paths for GuardDuty findings are documented and tested.",
    )

    def det09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        detector_id = _guardduty_detector_id(ctx)
        if detector_id is None:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-09",
                "FAIL",
                {"destination_count": 0},
                "No GuardDuty detector to assess publishing destinations",
            )
        data = ctx.invoke_aws_cli(
            ["guardduty", "list-publishing-destinations", "--detector-id", detector_id]
        )
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-09")
        destinations = cli_array(property_value(data, ["Destinations"])) if has_property(data, "Destinations") else []
        destination_count = collection_count(destinations)
        if destination_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-09",
                "PASS",
                {"destination_count": destination_count},
                "GuardDuty findings export destinations are configured",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-09",
            "PARTIAL",
            {"destination_count": 0},
            "No GuardDuty publishing destinations; verify centralized SIEM integration",
        )

    checks["DET-09"] = det09

    def det10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["securityhub", "describe-hub"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-10")
        hub_arn = str(property_value(data, ["HubArn"]) or "")
        if hub_arn:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-10",
                "PASS",
                {"hub_arn": hub_arn},
                "Security Hub is enabled in region",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-10",
            "FAIL",
            None,
            "Security Hub is not enabled in region",
        )

    checks["DET-10"] = det10

    def det11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = ctx.results.global_control_gate(account_id, account_name, region, "DET-11")
        if gate:
            return gate
        data = ctx.invoke_aws_cli(["securityhub", "get-enabled-standards"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-11")
        standard_count = 0
        if has_property(data, "StandardsSubscriptions"):
            standard_count = collection_count(cli_array(property_value(data, ["StandardsSubscriptions"])))
        if standard_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-11",
                "PASS",
                {"enabled_standards_count": standard_count},
                "Security Hub standards are subscribed",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-11",
            "FAIL",
            {"enabled_standards_count": 0},
            "No Security Hub standards subscribed",
        )

    checks["DET-11"] = det11
    checks["DET-12"] = workshop(
        "DET-12",
        "Verify Security Hub findings workflow: triage, ownership, remediation SLAs and reporting.",
    )

    def det13(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["securityhub", "list-automation-rules"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-13")
        rule_count = 0
        if has_property(data, "AutomationRulesMetadata"):
            rule_count = collection_count(cli_array(property_value(data, ["AutomationRulesMetadata"])))
        if rule_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-13",
                "PASS",
                {"automation_rule_count": rule_count},
                "Security Hub automation rules are configured",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-13",
            "PARTIAL",
            {"automation_rule_count": 0},
            "No Security Hub automation rules found",
        )

    checks["DET-13"] = det13

    def det14(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["detective", "list-graphs"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-14")
        graph_count = 0
        if has_property(data, "GraphList"):
            graph_count = collection_count(cli_array(property_value(data, ["GraphList"])))
        if graph_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-14",
                "PASS",
                {"graph_count": graph_count},
                "Amazon Detective graph is enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-14",
            "FAIL",
            {"graph_count": 0},
            "No Amazon Detective graphs found",
        )

    checks["DET-14"] = det14

    def det15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["iam", "list-roles", "--max-items", "1000"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-15")
        detective_roles: list[str] = []
        for role in cli_array(property_value(data, ["Roles"])):
            if not isinstance(role, dict):
                continue
            role_name = str(property_value(role, ["RoleName"]) or "")
            if re.search(r"detective|Detective", role_name, re.IGNORECASE):
                detective_roles.append(role_name)
        if collection_count(detective_roles) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-15",
                "PARTIAL",
                {"detective_role_count": collection_count(detective_roles), "roles": detective_roles[:10]},
                "Detective-related IAM roles found; verify least privilege in workshop",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-15",
            "PARTIAL",
            {"detective_role_count": 0},
            "No Detective-specific IAM roles identified by name pattern",
        )

    checks["DET-15"] = det15

    def det16(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["macie2", "get-macie-session"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-16")
        status = str(property_value(data, ["status"]) or property_value(data, ["Status"]) or "")
        if status.upper() == "ENABLED":
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-16",
                "PASS",
                {"status": status},
                "Amazon Macie is enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-16",
            "FAIL",
            {"status": status or "unknown"},
            "Amazon Macie is not enabled",
        )

    checks["DET-16"] = det16

    def det17(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["macie2", "list-classification-jobs"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-17")
        job_count = 0
        if has_property(data, "items"):
            job_count = collection_count(cli_array(property_value(data, ["items"])))
        elif has_property(data, "jobs"):
            job_count = collection_count(cli_array(property_value(data, ["jobs"])))
        if job_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-17",
                "PASS",
                {"classification_job_count": job_count},
                "Macie classification jobs are configured",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-17",
            "PARTIAL",
            {"classification_job_count": 0},
            "No Macie classification jobs found",
        )

    checks["DET-17"] = det17

    def det18(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["events", "list-rules"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DET-18")
        macie_rules: list[str] = []
        for rule in cli_array(property_value(data, ["Rules"])):
            if not isinstance(rule, dict):
                continue
            rule_name = str(property_value(rule, ["Name"]) or "")
            if re.search(r"macie|Macie", rule_name, re.IGNORECASE):
                macie_rules.append(rule_name)
        if collection_count(macie_rules) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-18",
                "PASS",
                {"macie_rule_count": collection_count(macie_rules), "rules": macie_rules[:10]},
                "EventBridge rules exist for Macie findings",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-18",
            "PARTIAL",
            {"macie_rule_count": 0},
            "No EventBridge rules found for Macie alerting",
        )

    checks["DET-18"] = det18

    def det19(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        regional_acls = _waf_web_acls(ctx, "REGIONAL")
        cloudfront_acls = _waf_web_acls(ctx, "CLOUDFRONT")
        associated_count = 0
        for scope, acls in (("REGIONAL", regional_acls), ("CLOUDFRONT", cloudfront_acls)):
            for acl in acls:
                acl_arn = str(property_value(acl, ["ARN"]) or "")
                if not acl_arn:
                    continue
                resource_data = ctx.invoke_aws_cli(
                    ["wafv2", "list-resources-for-web-acl", "--web-acl-arn", acl_arn, "--scope", scope]
                )
                if resource_data is None:
                    continue
                resources = cli_array(property_value(resource_data, ["ResourceArns"]))
                if collection_count(resources) > 0:
                    associated_count += 1
        evidence = {
            "regional_web_acl_count": collection_count(regional_acls),
            "cloudfront_web_acl_count": collection_count(cloudfront_acls),
            "associated_web_acl_count": associated_count,
        }
        if associated_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-19",
                "PASS",
                evidence,
                "WAF web ACLs are associated with protected resources",
            )
        if collection_count(regional_acls) + collection_count(cloudfront_acls) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-19",
                "PARTIAL",
                evidence,
                "WAF web ACLs exist but none are associated with resources",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-19",
            "FAIL",
            evidence,
            "No WAF web ACLs found",
        )

    checks["DET-19"] = det19
    checks["DET-20"] = workshop(
        "DET-20",
        "Verify WAF rule review process and exception handling for false positives.",
    )

    def det21(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        regional_acls = _waf_web_acls(ctx, "REGIONAL")
        managed_rule_acl_count = 0
        for acl in regional_acls:
            acl_name = str(property_value(acl, ["Name"]) or "")
            acl_id = str(property_value(acl, ["Id"]) or "")
            if not acl_name or not acl_id:
                continue
            detail = ctx.invoke_aws_cli(
                [
                    "wafv2",
                    "get-web-acl",
                    "--name",
                    acl_name,
                    "--scope",
                    "REGIONAL",
                    "--id",
                    acl_id,
                ]
            )
            if detail is None:
                continue
            web_acl = property_value(detail, ["WebACL"])
            rules = property_value(web_acl, ["Rules"]) if isinstance(web_acl, dict) else None
            if not isinstance(rules, list):
                continue
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                statement = property_value(rule, ["Statement"])
                if isinstance(statement, dict) and property_value(statement, ["ManagedRuleGroupStatement"]):
                    managed_rule_acl_count += 1
                    break
        if managed_rule_acl_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-21",
                "PASS",
                {
                    "regional_web_acl_count": collection_count(regional_acls),
                    "managed_rule_web_acl_count": managed_rule_acl_count,
                },
                "WAF managed rule groups are in use",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-21",
            "PARTIAL",
            {
                "regional_web_acl_count": collection_count(regional_acls),
                "managed_rule_web_acl_count": 0,
            },
            "No WAF managed rule groups detected on regional web ACLs",
        )

    checks["DET-21"] = det21

    def det22(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        regional_acls = _waf_web_acls(ctx, "REGIONAL")
        logging_enabled_count = 0
        for acl in regional_acls:
            acl_name = str(property_value(acl, ["Name"]) or "")
            acl_id = str(property_value(acl, ["Id"]) or "")
            if not acl_name or not acl_id:
                continue
            logging_data = ctx.invoke_aws_cli(
                [
                    "wafv2",
                    "get-logging-configuration",
                    "--resource-arn",
                    str(property_value(acl, ["ARN"]) or ""),
                ]
            )
            if logging_data is not None and has_property(logging_data, "LoggingConfiguration"):
                logging_enabled_count += 1
        if logging_enabled_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-22",
                "PASS",
                {
                    "regional_web_acl_count": collection_count(regional_acls),
                    "logging_enabled_count": logging_enabled_count,
                },
                "WAF logging is enabled for one or more web ACLs",
            )
        if collection_count(regional_acls) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-22",
                "FAIL",
                {
                    "regional_web_acl_count": collection_count(regional_acls),
                    "logging_enabled_count": 0,
                },
                "WAF web ACLs exist but logging is not enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-22",
            "PARTIAL",
            {"regional_web_acl_count": 0, "logging_enabled_count": 0},
            "No regional WAF web ACLs found to assess logging",
        )

    checks["DET-22"] = det22

    def det23(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        api_data = ctx.invoke_aws_cli(["apigateway", "get-rest-apis"])
        api_count = 0
        protected_api_count = 0
        if api_data is not None and has_property(api_data, "items"):
            for api in cli_array(property_value(api_data, ["items"])):
                if not isinstance(api, dict):
                    continue
                api_count += 1
                api_id = str(property_value(api, ["id"]) or "")
                if not api_id:
                    continue
                stage_data = ctx.invoke_aws_cli(["apigateway", "get-stages", "--rest-api-id", api_id])
                if stage_data is None or not has_property(stage_data, "item"):
                    continue
                for stage in cli_array(property_value(stage_data, ["item"])):
                    if not isinstance(stage, dict):
                        continue
                    web_acl_arn = str(property_value(stage, ["webAclArn"]) or "")
                    if web_acl_arn:
                        protected_api_count += 1
                        break
        evidence = {"api_count": api_count, "protected_api_count": protected_api_count}
        if api_count == 0:
            return ctx.results.not_applicable_no_resources(
                account_id, account_name, region, "DET-23", evidence, "No API Gateway REST APIs in region"
            )
        if protected_api_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DET-23",
                "PASS",
                evidence,
                "API Gateway stages are protected by WAF",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DET-23",
            "FAIL",
            evidence,
            "API Gateway APIs exist without WAF association on stages",
        )

    checks["DET-23"] = det23
    checks["DET-24"] = workshop(
        "DET-24",
        "Verify threat intelligence feeds and custom indicators are integrated into detection workflows.",
    )
    checks["DET-25"] = workshop(
        "DET-25",
        "Verify detection coverage mapping against MITRE ATT&CK or equivalent framework.",
    )
    checks["DET-26"] = workshop(
        "DET-26",
        "Verify periodic detection capability review and purple-team exercises are performed.",
    )
    checks["DET-27"] = workshop(
        "DET-27",
        "Verify third-party EDR/SIEM integration and correlation with AWS-native detection services.",
    )
    checks["DET-28"] = workshop(
        "DET-28",
        "Verify continuous improvement process for detection capability maturity.",
    )

    if len(checks) != 28:
        raise RuntimeError(f"DET domain must define 28 controls, found {len(checks)}")

    return DomainModule(code="DET", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
