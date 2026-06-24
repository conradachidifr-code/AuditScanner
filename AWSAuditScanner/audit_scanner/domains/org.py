"""ORG domain controls."""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "ORG-01": "P0",
    "ORG-02": "P0",
    "ORG-03": "P0",
    "ORG-04": "P0",
    "ORG-05": "P1",
    "ORG-06": "P0",
    "ORG-07": "P0",
    "ORG-08": "P1",
    "ORG-09": "P0",
    "ORG-10": "P2",
    "ORG-11": "P2",
    "ORG-12": "P0",
    "ORG-13": "P0",
    "ORG-14": "P0",
    "ORG-15": "P1",
    "ORG-16": "P0",
    "ORG-17": "P2",
    "ORG-18": "P0",
    "ORG-19": "P0",
}

_ORG_LOG_SCP_PATTERNS = (
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "DeleteLogGroup",
    "PutRetentionPolicy",
    "PutBucketPolicy",
    "DeleteBucket",
)
_ORG_SEC_SCP_PATTERNS = (
    "guardduty:DeleteDetector",
    "guardduty:DisassociateFromMasterAccount",
    "securityhub:DisableSecurityHub",
    "securityhub:DeleteInvitations",
    "config:DeleteConfigurationRecorder",
    "config:StopConfigurationRecorder",
    "macie2:DisableMacie",
    "access-analyzer:DeleteAnalyzer",
)


def _org_global_control_gate(
    account_id: str, account_name: str, region: str, control_id: str, ctx: CheckContext
) -> AuditResult | None:
    return ctx.results.global_control_gate(account_id, account_name, region, control_id)


def _org_scp_summaries(ctx: CheckContext) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["organizations", "list-policies", "--filter", "SERVICE_CONTROL_POLICY"])
    if data is None:
        return None
    if has_property(data, "Policies"):
        return [item for item in cli_array(property_value(data, ["Policies"])) if isinstance(item, dict)]
    return []


def _org_policy_document_text(ctx: CheckContext, policy_id: str) -> str | None:
    data = ctx.invoke_aws_cli(["organizations", "describe-policy", "--policy-id", policy_id])
    if data is None:
        return None
    if not has_property(data, "Policy"):
        return None
    policy_obj = property_value(data, ["Policy"])
    if not isinstance(policy_obj, dict):
        return None
    if not has_property(policy_obj, "Content"):
        return None
    return str(property_value(policy_obj, ["Content"]) or "")


def _org_scp_documents(ctx: CheckContext) -> dict[str, Any] | None:
    scps = _org_scp_summaries(ctx)
    if scps is None:
        return None
    documents: list[dict[str, Any]] = []
    unreadable_count = 0
    for scp in scps:
        if not has_property(scp, "Id"):
            continue
        policy_id = str(property_value(scp, ["Id"]) or "")
        content = _org_policy_document_text(ctx, policy_id)
        if content is None:
            unreadable_count += 1
            documents.append(
                {
                    "Id": policy_id,
                    "Name": str(property_value(scp, ["Name"]) or ""),
                    "Content": None,
                    "IsReadable": False,
                }
            )
            continue
        documents.append(
            {
                "Id": policy_id,
                "Name": str(property_value(scp, ["Name"]) or ""),
                "Content": content,
                "IsReadable": True,
            }
        )
    return {
        "ScpCount": collection_count(scps),
        "Documents": list(documents),
        "UnreadableCount": unreadable_count,
    }


def _org_personal_email(email_address: str) -> bool:
    if not email_address or not email_address.strip():
        return True
    personal_domains = [
        "gmail.com",
        "googlemail.com",
        "hotmail.com",
        "outlook.com",
        "live.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
        "aol.com",
    ]
    lower_email = email_address.lower()
    return any(lower_email.endswith(f"@{domain}") for domain in personal_domains)


def _org_iam_roles(ctx: CheckContext) -> list[dict[str, Any]] | None:
    roles: list[dict[str, Any]] = []
    marker: str | None = None
    while True:
        args = ["iam", "list-roles", "--max-items", "1000"]
        if marker:
            args.extend(["--marker", marker])
        data = ctx.invoke_aws_cli(args)
        if data is None:
            return None
        if has_property(data, "Roles"):
            for role in cli_array(property_value(data, ["Roles"])):
                if isinstance(role, dict):
                    roles.append(role)
        marker = None
        if has_property(data, "Marker"):
            marker_value = str(property_value(data, ["Marker"]) or "")
            if marker_value.strip():
                is_truncated = True
                if has_property(data, "IsTruncated"):
                    is_truncated = property_value(data, ["IsTruncated"]) is True
                if is_truncated:
                    marker = marker_value
        if not marker:
            break
    return roles


def _org_role_attached_policy_match(ctx: CheckContext, role_name: str, policy_patterns: list[str]) -> bool:
    data = ctx.invoke_aws_cli(["iam", "list-attached-role-policies", "--role-name", role_name])
    if data is None:
        return False
    if not has_property(data, "AttachedPolicies"):
        return False
    for policy in cli_array(property_value(data, ["AttachedPolicies"])):
        if not isinstance(policy, dict):
            continue
        policy_name = str(property_value(policy, ["PolicyName"]) or "")
        policy_arn = str(property_value(policy, ["PolicyArn"]) or "")
        low_name = policy_name.lower()
        low_arn = policy_arn.lower()
        for pattern in policy_patterns:
            low_pattern = pattern.lower()
            if low_pattern in low_name or low_pattern in low_arn:
                return True
    return False


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def org01(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-01", ctx)
        if gate:
            return gate
        scp_data = _org_scp_documents(ctx)
        if scp_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-01")
        scp_count = int(property_value(scp_data, ["ScpCount"]) or 0)
        if scp_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-01",
                "FAIL",
                {"scp_count": 0, "deny_statement_count": 0, "scp_names": []},
                "No deny SCPs found",
            )
        deny_statement_count = 0
        matching_policy_names: list[str] = []
        for document in cli_array(property_value(scp_data, ["Documents"])):
            if not isinstance(document, dict):
                continue
            if not has_property(document, "IsReadable"):
                continue
            content = str(property_value(document, ["Content"]) or "")
            has_deny = re.search(r'"Effect"\s*:\s*"Deny"', content, re.IGNORECASE) is not None
            covers_logs = any(re.search(re.escape(pattern), content, re.IGNORECASE) for pattern in _ORG_LOG_SCP_PATTERNS)
            if has_deny and covers_logs:
                deny_statement_count += 1
                if has_property(document, "Name"):
                    matching_policy_names.append(str(property_value(document, ["Name"]) or ""))
        evidence = {
            "scp_count": scp_count,
            "deny_statement_count": deny_statement_count,
            "scp_names": list(matching_policy_names),
            "unreadable_count": int(property_value(scp_data, ["UnreadableCount"]) or 0),
        }
        if deny_statement_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-01",
                "PASS",
                evidence,
                "SCPs exist with Deny statements protecting logging services",
            )
        if int(property_value(scp_data, ["UnreadableCount"]) or 0) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-01",
                "PARTIAL",
                evidence,
                "SCPs exist but content not readable",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "ORG-01", "FAIL", evidence, "No deny SCPs found"
        )

    checks["ORG-01"] = org01

    def org02(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-02", ctx)
        if gate:
            return gate
        scp_data = _org_scp_documents(ctx)
        if scp_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-02")
        deny_actions_found: list[str] = []
        for document in cli_array(property_value(scp_data, ["Documents"])):
            if not isinstance(document, dict):
                continue
            if not has_property(document, "IsReadable"):
                continue
            content = str(property_value(document, ["Content"]) or "")
            for pattern in _ORG_SEC_SCP_PATTERNS:
                if re.search(re.escape(pattern), content, re.IGNORECASE):
                    deny_actions_found.append(pattern)
        unique_actions: list[str] = []
        for action in deny_actions_found:
            if action not in unique_actions:
                unique_actions.append(action)
        evidence = {
            "deny_actions_found": list(unique_actions),
            "scp_count": int(property_value(scp_data, ["ScpCount"]) or 0),
        }
        if collection_count(unique_actions) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-02",
                "PASS",
                evidence,
                "At least one SCP denies disabling security services",
            )
        if (
            int(property_value(scp_data, ["UnreadableCount"]) or 0) > 0
            and int(property_value(scp_data, ["ScpCount"]) or 0) > 0
        ):
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-02",
                "PARTIAL",
                evidence,
                "SCPs exist but content not readable",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "ORG-02", "FAIL", evidence, "No such denial found"
        )

    checks["ORG-02"] = org02

    def org03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-03", ctx)
        if gate:
            return gate
        scp_data = _org_scp_documents(ctx)
        if scp_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-03")
        matched_policy_names: list[str] = []
        region_values: list[str] = []
        for document in cli_array(property_value(scp_data, ["Documents"])):
            if not isinstance(document, dict):
                continue
            if not has_property(document, "IsReadable"):
                continue
            content = str(property_value(document, ["Content"]) or "")
            if re.search(r"aws:RequestedRegion", content, re.IGNORECASE) is None:
                continue
            if has_property(document, "Name"):
                matched_policy_names.append(str(property_value(document, ["Name"]) or ""))
            for match in re.finditer(
                r'"(eu-[a-z0-9-]+|us-[a-z0-9-]+|ap-[a-z0-9-]+|ca-[a-z0-9-]+|sa-[a-z0-9-]+|af-[a-z0-9-]+|me-[a-z0-9-]+)"',
                content,
                re.IGNORECASE,
            ):
                region_value = match.group(1)
                if region_value not in region_values:
                    region_values.append(region_value)
        evidence = {
            "scp_count": int(property_value(scp_data, ["ScpCount"]) or 0),
            "policy_names": list(matched_policy_names),
            "regions_referenced": list(region_values),
        }
        if collection_count(matched_policy_names) > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "ORG-03", "PASS", evidence, "Region restriction SCP exists"
            )
        if (
            int(property_value(scp_data, ["UnreadableCount"]) or 0) > 0
            and int(property_value(scp_data, ["ScpCount"]) or 0) > 0
        ):
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-03",
                "PARTIAL",
                evidence,
                "SCPs exist but content not readable",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "ORG-03", "FAIL", evidence, "No region restriction"
        )

    checks["ORG-03"] = org03

    def org04(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-04", ctx)
        if gate:
            return gate
        roots_data = ctx.invoke_aws_cli(["organizations", "list-roots"])
        if roots_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-04")
        roots = cli_array(property_value(roots_data, ["Roots"])) if has_property(roots_data, "Roots") else []
        ou_names: list[str] = []
        orphan_accounts: list[dict[str, str]] = []
        for root in roots:
            if not isinstance(root, dict) or not has_property(root, "Id"):
                continue
            root_id = str(property_value(root, ["Id"]) or "")
            ou_data = ctx.invoke_aws_cli(
                ["organizations", "list-organizational-units-for-parent", "--parent-id", root_id]
            )
            if ou_data and has_property(ou_data, "OrganizationalUnits"):
                for ou in cli_array(property_value(ou_data, ["OrganizationalUnits"])):
                    if isinstance(ou, dict) and has_property(ou, "Name"):
                        ou_names.append(str(property_value(ou, ["Name"]) or ""))
            account_data = ctx.invoke_aws_cli(
                ["organizations", "list-accounts-for-parent", "--parent-id", root_id]
            )
            if account_data and has_property(account_data, "Accounts"):
                for account in cli_array(property_value(account_data, ["Accounts"])):
                    if not isinstance(account, dict):
                        continue
                    orphan_accounts.append(
                        {
                            "id": str(property_value(account, ["Id"]) or ""),
                            "name": str(property_value(account, ["Name"]) or ""),
                        }
                    )
        evidence = {
            "ou_count": collection_count(ou_names),
            "ou_names": list(ou_names),
            "root_orphan_account_count": collection_count(orphan_accounts),
            "root_orphan_accounts": list(orphan_accounts[:10]),
        }
        if collection_count(orphan_accounts) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-04",
                "FAIL",
                evidence,
                "One or more active accounts are attached directly under the organization root",
            )
        if collection_count(ou_names) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-04",
                "PARTIAL",
                evidence,
                "No organizational units found; verify OU segmentation in workshop",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "ORG-04",
            "PASS",
            evidence,
            "Organizational units exist and no accounts are directly under root",
        )

    checks["ORG-04"] = org04

    def org05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-05", ctx)
        if gate:
            return gate
        account_data = ctx.invoke_aws_cli(["organizations", "list-accounts"])
        if account_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-05")
        dedicated_types = {
            "security": False,
            "log_archive": False,
            "network": False,
            "shared": False,
        }
        matched_accounts: list[dict[str, str]] = []
        if has_property(account_data, "Accounts"):
            for account in cli_array(property_value(account_data, ["Accounts"])):
                if not isinstance(account, dict):
                    continue
                if str(property_value(account, ["Status"]) or "") != "ACTIVE":
                    continue
                account_name_value = str(property_value(account, ["Name"]) or "").lower()
                account_id_value = str(property_value(account, ["Id"]) or "")
                if re.search(r"security|sec-", account_name_value):
                    dedicated_types["security"] = True
                if re.search(r"log.?archive|logarchive|logs", account_name_value):
                    dedicated_types["log_archive"] = True
                if re.search(r"network|net-", account_name_value):
                    dedicated_types["network"] = True
                if re.search(r"shared|common|core", account_name_value):
                    dedicated_types["shared"] = True
                if collection_count(matched_accounts) < 20:
                    matched_accounts.append({"id": account_id_value, "name": account_name_value})
        found_count = sum(1 for present in dedicated_types.values() if present)
        evidence = {
            "dedicated_account_types": dedicated_types,
            "dedicated_type_count": found_count,
            "active_accounts_sample": list(matched_accounts),
        }
        if found_count >= 3:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-05",
                "PASS",
                evidence,
                "Dedicated security, logging, network or shared accounts detected by naming",
            )
        if found_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-05",
                "PARTIAL",
                evidence,
                "Some dedicated account types detected; verify full account separation",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "ORG-05",
            "FAIL",
            evidence,
            "No dedicated security, log-archive, network or shared accounts detected",
        )

    checks["ORG-05"] = org05

    def org06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "ORG-06",
            "PARTIAL",
            None,
            "Verify account vending machine exists. Check Service Catalog products.",
        )

    checks["ORG-06"] = org06

    def org07(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-07", ctx)
        if gate:
            return gate
        guard_duty_data = ctx.invoke_aws_cli(["guardduty", "list-organization-admin-accounts"])
        delegated_data = ctx.invoke_aws_cli(["organizations", "list-delegated-administrators"])
        if guard_duty_data is None and delegated_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-07")
        guard_duty_admin_accounts: list[dict[str, str]] = []
        if guard_duty_data and has_property(guard_duty_data, "AdminAccounts"):
            for admin_account in cli_array(property_value(guard_duty_data, ["AdminAccounts"])):
                if not isinstance(admin_account, dict):
                    continue
                guard_duty_admin_accounts.append(
                    {
                        "account_id": str(property_value(admin_account, ["AccountId"]) or ""),
                        "admin_status": str(property_value(admin_account, ["AdminStatus"]) or ""),
                    }
                )
        delegated_admins: list[dict[str, Any]] = []
        if delegated_data and has_property(delegated_data, "DelegatedAdministrators"):
            for delegated_admin in cli_array(property_value(delegated_data, ["DelegatedAdministrators"])):
                if not isinstance(delegated_admin, dict):
                    continue
                delegated_admins.append(
                    {
                        "account_id": str(property_value(delegated_admin, ["Id"]) or ""),
                        "service_principals": cli_array(property_value(delegated_admin, ["ServicePrincipal"])),
                    }
                )
        guard_duty_delegated = collection_count(guard_duty_admin_accounts) > 0
        security_hub_delegated = False
        config_delegated = False
        macie_delegated = False
        if not guard_duty_delegated and collection_count(delegated_admins) > 0:
            for delegated_admin in delegated_admins:
                for principal in cli_array(property_value(delegated_admin, ["service_principals"])):
                    principal_text = str(principal or "").lower()
                    if "guardduty" in principal_text:
                        guard_duty_delegated = True
                    if "securityhub" in principal_text:
                        security_hub_delegated = True
                    if "config" in principal_text:
                        config_delegated = True
                    if "macie" in principal_text:
                        macie_delegated = True
        evidence = {
            "guardduty_admin_accounts": list(guard_duty_admin_accounts),
            "delegated_administrators": list(delegated_admins),
            "security_hub_delegated": security_hub_delegated,
            "config_delegated": config_delegated,
            "macie_delegated": macie_delegated,
        }
        delegated_count = sum(
            1
            for flag in (guard_duty_delegated, security_hub_delegated, config_delegated, macie_delegated)
            if flag
        )
        if delegated_count >= 2:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-07",
                "PASS",
                evidence,
                "Delegated administrators configured for multiple security services",
            )
        if delegated_count == 1:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-07",
                "PARTIAL",
                evidence,
                "Only one security service has a delegated administrator",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "ORG-07", "FAIL", evidence, "No delegated admin for security services"
        )

    checks["ORG-07"] = org07
    checks["ORG-08"] = (
        lambda account_id, account_name, region, ctx: ctx.results.workshop_control(
            account_id,
            account_name,
            region,
            "ORG-08",
            "Verify log-archive account exists in isolated OU. Check access restrictions.",
        )
    )

    def org09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        identity_data = ctx.invoke_aws_cli(["sts", "get-caller-identity"])
        if identity_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-09")
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "ORG-09",
            "PARTIAL",
            {
                "account": str(property_value(identity_data, ["Account"]) or ""),
                "arn": str(property_value(identity_data, ["Arn"]) or ""),
                "user_id": str(property_value(identity_data, ["UserId"]) or ""),
            },
            "Verify Security account hosts: GuardDuty admin, CloudTrail bucket, Config aggregator.",
        )

    checks["ORG-09"] = org09

    def org10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["budgets", "describe-budgets", "--account-id", account_id])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-10")
        budgets = cli_array(property_value(data, ["Budgets"])) if has_property(data, "Budgets") else []
        budgets_with_alerts: list[dict[str, Any]] = []
        security_budget_count = 0
        for budget in budgets:
            if not isinstance(budget, dict):
                continue
            budget_name = str(property_value(budget, ["BudgetName"]) or "").lower()
            is_security_budget = bool(
                re.search(r"guardduty|securityhub|cloudtrail|config|macie|security", budget_name)
            )
            alert_thresholds: list[str] = []
            if has_property(budget, "NotificationsWithSubscribers"):
                for notification in cli_array(property_value(budget, ["NotificationsWithSubscribers"])):
                    if not isinstance(notification, dict):
                        continue
                    if has_property(notification, "Notification"):
                        notification_obj = property_value(notification, ["Notification"])
                        threshold = property_value(notification_obj, ["Threshold"]) if notification_obj else None
                        if threshold:
                            alert_thresholds.append(str(threshold))
            if collection_count(alert_thresholds) > 0:
                if is_security_budget:
                    security_budget_count += 1
                budgets_with_alerts.append(
                    {
                        "budget_name": str(property_value(budget, ["BudgetName"]) or ""),
                        "alert_thresholds": list(alert_thresholds),
                        "security_related": is_security_budget,
                    }
                )
        evidence = {
            "budget_count": collection_count(budgets),
            "budgets_with_alerts": list(budgets_with_alerts),
            "budgets_with_alert_count": collection_count(budgets_with_alerts),
            "security_budget_with_alert_count": security_budget_count,
        }
        if security_budget_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-10",
                "PASS",
                evidence,
                "At least one security-related budget with alerts is configured",
            )
        if collection_count(budgets_with_alerts) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-10",
                "PARTIAL",
                evidence,
                "Budget alerts exist but none appear security-service specific",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "ORG-10", "FAIL", evidence, "No budgets or no alerts"
        )

    checks["ORG-10"] = org10

    def org11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "ORG-11",
            "PARTIAL",
            None,
            "Verify quota monitoring exists for GuardDuty, Lambda, CloudTrail.",
        )

    checks["ORG-11"] = org11

    def org12(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-12", ctx)
        if gate:
            return gate
        shares_data = ctx.invoke_aws_cli(["ram", "list-resource-shares", "--resource-owner", "SELF"])
        if shares_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-12")
        shares = cli_array(property_value(shares_data, ["resourceShares"])) if has_property(shares_data, "resourceShares") else []
        principals_data = ctx.invoke_aws_cli(["ram", "list-principals", "--resource-owner", "SELF"])
        resources_data = ctx.invoke_aws_cli(["ram", "list-resources", "--resource-owner", "SELF"])
        principal_count = 0
        resource_count = 0
        if principals_data and has_property(principals_data, "principals"):
            principal_count = collection_count(cli_array(property_value(principals_data, ["principals"])))
        if resources_data and has_property(resources_data, "resources"):
            resource_count = collection_count(cli_array(property_value(resources_data, ["resources"])))
        evidence = {
            "resource_share_count": collection_count(shares),
            "principal_count": principal_count,
            "shared_resource_count": resource_count,
        }
        if collection_count(shares) > 0 and principal_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-12",
                "PARTIAL",
                evidence,
                "RAM resource shares exist; verify authorized principals and periodic review in workshop",
            )
        if collection_count(shares) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-12",
                "PARTIAL",
                evidence,
                "RAM shares exist but no principals returned",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "ORG-12",
            "FAIL",
            evidence,
            "No RAM resource shares found",
        )

    checks["ORG-12"] = org12
    checks["ORG-13"] = (
        lambda account_id, account_name, region, ctx: ctx.results.workshop_control(
            account_id,
            account_name,
            region,
            "ORG-13",
            "Verify IAM, Route53, CloudFront governance defined at org level. Check SCP coverage for us-east-1.",
        )
    )

    def org14(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-14", ctx)
        if gate:
            return gate
        roles = _org_iam_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-14")
        matching_roles: list[dict[str, str]] = []
        for role in roles:
            role_name = str(property_value(role, ["RoleName"]) or "")
            if re.search(r"Audit|ReadOnly|SecurityAudit", role_name, re.IGNORECASE) is None:
                continue
            has_audit_policy = _org_role_attached_policy_match(
                ctx, role_name, policy_patterns=["ReadOnly", "SecurityAudit"]
            )
            has_elevated_policy = _org_role_attached_policy_match(
                ctx, role_name, policy_patterns=["AdministratorAccess", "IAMFullAccess"]
            )
            max_session_duration = int(property_value(role, ["MaxSessionDuration"]) or 0)
            if not has_audit_policy:
                continue
            matching_roles.append(
                {
                    "role_name": role_name,
                    "role_arn": str(property_value(role, ["Arn"]) or ""),
                    "max_session_duration": max_session_duration,
                    "has_elevated_policy": has_elevated_policy,
                }
            )
        elevated_roles = [item for item in matching_roles if item.get("has_elevated_policy")]
        long_session_roles = [
            item for item in matching_roles if int(item.get("max_session_duration") or 0) > 3600
        ]
        evidence = {
            "matching_role_count": collection_count(matching_roles),
            "roles": list(matching_roles),
            "elevated_policy_role_count": collection_count(elevated_roles),
            "long_session_role_count": collection_count(long_session_roles),
        }
        if collection_count(elevated_roles) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-14",
                "FAIL",
                evidence,
                "Audit role has elevated administrator or IAM full access policy attached",
            )
        if collection_count(matching_roles) > 0:
            if collection_count(long_session_roles) > 0:
                return ctx.results.audit_result(
                    account_id,
                    account_name,
                    region,
                    "ORG-14",
                    "PARTIAL",
                    evidence,
                    "Audit role found but MaxSessionDuration exceeds one hour",
                )
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-14",
                "PASS",
                evidence,
                "Audit role found with ReadOnly or SecurityAudit managed policy",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "ORG-14", "FAIL", evidence, "No audit-specific role found"
        )

    checks["ORG-14"] = org14

    def org15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-15", ctx)
        if gate:
            return gate
        roles = _org_iam_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-15")
        break_glass_roles: list[dict[str, str]] = []
        for role in roles:
            role_name = str(property_value(role, ["RoleName"]) or "")
            if re.search(r"BreakGlass|Emergency", role_name, re.IGNORECASE):
                break_glass_roles.append(
                    {
                        "role_name": role_name,
                        "role_arn": str(property_value(role, ["Arn"]) or ""),
                    }
                )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "ORG-15",
            "PARTIAL",
            {
                "break_glass_role_count": collection_count(break_glass_roles),
                "roles": list(break_glass_roles),
            },
            "Verify break-glass procedure exists with activation log, RSSI notification.",
        )

    checks["ORG-15"] = org15

    def org16(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _org_global_control_gate(account_id, account_name, region, "ORG-16", ctx)
        if gate:
            return gate
        scp_data = _org_scp_documents(ctx)
        if scp_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-16")
        policy_names: list[str] = []
        for document in cli_array(property_value(scp_data, ["Documents"])):
            if not isinstance(document, dict):
                continue
            if has_property(document, "Name"):
                policy_names.append(str(property_value(document, ["Name"]) or ""))
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "ORG-16",
            "PARTIAL",
            {
                "scp_count": int(property_value(scp_data, ["ScpCount"]) or 0),
                "scp_names": list(policy_names),
                "unreadable": int(property_value(scp_data, ["UnreadableCount"]) or 0),
            },
            "Verify service catalog / allowed services list exists.",
        )

    checks["ORG-16"] = org16
    checks["ORG-17"] = (
        lambda account_id, account_name, region, ctx: ctx.results.workshop_control(
            account_id,
            account_name,
            region,
            "ORG-17",
            "Verify IaC modules are versioned via GitLab tags/releases.",
        )
    )

    def org18(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        security_contact_data = ctx.invoke_aws_cli(
            ["account", "get-alternate-contact", "--alternate-contact-type", "SECURITY"]
        )
        billing_contact_data = ctx.invoke_aws_cli(
            ["account", "get-alternate-contact", "--alternate-contact-type", "BILLING"]
        )
        original_region = ctx.aws.region
        support_data = None
        try:
            ctx.aws.region = "us-east-1"
            support_data = ctx.invoke_aws_cli(["support", "describe-severity-levels"])
        finally:
            ctx.aws.region = original_region
        if security_contact_data is None and billing_contact_data is None and support_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "ORG-18")
        security_email = None
        security_name = None
        if security_contact_data and has_property(security_contact_data, "AlternateContact"):
            alternate_contact = property_value(security_contact_data, ["AlternateContact"])
            security_email = str(property_value(alternate_contact, ["EmailAddress"]) or "")
            security_name = str(property_value(alternate_contact, ["Name"]) or "")
        billing_email = None
        if billing_contact_data and has_property(billing_contact_data, "AlternateContact"):
            alternate_contact = property_value(billing_contact_data, ["AlternateContact"])
            billing_email = str(property_value(alternate_contact, ["EmailAddress"]) or "")
        evidence = {
            "security_contact": {
                "configured": bool(security_email and security_email.strip()),
                "email": security_email,
                "name": security_name,
            },
            "billing_contact": {
                "configured": bool(billing_email and billing_email.strip()),
                "email": billing_email,
            },
            "support_severity_levels_available": support_data is not None,
        }
        if not security_email or not security_email.strip():
            return ctx.results.audit_result(
                account_id, account_name, region, "ORG-18", "FAIL", evidence, "No SECURITY contact configured"
            )
        if _org_personal_email(security_email):
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-18",
                "FAIL",
                evidence,
                "SECURITY contact uses a personal email address",
            )
        if support_data is None:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "ORG-18",
                "PARTIAL",
                evidence,
                "SECURITY contact configured but AWS Support plan could not be verified via Support API",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "ORG-18",
            "PASS",
            evidence,
            "SECURITY alternate contact configured and AWS Support API is available",
        )

    checks["ORG-18"] = org18
    checks["ORG-19"] = (
        lambda account_id, account_name, region, ctx: ctx.results.workshop_control(
            account_id,
            account_name,
            region,
            "ORG-19",
            "Verify SCP documentation exists with owner per SCP and exception process.",
        )
    )

    if len(checks) != 19:
        raise RuntimeError(f"ORG domain must define 19 controls, found {len(checks)}")

    return DomainModule(code="ORG", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
