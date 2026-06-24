"""IAM domain controls."""

from __future__ import annotations

import base64
import csv
import io
import json
import re
import time
import urllib.parse
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "IAM-01": "P0",
    "IAM-02": "P0",
    "IAM-03": "P0",
    "IAM-04": "P0",
    "IAM-05": "P0",
    "IAM-06": "P0",
    "IAM-07": "P0",
    "IAM-08": "P0",
    "IAM-09": "P0",
    "IAM-10": "P0",
    "IAM-11": "P0",
    "IAM-12": "P0",
    "IAM-13": "P0",
    "IAM-14": "P0",
    "IAM-15": "P0",
    "IAM-16": "P0",
    "IAM-17": "P0",
    "IAM-18": "P0",
    "IAM-19": "P0",
    "IAM-20": "P0",
    "IAM-21": "P0",
    "IAM-22": "P0",
    "IAM-23": "P0",
    "IAM-24": "P0",
    "IAM-25": "P0",
    "IAM-26": "P0",
    "IAM-27": "P0",
    "IAM-28": "P0",
    "IAM-29": "P0",
    "IAM-30": "P1",
    "IAM-31": "P0",
    "IAM-32": "P1",
    "IAM-33": "P0",
    "IAM-34": "P0",
    "IAM-35": "P0",
    "IAM-36": "P0",
    "IAM-37": "P0",
    "IAM-38": "P0",
    "IAM-39": "P1",
    "IAM-40": "P1",
    "IAM-41": "P0",
    "IAM-42": "P0",
    "IAM-43": "P0",
    "IAM-44": "P0",
    "IAM-45": "P0",
    "IAM-46": "P0",
    "IAM-47": "P0",
    "IAM-48": "P0",
    "IAM-49": "P0",
    "IAM-50": "P0",
    "IAM-51": "P0",
    "IAM-52": "P0",
    "IAM-53": "P0",
    "IAM-54": "P0",
    "IAM-55": "P0",
}


def _iam_global_control_gate(
    account_id: str, account_name: str, region: str, control_id: str, ctx: CheckContext
) -> AuditResult | None:
    if region == "eu-west-1":
        return None
    return ctx.results.audit_result(
        account_id,
        account_name,
        region,
        control_id,
        "NOT_TESTED",
        None,
        "Global IAM control - evaluated in eu-west-1 only",
    )


def _iso_duration_hours(duration: str) -> int:
    if not duration or not duration.strip():
        return 0
    match = re.match(r"^PT(\d+)H", duration)
    if match:
        return int(match.group(1))
    return 0


def _iam_account_summary_map(ctx: CheckContext) -> dict[str, Any] | None:
    data = ctx.invoke_aws_cli(["iam", "get-account-summary"])
    if data is None:
        return None
    if not has_property(data, "SummaryMap"):
        return {}
    summary = property_value(data, ["SummaryMap"])
    if isinstance(summary, dict):
        return summary
    return {}


def _iam_all_users(ctx: CheckContext) -> list[dict[str, Any]] | None:
    users: list[dict[str, Any]] = []
    marker: str | None = None
    while True:
        args = ["iam", "list-users", "--max-items", "1000"]
        if marker:
            args.extend(["--marker", marker])
        data = ctx.invoke_aws_cli(args)
        if data is None:
            return None
        if has_property(data, "Users"):
            for user in cli_array(property_value(data, ["Users"])):
                if isinstance(user, dict):
                    users.append(user)
        marker = None
        is_truncated = False
        if has_property(data, "IsTruncated"):
            is_truncated = property_value(data, ["IsTruncated"]) is True
        if is_truncated and has_property(data, "Marker"):
            marker_value = str(property_value(data, ["Marker"]) or "")
            if marker_value.strip():
                marker = marker_value
        if not marker:
            break
    return users


def _iam_all_roles(ctx: CheckContext) -> list[dict[str, Any]] | None:
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
        is_truncated = False
        if has_property(data, "IsTruncated"):
            is_truncated = property_value(data, ["IsTruncated"]) is True
        if is_truncated and has_property(data, "Marker"):
            marker_value = str(property_value(data, ["Marker"]) or "")
            if marker_value.strip():
                marker = marker_value
        if not marker:
            break
    return roles


def _iam_user_has_console_access(ctx: CheckContext, user_name: str) -> bool:
    data = ctx.invoke_aws_cli(["iam", "get-login-profile", "--user-name", user_name])
    if data is None:
        return False
    return True


def _iam_user_has_mfa(ctx: CheckContext, user_name: str) -> bool | None:
    data = ctx.invoke_aws_cli(["iam", "list-mfa-devices", "--user-name", user_name])
    if data is None:
        return None
    if has_property(data, "MFADevices"):
        return collection_count(property_value(data, ["MFADevices"])) > 0
    return False


def _iam_generic_user_name(user_name: str) -> bool:
    lower_name = user_name.lower()
    if lower_name == "admin":
        return True
    if lower_name == "shared":
        return True
    if lower_name == "administrator":
        return True
    if lower_name.startswith("shared"):
        return True
    if lower_name.startswith("service") and "owner" not in lower_name:
        return True
    return False


def _iam_user_access_key_summary(ctx: CheckContext, user_name: str) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["iam", "list-access-keys", "--user-name", user_name])
    if data is None:
        return None
    active_keys: list[dict[str, Any]] = []
    if has_property(data, "AccessKeyMetadata"):
        for key in cli_array(property_value(data, ["AccessKeyMetadata"])):
            if isinstance(key, dict) and str(property_value(key, ["Status"]) or "") == "Active":
                active_keys.append(key)
    return active_keys


def _iam_role_has_administrator_access(ctx: CheckContext, role_name: str) -> bool | None:
    data = ctx.invoke_aws_cli(["iam", "list-attached-role-policies", "--role-name", role_name])
    if data is None:
        return None
    if not has_property(data, "AttachedPolicies"):
        return False
    for policy in cli_array(property_value(data, ["AttachedPolicies"])):
        if not isinstance(policy, dict):
            continue
        policy_name = str(property_value(policy, ["PolicyName"]) or "")
        policy_arn = str(property_value(policy, ["PolicyArn"]) or "")
        if policy_name == "AdministratorAccess":
            return True
        if re.search(r":policy/AdministratorAccess$", policy_arn):
            return True
    return False


def _iam_role_trust_policy_text(ctx: CheckContext, role_name: str) -> str | None:
    data = ctx.invoke_aws_cli(["iam", "get-role", "--role-name", role_name])
    if data is None:
        return None
    role = property_value(data, ["Role"])
    if role is None or not isinstance(role, dict):
        return None
    if not has_property(role, "AssumeRolePolicyDocument"):
        return None
    document = str(property_value(role, ["AssumeRolePolicyDocument"]) or "")
    return urllib.parse.unquote(document)


def _iam_cross_account_role(account_id: str, trust_policy_text: str) -> bool:
    if not trust_policy_text or not trust_policy_text.strip():
        return False
    match = re.search(r"arn:aws:iam::(\d{12}):", trust_policy_text)
    if match and match.group(1) != account_id:
        return True
    if re.search(r'"AWS"\s*:\s*"\*"', trust_policy_text):
        return True
    return False


def _iam_trust_policy_has_cross_account_restriction(trust_policy_text: str) -> bool:
    if not trust_policy_text or not trust_policy_text.strip():
        return False
    return bool(
        re.search(r"ExternalId|sts:ExternalId|aws:SourceAccount|aws:SourceArn", trust_policy_text)
    )


def _iam_role_has_wildcard_inline_policy(ctx: CheckContext, role_name: str) -> bool:
    data = ctx.invoke_aws_cli(["iam", "list-role-policies", "--role-name", role_name])
    if data is None or not has_property(data, "PolicyNames"):
        return False
    for policy_name in cli_array(property_value(data, ["PolicyNames"])):
        policy_data = ctx.invoke_aws_cli(
            ["iam", "get-role-policy", "--role-name", role_name, "--policy-name", str(policy_name)]
        )
        if policy_data is None:
            continue
        document = str(property_value(policy_data, ["PolicyDocument"]) or "")
        if re.search(r'"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"', document):
            return True
    return False


def _iam_sso_instances(ctx: CheckContext) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["sso-admin", "list-instances"])
    if data is None:
        return None
    if has_property(data, "Instances"):
        instances = [item for item in cli_array(property_value(data, ["Instances"])) if isinstance(item, dict)]
        return instances
    return []


def _iam_permission_set_details(ctx: CheckContext, instance_arn: str) -> list[dict[str, Any]] | None:
    permission_sets: list[dict[str, Any]] = []
    token: str | None = None
    while True:
        args = [
            "sso-admin",
            "list-permission-sets",
            "--instance-arn",
            instance_arn,
            "--max-results",
            "100",
        ]
        if token:
            args.extend(["--next-token", token])
        list_data = ctx.invoke_aws_cli(args)
        if list_data is None:
            return None
        if has_property(list_data, "PermissionSets"):
            for permission_set_arn in cli_array(property_value(list_data, ["PermissionSets"])):
                describe_data = ctx.invoke_aws_cli(
                    [
                        "sso-admin",
                        "describe-permission-set",
                        "--instance-arn",
                        instance_arn,
                        "--permission-set-arn",
                        str(permission_set_arn),
                    ]
                )
                if describe_data and has_property(describe_data, "PermissionSet"):
                    permission_set = property_value(describe_data, ["PermissionSet"])
                    if isinstance(permission_set, dict):
                        permission_sets.append(permission_set)
        token = None
        if has_property(list_data, "NextToken"):
            token_value = str(property_value(list_data, ["NextToken"]) or "")
            if token_value.strip():
                token = token_value
        if not token:
            break
    return permission_sets


def _iam_permission_set_has_administrator_access(
    ctx: CheckContext, instance_arn: str, permission_set_arn: str
) -> bool | None:
    data = ctx.invoke_aws_cli(
        [
            "sso-admin",
            "list-managed-policies-in-permission-set",
            "--instance-arn",
            instance_arn,
            "--permission-set-arn",
            permission_set_arn,
        ]
    )
    if data is None:
        return None
    if not has_property(data, "AttachedManagedPolicies"):
        return False
    for policy in cli_array(property_value(data, ["AttachedManagedPolicies"])):
        if not isinstance(policy, dict):
            continue
        if str(property_value(policy, ["Name"]) or "") == "AdministratorAccess":
            return True
    return False


def _iam_roles_anywhere_context(ctx: CheckContext) -> dict[str, Any] | None:
    anchor_data = ctx.invoke_aws_cli(["rolesanywhere", "list-trust-anchors"])
    profile_data = ctx.invoke_aws_cli(["rolesanywhere", "list-profiles"])
    if anchor_data is None and profile_data is None:
        return None
    anchors: list[dict[str, Any]] = []
    if anchor_data and has_property(anchor_data, "TrustAnchors"):
        anchors = [item for item in cli_array(property_value(anchor_data, ["TrustAnchors"])) if isinstance(item, dict)]
    profiles: list[dict[str, Any]] = []
    if profile_data and has_property(profile_data, "Profiles"):
        profiles = [item for item in cli_array(property_value(profile_data, ["Profiles"])) if isinstance(item, dict)]
    return {
        "TrustAnchors": anchors,
        "Profiles": profiles,
        "Detected": (collection_count(anchors) > 0 or collection_count(profiles) > 0),
    }


def _iam_roles_anywhere_not_detected_result(
    account_id: str, account_name: str, region: str, control_id: str, ctx: CheckContext
) -> AuditResult:
    return ctx.results.audit_result(
        account_id,
        account_name,
        region,
        control_id,
        "NOT_TESTED",
        None,
        "IAM Roles Anywhere API unavailable, access denied, or not in use in this account",
    )


def _get_iam_credential_report(ctx: CheckContext) -> dict[str, Any] | None:
    if "report" in ctx._credential_report_cache:
        return ctx._credential_report_cache["report"]

    generate_data = ctx.invoke_aws_cli(["iam", "generate-credential-report"])
    if generate_data is None:
        result: dict[str, Any] | None = None
    else:
        result = None
        for _ in range(10):
            state = str(property_value(generate_data, ["State"]) or "")
            if state == "COMPLETE":
                report_data = ctx.invoke_aws_cli(["iam", "get-credential-report"])
                generated_time = None
                if report_data and has_property(report_data, "GeneratedTime"):
                    generated_time = str(property_value(report_data, ["GeneratedTime"]) or "")
                result = {"state": state, "report": report_data, "generated_time": generated_time}
                break
            if state == "FAILED":
                result = {"state": state, "report": None, "generated_time": None}
                break
            time.sleep(2)
            generate_data = ctx.invoke_aws_cli(["iam", "generate-credential-report"])
            if generate_data is None:
                result = None
                break
        else:
            result = {"state": "TIMEOUT", "report": None, "generated_time": None}

    ctx._credential_report_cache["report"] = result
    return result


_IAM_ROLE_SEPARATION_PATTERNS = {
    "admin": re.compile(r"admin|administrator", re.IGNORECASE),
    "security": re.compile(r"sec|security|soc|csirt", re.IGNORECASE),
    "ops": re.compile(r"ops|operation|exploit|devops", re.IGNORECASE),
    "network": re.compile(r"net|network|netw|infra", re.IGNORECASE),
    "readonly": re.compile(r"read|viewer|readonly|view", re.IGNORECASE),
}

_KMS_ADMIN_ACTION_PATTERN = re.compile(
    r"kms:\*|kms:Create|kms:Put|kms:ScheduleKeyDeletion|kms:Disable|kms:Delete|kms:Update",
    re.IGNORECASE,
)
_KMS_USE_ACTION_PATTERN = re.compile(r"kms:Encrypt|kms:Decrypt|kms:GenerateDataKey|kms:ReEncrypt", re.IGNORECASE)


def _iam_root_credential_usage(ctx: CheckContext) -> dict[str, Any] | None:
    credential_report = _get_iam_credential_report(ctx)
    if not credential_report:
        return None
    report = credential_report.get("report")
    if not isinstance(report, dict) or not has_property(report, "Content"):
        return None
    try:
        content = base64.b64decode(str(property_value(report, ["Content"]) or "")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        if str(row.get("user", "")).strip() == "<root_account>":
            return {
                "password_last_used": row.get("password_last_used"),
                "access_key_1_last_used_date": row.get("access_key_1_last_used_date"),
                "access_key_2_last_used_date": row.get("access_key_2_last_used_date"),
            }
    return None


def _iam_role_separation_evidence(roles: list[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, list[str]] = {name: [] for name in _IAM_ROLE_SEPARATION_PATTERNS}
    cumulation_suspects: list[dict[str, Any]] = []
    for role in roles:
        role_name = str(property_value(role, ["RoleName"]) or "")
        matched_buckets = [
            bucket_name
            for bucket_name, pattern in _IAM_ROLE_SEPARATION_PATTERNS.items()
            if pattern.search(role_name)
        ]
        if len(matched_buckets) >= 2 and len(cumulation_suspects) < 10:
            cumulation_suspects.append({"role_name": role_name, "matched_buckets": matched_buckets})
        for bucket_name in matched_buckets:
            if len(buckets[bucket_name]) < 5:
                buckets[bucket_name].append(role_name)
    return {
        "role_buckets": {
            bucket_name: {"count": len(sample_roles), "sample_roles": sample_roles}
            for bucket_name, sample_roles in buckets.items()
        },
        "cumulation_suspects": cumulation_suspects,
    }


def _iam_customer_master_keys(ctx: CheckContext) -> list[dict[str, Any]] | None:
    keys: list[dict[str, Any]] = []
    marker: str | None = None
    while True:
        arguments = ["kms", "list-keys", "--limit", "1000"]
        if marker:
            arguments.extend(["--marker", marker])
        list_data = ctx.invoke_aws_cli(arguments)
        if list_data is None:
            return None
        if has_property(list_data, "Keys"):
            for key in cli_array(property_value(list_data, ["Keys"])):
                key_id = str(property_value(key, ["KeyId"]) or "")
                if not key_id:
                    continue
                describe_data = ctx.invoke_aws_cli(["kms", "describe-key", "--key-id", key_id])
                metadata = property_value(describe_data, ["KeyMetadata"]) if describe_data else None
                if isinstance(metadata, dict) and str(property_value(metadata, ["KeyManager"]) or "") == "CUSTOMER":
                    keys.append(metadata)
        marker = None
        if has_property(list_data, "NextMarker"):
            next_marker = str(property_value(list_data, ["NextMarker"]) or "").strip()
            if next_marker and property_value(list_data, ["Truncated"]) is True:
                marker = next_marker
        if not marker:
            break
    return keys


def _iam_is_ccoe_key(ctx: CheckContext, key_metadata: dict[str, Any]) -> bool:
    key_id = str(property_value(key_metadata, ["KeyId"]) or "")
    tag_data = ctx.invoke_aws_cli(["kms", "list-resource-tags", "--key-id", key_id])
    if tag_data and has_property(tag_data, "Tags"):
        for tag in cli_array(property_value(tag_data, ["Tags"])):
            tag_key = str(property_value(tag, ["TagKey"]) or "")
            tag_value = str(property_value(tag, ["TagValue"]) or "")
            if tag_key == "CCOE-DO-NOT-DELETE" and tag_value.upper() == "TRUE":
                return True
    return False


def _iam_policy_principal_actions(policy_text: str) -> dict[str, set[str]]:
    principal_actions: dict[str, set[str]] = {}
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError:
        return principal_actions
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if str(statement.get("Effect", "")).upper() != "Allow":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        principals = statement.get("Principal", {})
        principal_ids: list[str] = []
        if isinstance(principals, str):
            principal_ids = [principals]
        elif isinstance(principals, dict):
            for value in principals.values():
                if isinstance(value, str):
                    principal_ids.append(value)
                elif isinstance(value, list):
                    principal_ids.extend(str(item) for item in value)
        for principal in principal_ids:
            principal_actions.setdefault(principal, set()).update(str(action) for action in actions)
    return principal_actions


def _iam_kms_dual_access_evidence(ctx: CheckContext) -> dict[str, Any] | None:
    customer_keys = _iam_customer_master_keys(ctx)
    if customer_keys is None:
        return None
    ccoe_keys = [key for key in customer_keys if _iam_is_ccoe_key(ctx, key)]
    dual_access_keys: list[dict[str, Any]] = []
    checked_keys: list[str] = []
    for key_metadata in ccoe_keys:
        key_id = str(property_value(key_metadata, ["KeyId"]) or "")
        checked_keys.append(key_id)
        policy_data = ctx.invoke_aws_cli(["kms", "get-key-policy", "--key-id", key_id, "--policy-name", "default"])
        policy_text = str(property_value(policy_data, ["Policy"]) or "")
        if not policy_text:
            continue
        principal_actions = _iam_policy_principal_actions(policy_text)
        for principal, actions in principal_actions.items():
            action_text = " ".join(sorted(actions))
            has_admin = bool(_KMS_ADMIN_ACTION_PATTERN.search(action_text))
            has_use = bool(_KMS_USE_ACTION_PATTERN.search(action_text))
            if has_admin and has_use:
                dual_access_keys.append({"key_id": key_id, "principal": principal})
    return {
        "ccoe_key_count": collection_count(ccoe_keys),
        "checked_key_ids": checked_keys[:10],
        "dual_access_entries": dual_access_keys[:10],
    }


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(cid: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, cid, notes)

        return _check

    def iam01(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-01", ctx)
        if gate:
            return gate
        root_usage = _iam_root_credential_usage(ctx)
        if root_usage is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-01")
        evidence: dict[str, Any] = {"root_credential_usage": root_usage}
        recent_use_values = [
            str(root_usage.get("password_last_used") or ""),
            str(root_usage.get("access_key_1_last_used_date") or ""),
            str(root_usage.get("access_key_2_last_used_date") or ""),
        ]
        operational_use = any(
            value not in ("", "N/A", "no_information", "not_supported")
            for value in recent_use_values
        )
        if operational_use:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-01",
                "FAIL",
                evidence,
                "Root account shows recent operational usage in credential report",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-01",
            "PASS",
            evidence,
            "Root credential report shows no recent operational usage",
        )

    checks["IAM-01"] = iam01

    def iam02(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-02", ctx)
        if gate:
            return gate
        summary = _iam_account_summary_map(ctx)
        if summary is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-02")
        mfa_enabled = 0
        if has_property(summary, "AccountMFAEnabled"):
            value = property_value(summary, ["AccountMFAEnabled"])
            if value is not None:
                mfa_enabled = int(value)
        evidence = {"AccountMFAEnabled": mfa_enabled}
        if mfa_enabled == 1:
            return ctx.results.audit_result(
                account_id, account_name, region, "IAM-02", "PASS", evidence, "Root MFA is enabled"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "IAM-02", "FAIL", evidence, "Root MFA is not enabled"
        )

    checks["IAM-02"] = iam02

    def iam03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-03", ctx)
        if gate:
            return gate
        summary = _iam_account_summary_map(ctx)
        if summary is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-03")
        keys_present = 0
        if has_property(summary, "AccountAccessKeysPresent"):
            value = property_value(summary, ["AccountAccessKeysPresent"])
            if value is not None:
                keys_present = int(value)
        evidence = {"AccountAccessKeysPresent": keys_present}
        if keys_present == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "IAM-03", "PASS", evidence, "No root access keys present"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "IAM-03", "FAIL", evidence, "Root access keys are present"
        )

    checks["IAM-03"] = iam03
    checks["IAM-04"] = workshop(
        "IAM-04",
        "Verify formal procedure exists for root usage (RFC required + MFA). Check Confluence or DEX.",
    )

    def iam05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-05", ctx)
        if gate:
            return gate
        users = _iam_all_users(ctx)
        if users is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-05")
        instances = _iam_sso_instances(ctx)
        console_user_count = 0
        console_usernames: list[str] = []
        for user in users:
            user_name = str(property_value(user, ["UserName"]) or "")
            has_console = _iam_user_has_console_access(ctx, user_name)
            if has_console:
                console_user_count += 1
                if collection_count(console_usernames) < 5:
                    console_usernames.append(user_name)
        evidence = {
            "iam_user_count": collection_count(users),
            "console_user_count": console_user_count,
            "console_usernames": list(console_usernames),
            "identity_center_instance_count": collection_count(instances or []),
        }
        if console_user_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-05",
                "FAIL",
                evidence,
                "Local IAM users with console access found; human access should be federated",
            )
        if collection_count(instances or []) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-05",
                "PARTIAL",
                evidence,
                "No Identity Center instance detected to confirm central IdP federation",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-05",
            "PASS",
            evidence,
            "Identity Center is present and no local console IAM users were found",
        )

    checks["IAM-05"] = iam05

    def iam06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-06", ctx)
        if gate:
            return gate
        users = _iam_all_users(ctx)
        if users is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-06")
        console_user_count = 0
        with_mfa_count = 0
        without_mfa_count = 0
        users_without_mfa: list[str] = []
        for user in users:
            user_name = str(property_value(user, ["UserName"]) or "")
            if not _iam_user_has_console_access(ctx, user_name):
                continue
            console_user_count += 1
            has_mfa = _iam_user_has_mfa(ctx, user_name)
            if has_mfa is True:
                with_mfa_count += 1
            else:
                without_mfa_count += 1
                if collection_count(users_without_mfa) < 5:
                    users_without_mfa.append(user_name)
        evidence = {
            "console_user_count": console_user_count,
            "with_mfa_count": with_mfa_count,
            "without_mfa_count": without_mfa_count,
            "users_without_mfa": list(users_without_mfa),
        }
        if without_mfa_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-06",
                "FAIL",
                evidence,
                "One or more console users do not have MFA",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-06",
            "PASS",
            evidence,
            "All console users have MFA devices",
        )

    checks["IAM-06"] = iam06

    def iam07(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-07", ctx)
        if gate:
            return gate
        instances = _iam_sso_instances(ctx)
        if instances is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-07")
        if collection_count(instances) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-07",
                "PARTIAL",
                {"permission_set_count": 0},
                "No Identity Center instance found to assess session duration",
            )
        duration_buckets: dict[str, int] = {}
        long_duration_sets: list[str] = []
        permission_set_count = 0
        long_session_roles: list[str] = []
        roles = _iam_all_roles(ctx)
        if roles:
            for role in roles:
                max_session = int(property_value(role, ["MaxSessionDuration"]) or 3600)
                if max_session > 3600:
                    role_name = str(property_value(role, ["RoleName"]) or "")
                    if collection_count(long_session_roles) < 10:
                        long_session_roles.append(role_name)
        for instance in instances:
            instance_arn = str(property_value(instance, ["InstanceArn"]) or "")
            if not instance_arn.strip():
                continue
            permission_sets = _iam_permission_set_details(ctx, instance_arn)
            if permission_sets is None:
                continue
            for permission_set in permission_sets:
                permission_set_count += 1
                duration = "PT1H"
                if has_property(permission_set, "SessionDuration"):
                    duration = str(property_value(permission_set, ["SessionDuration"]) or "PT1H")
                duration_buckets[duration] = duration_buckets.get(duration, 0) + 1
                if _iso_duration_hours(duration) > 8 and collection_count(long_duration_sets) < 10:
                    long_duration_sets.append(str(property_value(permission_set, ["Name"]) or ""))
        evidence = {
            "permission_set_count": permission_set_count,
            "duration_buckets": duration_buckets,
            "long_duration_names": list(long_duration_sets),
            "roles_over_1h_session_count": collection_count(long_session_roles),
            "roles_over_1h_session_names": list(long_session_roles),
        }
        if collection_count(long_duration_sets) > 0 or collection_count(long_session_roles) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-07",
                "FAIL",
                evidence,
                "One or more permission sets or IAM roles exceed allowed session duration",
            )
        if permission_set_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-07",
                "PARTIAL",
                evidence,
                "Mixed durations, no documented policy by role level",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-07",
            "PASS",
            evidence,
            "All permission sets are at most PT8H and no IAM roles exceed 1 hour MaxSessionDuration",
        )

    checks["IAM-07"] = iam07

    def iam08(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-08", ctx)
        if gate:
            return gate
        users = _iam_all_users(ctx)
        if users is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-08")
        generic_names: list[str] = []
        for user in users:
            user_name = str(property_value(user, ["UserName"]) or "")
            if _iam_generic_user_name(user_name) and collection_count(generic_names) < 10:
                generic_names.append(user_name)
        evidence = {"user_count": collection_count(users), "generic_names": list(generic_names)}
        if collection_count(generic_names) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-08",
                "FAIL",
                evidence,
                "Generic or shared IAM usernames found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-08",
            "PASS",
            evidence,
            "No generic shared IAM usernames detected",
        )

    checks["IAM-08"] = iam08

    def iam09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-09", ctx)
        if gate:
            return gate
        users = _iam_all_users(ctx)
        if users is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-09")
        instances = _iam_sso_instances(ctx)
        identity_center_active = instances is not None and collection_count(instances) > 0
        active_key_count = 0
        for user in users:
            keys = _iam_user_access_key_summary(ctx, str(property_value(user, ["UserName"]) or ""))
            if keys is None:
                continue
            active_key_count += collection_count(keys)
        evidence = {
            "identity_center_active": identity_center_active,
            "iam_user_count": collection_count(users),
            "active_access_key_count": active_key_count,
        }
        if identity_center_active and active_key_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-09",
                "PASS",
                evidence,
                "Identity Center active with no static access keys",
            )
        if active_key_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-09",
                "FAIL",
                evidence,
                "Static IAM access keys exist for human or long-lived access",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-09",
            "PARTIAL",
            evidence,
            "No static access keys but Identity Center not detected",
        )

    checks["IAM-09"] = iam09

    def iam10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-10", ctx)
        if gate:
            return gate
        roles = _iam_all_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-10")
        separation = _iam_role_separation_evidence(roles)
        populated_buckets = [
            name for name, data in separation["role_buckets"].items() if data["count"] > 0
        ]
        evidence = {
            "role_count": collection_count(roles),
            "role_buckets": separation["role_buckets"],
            "cumulation_suspects": separation["cumulation_suspects"],
        }
        if collection_count(separation["cumulation_suspects"]) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-10",
                "PARTIAL",
                evidence,
                "One or more roles match multiple functional naming buckets; verify role separation",
            )
        if len(populated_buckets) >= 3:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-10",
                "PARTIAL",
                evidence,
                "Role naming suggests separation across admin, security, operations and network functions; verify against naming convention",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-10",
            "PARTIAL",
            evidence,
            "Dedicated admin, security, operations and network roles not clearly identified by naming convention",
        )

    checks["IAM-10"] = iam10

    def iam11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-11", ctx)
        if gate:
            return gate
        roles = _iam_all_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-11")
        admin_roles: list[str] = []
        wildcard_inline_roles: list[str] = []
        admin_role_count = 0
        for role in roles:
            role_name = str(property_value(role, ["RoleName"]) or "")
            has_admin = _iam_role_has_administrator_access(ctx, role_name)
            if has_admin is True:
                admin_role_count += 1
                if collection_count(admin_roles) < 10:
                    admin_roles.append(role_name)
            if re.search(r"Deploy|Pipeline|CICD|Script", role_name, re.IGNORECASE):
                if _iam_role_has_wildcard_inline_policy(ctx, role_name):
                    if collection_count(wildcard_inline_roles) < 10:
                        wildcard_inline_roles.append(role_name)
        evidence = {
            "role_count": collection_count(roles),
            "administrator_role_count": admin_role_count,
            "administrator_roles": list(admin_roles),
            "wildcard_inline_roles": list(wildcard_inline_roles),
        }
        if collection_count(wildcard_inline_roles) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-11",
                "FAIL",
                evidence,
                "Pipeline or deployment roles have inline policies with Action:* or Resource:*",
            )
        if admin_role_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-11",
                "FAIL",
                evidence,
                "Roles with AdministratorAccess found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-11",
            "PASS",
            evidence,
            "No AdministratorAccess on non-admin roles detected",
        )

    checks["IAM-11"] = iam11

    def iam12(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-12", ctx)
        if gate:
            return gate
        roles = _iam_all_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-12")
        admin_roles: list[str] = []
        for role in roles:
            role_name = str(property_value(role, ["RoleName"]) or "")
            if _iam_role_has_administrator_access(ctx, role_name):
                admin_roles.append(role_name)
        evidence = {"administrator_role_count": collection_count(admin_roles), "administrator_roles": list(admin_roles)}
        if collection_count(admin_roles) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-12",
                "FAIL",
                evidence,
                "AdministratorAccess found on roles outside approved exception list",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-12",
            "PASS",
            evidence,
            "No roles with AdministratorAccess managed policy found",
        )

    checks["IAM-12"] = iam12

    def iam13(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-13", ctx)
        if gate:
            return gate
        roles = _iam_all_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-13")
        delegated_count = 0
        with_boundary_count = 0
        without_boundary: list[str] = []
        for role in roles:
            role_name = str(property_value(role, ["RoleName"]) or "")
            path = str(property_value(role, ["Path"]) or "")
            if re.search(r"^/aws-service-role/", path):
                continue
            trust_text = _iam_role_trust_policy_text(ctx, role_name)
            if not trust_text:
                continue
            if not _iam_cross_account_role(account_id, trust_text):
                continue
            delegated_count += 1
            role_data = ctx.invoke_aws_cli(["iam", "get-role", "--role-name", role_name])
            role_obj = property_value(role_data, ["Role"]) if role_data else None
            boundary = property_value(role_obj, ["PermissionsBoundary"]) if role_obj else None
            if boundary:
                with_boundary_count += 1
            elif collection_count(without_boundary) < 10:
                without_boundary.append(role_name)
        evidence = {
            "role_count": collection_count(roles),
            "delegated_role_count": delegated_count,
            "with_boundary_count": with_boundary_count,
            "without_boundary_roles": list(without_boundary),
        }
        if collection_count(without_boundary) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-13",
                "FAIL",
                evidence,
                "Cross-account delegated roles without permission boundary found",
            )
        if delegated_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-13",
                "PARTIAL",
                evidence,
                "Cannot determine which roles are delegated",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-13",
            "PASS",
            evidence,
            "Cross-account delegated roles have permission boundaries set",
        )

    checks["IAM-13"] = iam13

    def iam14(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-14", ctx)
        if gate:
            return gate
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-14",
            "PARTIAL",
            None,
            "Full policy analysis required. Spot-check critical roles for condition usage.",
        )

    checks["IAM-14"] = iam14

    def iam15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-15", ctx)
        if gate:
            return gate
        roles = _iam_all_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-15")
        cross_account_count = 0
        with_external_id_count = 0
        missing_external_id: list[str] = []
        for role in roles:
            role_name = str(property_value(role, ["RoleName"]) or "")
            trust_text = _iam_role_trust_policy_text(ctx, role_name)
            if not trust_text:
                continue
            if not _iam_cross_account_role(account_id, trust_text):
                continue
            cross_account_count += 1
            if _iam_trust_policy_has_cross_account_restriction(trust_text):
                with_external_id_count += 1
            elif collection_count(missing_external_id) < 10:
                missing_external_id.append(role_name)
        evidence = {
            "cross_account_role_count": cross_account_count,
            "with_external_id_count": with_external_id_count,
            "missing_external_id_roles": list(missing_external_id),
        }
        if cross_account_count == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "IAM-15", "PASS", evidence, "No cross-account roles found"
            )
        if collection_count(missing_external_id) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-15",
                "FAIL",
                evidence,
                "Cross-account roles without ExternalId, SourceAccount or SourceArn condition found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-15",
            "PASS",
            evidence,
            "All cross-account roles have ExternalId, SourceAccount or SourceArn condition",
        )

    checks["IAM-15"] = iam15

    def iam16(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-16", ctx)
        if gate:
            return gate
        data = ctx.invoke_aws_cli(["accessanalyzer", "list-analyzers"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-16")
        analyzers = cli_array(property_value(data, ["analyzers"])) if has_property(data, "analyzers") else []
        org_analyzers: list[dict[str, str]] = []
        account_analyzers: list[dict[str, str]] = []
        for analyzer in analyzers:
            if not isinstance(analyzer, dict):
                continue
            record = {
                "name": str(property_value(analyzer, ["name"]) or ""),
                "type": str(property_value(analyzer, ["type"]) or ""),
                "status": str(property_value(analyzer, ["status"]) or ""),
            }
            if record["type"] == "ORGANIZATION" and record["status"] == "ACTIVE":
                org_analyzers.append(record)
            if record["type"] == "ACCOUNT":
                account_analyzers.append(record)
        evidence = {
            "analyzer_count": collection_count(analyzers),
            "organization_analyzers": list(org_analyzers),
            "account_analyzers": list(account_analyzers),
        }
        if collection_count(org_analyzers) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-16",
                "PASS",
                evidence,
                "Organization-level IAM Access Analyzer is active",
            )
        if collection_count(account_analyzers) > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "IAM-16", "PARTIAL", evidence, "Account-level analyzer only"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "IAM-16", "FAIL", evidence, "No organization-level analyzer found"
        )

    checks["IAM-16"] = iam16

    def iam17(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-17", ctx)
        if gate:
            return gate
        users = _iam_all_users(ctx)
        if users is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-17")
        users_with_keys: list[str] = []
        total_active_keys = 0
        for user in users:
            user_name = str(property_value(user, ["UserName"]) or "")
            keys = _iam_user_access_key_summary(ctx, user_name)
            if keys is None:
                continue
            if collection_count(keys) > 0:
                total_active_keys += collection_count(keys)
                if collection_count(users_with_keys) < 10:
                    users_with_keys.append(user_name)
        evidence = {
            "user_count": collection_count(users),
            "active_key_count": total_active_keys,
            "users_with_keys": list(users_with_keys),
        }
        if total_active_keys > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-17",
                "FAIL",
                evidence,
                "Active access keys found on IAM users",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "IAM-17", "PASS", evidence, "No active access keys on IAM users"
        )

    checks["IAM-17"] = iam17

    def iam18(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-18", ctx)
        if gate:
            return gate
        users = _iam_all_users(ctx)
        if users is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-18")
        stale_keys: list[dict[str, Any]] = []
        active_key_count = 0
        now = datetime.now()
        for user in users:
            user_name = str(property_value(user, ["UserName"]) or "")
            keys = _iam_user_access_key_summary(ctx, user_name)
            if keys is None:
                continue
            for key in keys:
                active_key_count += 1
                create_date_text = str(property_value(key, ["CreateDate"]) or "")
                try:
                    create_date = datetime.fromisoformat(create_date_text.replace("Z", "+00:00"))
                except ValueError:
                    continue
                age_days = (now - create_date.replace(tzinfo=None)).days
                if age_days > 90 and collection_count(stale_keys) < 10:
                    stale_keys.append(
                        {
                            "access_key_id": str(property_value(key, ["AccessKeyId"]) or ""),
                            "user_name": user_name,
                            "age_days": age_days,
                            "create_date": create_date.isoformat(),
                        }
                    )
        evidence = {
            "active_key_count": active_key_count,
            "stale_key_count": collection_count(stale_keys),
            "stale_keys": list(stale_keys),
        }
        if collection_count(stale_keys) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-18",
                "FAIL",
                evidence,
                "Access keys older than 90 days found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-18",
            "PASS",
            evidence,
            "All active access keys are within 90 days",
        )

    checks["IAM-18"] = iam18

    def iam19(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-19", ctx)
        if gate:
            return gate
        roles = _iam_all_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-19")
        pipeline_admin_roles: list[str] = []
        pipeline_wildcard_roles: list[str] = []
        for role in roles:
            role_name = str(property_value(role, ["RoleName"]) or "")
            if not re.search(r"Deploy|Pipeline|CICD|Script", role_name):
                continue
            if _iam_role_has_administrator_access(ctx, role_name):
                pipeline_admin_roles.append(role_name)
            if _iam_role_has_wildcard_inline_policy(ctx, role_name):
                pipeline_wildcard_roles.append(role_name)
        evidence = {
            "pipeline_admin_roles": list(pipeline_admin_roles),
            "pipeline_wildcard_roles": list(pipeline_wildcard_roles),
        }
        if collection_count(pipeline_wildcard_roles) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-19",
                "FAIL",
                evidence,
                "Pipeline roles with wildcard inline policies found",
            )
        if collection_count(pipeline_admin_roles) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-19",
                "FAIL",
                evidence,
                "Pipeline roles with AdministratorAccess found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-19",
            "PASS",
            evidence,
            "No pipeline roles with AdministratorAccess found",
        )

    checks["IAM-19"] = iam19

    def iam20(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-20", ctx)
        if gate:
            return gate
        data = ctx.invoke_aws_cli(["iam", "list-open-id-connect-providers"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-20")
        providers: list[str] = []
        oidc_role_count = 0
        roles_with_audience_and_subject = 0
        roles_missing_conditions = 0
        if has_property(data, "OpenIDConnectProviderList"):
            for provider in cli_array(property_value(data, ["OpenIDConnectProviderList"])):
                if not isinstance(provider, dict):
                    continue
                if has_property(provider, "Arn"):
                    providers.append(str(property_value(provider, ["Arn"]) or ""))
        roles = _iam_all_roles(ctx)
        if roles:
            for role in roles:
                role_name = str(property_value(role, ["RoleName"]) or "")
                trust_text = _iam_role_trust_policy_text(ctx, role_name)
                if not trust_text or "oidc-provider" not in trust_text.lower():
                    continue
                oidc_role_count += 1
                has_audience_condition = bool(re.search(r":aud|audience", trust_text, re.IGNORECASE))
                has_subject_condition = bool(re.search(r":sub|subject", trust_text, re.IGNORECASE))
                if has_audience_condition and has_subject_condition:
                    roles_with_audience_and_subject += 1
                else:
                    roles_missing_conditions += 1
        evidence = {
            "oidc_provider_arns": list(providers),
            "oidc_role_count": oidc_role_count,
            "roles_with_audience_and_subject": roles_with_audience_and_subject,
            "roles_missing_conditions": roles_missing_conditions,
        }
        if (
            collection_count(providers) > 0
            and oidc_role_count > 0
            and roles_with_audience_and_subject == oidc_role_count
        ):
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-20",
                "PASS",
                evidence,
                "OIDC-trusted roles include both audience and subject conditions",
            )
        if collection_count(providers) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-20",
                "PARTIAL",
                evidence,
                "OIDC provider present but audience or subject conditions are insufficient",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "IAM-20", "FAIL", evidence, "No OIDC providers found"
        )

    checks["IAM-20"] = iam20
    checks["IAM-21"] = workshop(
        "IAM-21",
        "Verify periodic access review process exists (frequency, owner, treatment of non-recertified access).",
    )
    checks["IAM-22"] = workshop(
        "IAM-22",
        "Verify offboarding procedure triggers immediate Identity Center disabling. Check ServiceNow/ITSM integration.",
    )
    checks["IAM-23"] = workshop(
        "IAM-23",
        "Verify time-boxed elevation exists for break-glass access. Check formal RFC and approval process.",
    )

    def iam24(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-24", ctx)
        if gate:
            return gate
        kms_evidence = _iam_kms_dual_access_evidence(ctx)
        if kms_evidence is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-24")
        evidence = kms_evidence
        if evidence["ccoe_key_count"] == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-24",
                "PARTIAL",
                evidence,
                "No CCOE-tagged customer-managed KMS keys found to assess key-admin vs key-user separation",
            )
        if collection_count(evidence["dual_access_entries"]) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-24",
                "FAIL",
                evidence,
                "One or more CCOE KMS key policies grant both administrative and usage actions to the same principal",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-24",
            "PASS",
            evidence,
            "CCOE KMS key policies do not combine key-admin and key-user privileges on the same principal",
        )

    checks["IAM-24"] = iam24

    def iam25(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-25", ctx)
        if gate:
            return gate
        alarm_data = ctx.invoke_aws_cli(["cloudwatch", "describe-alarms"])
        rules_data = ctx.invoke_aws_cli(["events", "list-rules"])
        if alarm_data is None and rules_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-25")
        matching_alarms: list[str] = []
        if alarm_data and has_property(alarm_data, "MetricAlarms"):
            for alarm in cli_array(property_value(alarm_data, ["MetricAlarms"])):
                if not isinstance(alarm, dict):
                    continue
                alarm_name = str(property_value(alarm, ["AlarmName"]) or "")
                metric_name = str(property_value(alarm, ["MetricName"]) or "")
                if re.search(r"KMS|Key", alarm_name) or re.search(r"ScheduleKeyDeletion|KMS", metric_name):
                    matching_alarms.append(alarm_name)
        matching_rules: list[str] = []
        if rules_data and has_property(rules_data, "Rules"):
            for rule in cli_array(property_value(rules_data, ["Rules"])):
                if not isinstance(rule, dict):
                    continue
                rule_name = str(property_value(rule, ["Name"]) or "")
                event_pattern = str(property_value(rule, ["EventPattern"]) or "")
                if re.search(r"KMS|Key", rule_name) or re.search(r"kms|ScheduleKeyDeletion", event_pattern):
                    matching_rules.append(rule_name)
        evidence = {"matching_alarm_names": list(matching_alarms), "matching_rule_names": list(matching_rules)}
        if collection_count(matching_alarms) > 0 or collection_count(matching_rules) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-25",
                "PASS",
                evidence,
                "Alerting on KMS key deletion events found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-25",
            "FAIL",
            evidence,
            "No alerting on KMS ScheduleKeyDeletion found",
        )

    checks["IAM-25"] = iam25

    def iam26(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-26", ctx)
        if gate:
            return gate
        users = _iam_all_users(ctx)
        if users is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-26")
        contractor_users: list[str] = []
        for user in users:
            user_name = str(property_value(user, ["UserName"]) or "")
            if re.search(r"external|contractor|vendor", user_name) and collection_count(contractor_users) < 10:
                contractor_users.append(user_name)
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-26",
            "PARTIAL",
            {"user_count": collection_count(users), "contractor_matches": list(contractor_users)},
            "Verify contractor access managed via ITSM with end date. Check Management account access for no-end-date accounts.",
        )

    checks["IAM-26"] = iam26

    def iam27(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-27", ctx)
        if gate:
            return gate
        users = _iam_all_users(ctx)
        if users is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-27")
        mixed_identity_users: list[str] = []
        for user in users:
            user_name = str(property_value(user, ["UserName"]) or "")
            has_console = _iam_user_has_console_access(ctx, user_name)
            keys = _iam_user_access_key_summary(ctx, user_name)
            has_keys = keys is not None and collection_count(keys) > 0
            if has_console and has_keys and collection_count(mixed_identity_users) < 10:
                mixed_identity_users.append(user_name)
        evidence = {
            "mixed_identity_count": collection_count(mixed_identity_users),
            "mixed_identity_users": list(mixed_identity_users),
        }
        if collection_count(mixed_identity_users) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-27",
                "FAIL",
                evidence,
                "Users with both console and programmatic access found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-27",
            "PASS",
            evidence,
            "Clear separation between human and machine identities",
        )

    checks["IAM-27"] = iam27

    def _roles_anywhere_guard(
        account_id: str, account_name: str, region: str, control_id: str, ctx: CheckContext
    ) -> tuple[AuditResult | None, dict[str, Any] | None]:
        context = _iam_roles_anywhere_context(ctx)
        if context is None:
            return _iam_roles_anywhere_not_detected_result(account_id, account_name, region, control_id, ctx), None
        return None, context

    def iam28(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-28", ctx)
        if gate:
            return gate
        guard, _ = _roles_anywhere_guard(account_id, account_name, region, "IAM-28", ctx)
        if guard:
            return guard
        return ctx.results.workshop_control(
            account_id, account_name, region, "IAM-28", "Verify formal SSI decision authorizes IAM Roles Anywhere usage."
        )

    checks["IAM-28"] = iam28

    def iam29(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-29", ctx)
        if gate:
            return gate
        guard, context = _roles_anywhere_guard(account_id, account_name, region, "IAM-29", ctx)
        if guard:
            return guard
        trust_anchors = cli_array(property_value(context, ["TrustAnchors"]))
        profiles = cli_array(property_value(context, ["Profiles"]))
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-29",
            "PARTIAL",
            {"trust_anchor_count": collection_count(trust_anchors), "profile_count": collection_count(profiles)},
            "Verify external workloads using trust anchors are inventoried.",
        )

    checks["IAM-29"] = iam29

    def iam30(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-30", ctx)
        if gate:
            return gate
        guard, _ = _roles_anywhere_guard(account_id, account_name, region, "IAM-30", ctx)
        if guard:
            return guard
        return ctx.results.workshop_control(
            account_id, account_name, region, "IAM-30", "Verify on-premises workload inventory exists."
        )

    checks["IAM-30"] = iam30

    def iam31(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-31", ctx)
        if gate:
            return gate
        guard, context = _roles_anywhere_guard(account_id, account_name, region, "IAM-31", ctx)
        if guard:
            return guard
        trust_anchors = cli_array(property_value(context, ["TrustAnchors"]))
        public_ca_count = 0
        private_ca_count = 0
        source_types: list[str] = []
        for anchor in trust_anchors:
            if not isinstance(anchor, dict):
                continue
            source_type = str(property_value(anchor, ["SourceType"]) or "")
            if collection_count(source_types) < 10:
                source_types.append(source_type)
            if source_type == "AWS_ACM_PCA":
                private_ca_count += 1
            else:
                public_ca_count += 1
        evidence = {
            "trust_anchor_count": collection_count(trust_anchors),
            "private_ca_count": private_ca_count,
            "public_ca_count": public_ca_count,
            "source_types": list(source_types),
        }
        if public_ca_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-31",
                "FAIL",
                evidence,
                "Trust anchor uses public CA instead of private CA",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-31",
            "PASS",
            evidence,
            "Trust anchors use private CA sources",
        )

    checks["IAM-31"] = iam31

    def iam32(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-32", ctx)
        if gate:
            return gate
        guard, context = _roles_anywhere_guard(account_id, account_name, region, "IAM-32", ctx)
        if guard:
            return guard
        profiles = cli_array(property_value(context, ["Profiles"]))
        long_lifetime_profiles: list[str] = []
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            duration = 0
            duration_value = property_value(profile, ["DurationSeconds"])
            if duration_value is not None:
                duration = int(duration_value)
            days = round(duration / 86400, 2)
            if days > 90 and collection_count(long_lifetime_profiles) < 10:
                long_lifetime_profiles.append(str(property_value(profile, ["Name"]) or ""))
        evidence = {"profile_count": collection_count(profiles), "long_lifetime_profiles": list(long_lifetime_profiles)}
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-32",
            "PARTIAL",
            evidence,
            "Profile DurationSeconds collected; verify X.509 certificate lifetime separately in workshop",
        )

    checks["IAM-32"] = iam32

    def iam33(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-33", ctx)
        if gate:
            return gate
        guard, context = _roles_anywhere_guard(account_id, account_name, region, "IAM-33", ctx)
        if guard:
            return guard
        trust_anchors = cli_array(property_value(context, ["TrustAnchors"]))
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-33",
            "PARTIAL",
            {"trust_anchor_count": collection_count(trust_anchors)},
            "Verify CRL mechanism exists and propagates in under 10 minutes.",
        )

    checks["IAM-33"] = iam33

    def iam34(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-34", ctx)
        if gate:
            return gate
        guard, context = _roles_anywhere_guard(account_id, account_name, region, "IAM-34", ctx)
        if guard:
            return guard
        profiles = cli_array(property_value(context, ["Profiles"]))
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-34",
            "PARTIAL",
            {"profile_count": collection_count(profiles)},
            "Verify private key storage uses HSM or Secrets Manager. CCoE cannot enforce this.",
        )

    checks["IAM-34"] = iam34

    def iam35(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-35", ctx)
        if gate:
            return gate
        guard, context = _roles_anywhere_guard(account_id, account_name, region, "IAM-35", ctx)
        if guard:
            return guard
        profiles = cli_array(property_value(context, ["Profiles"]))
        role_ids: list[str] = []
        shared_role_count = 0
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            role_arn = str(property_value(profile, ["RoleArn"]) or "")
            if not role_arn.strip():
                continue
            if role_arn in role_ids:
                shared_role_count += 1
            else:
                role_ids.append(role_arn)
        evidence = {
            "profile_count": collection_count(profiles),
            "unique_role_count": collection_count(role_ids),
            "shared_role_count": shared_role_count,
        }
        if shared_role_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-35",
                "FAIL",
                evidence,
                "Multiple profiles share the same IAM role",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-35",
            "PASS",
            evidence,
            "Each profile maps to a dedicated IAM role",
        )

    checks["IAM-35"] = iam35

    def iam36(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-36", ctx)
        if gate:
            return gate
        guard, context = _roles_anywhere_guard(account_id, account_name, region, "IAM-36", ctx)
        if guard:
            return guard
        profiles = cli_array(property_value(context, ["Profiles"]))
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-36",
            "PARTIAL",
            {"profile_count": collection_count(profiles)},
            "Workload role permissions at workload discretion. Spot-check via IAM role analysis.",
        )

    checks["IAM-36"] = iam36

    def iam37(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-37", ctx)
        if gate:
            return gate
        guard, context = _roles_anywhere_guard(account_id, account_name, region, "IAM-37", ctx)
        if guard:
            return guard
        profiles = cli_array(property_value(context, ["Profiles"]))
        profiles_with_conditions = 0
        profiles_without_conditions = 0
        roles_without_conditions = 0
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            policy_text = str(property_value(profile, ["SessionPolicy"]) or "")
            profile_id = str(property_value(profile, ["profileId"]) or "")
            role_trust_text = ""
            if profile_id:
                profile_detail = ctx.invoke_aws_cli(["rolesanywhere", "get-profile", "--profile-id", profile_id])
                if profile_detail and has_property(profile_detail, "profile"):
                    prof = property_value(profile_detail, ["profile"])
                    if isinstance(prof, dict) and has_property(prof, "roleArns"):
                        for role_arn in cli_array(property_value(prof, ["roleArns"])):
                            role_arn_text = str(role_arn or "")
                            if "/role/" in role_arn_text:
                                role_name = role_arn_text.split("/role/")[-1]
                                role_trust_text = _iam_role_trust_policy_text(ctx, role_name)
                                break
            combined = f"{policy_text} {role_trust_text}"
            if re.search(r"serialNumber|aws:SourceIp|IpAddress|aws:PrincipalArn", combined):
                profiles_with_conditions += 1
            else:
                profiles_without_conditions += 1
                if role_trust_text and not re.search(r"serialNumber|aws:SourceIp|IpAddress", role_trust_text):
                    roles_without_conditions += 1
        evidence = {
            "profile_count": collection_count(profiles),
            "profiles_with_conditions": profiles_with_conditions,
            "profiles_without_conditions": profiles_without_conditions,
            "roles_without_trust_conditions": roles_without_conditions,
        }
        if profiles_without_conditions > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-37",
                "FAIL",
                evidence,
                "Profiles missing serial number or IP restrictions",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-37",
            "PASS",
            evidence,
            "Profiles include serial number or IP condition checks",
        )

    checks["IAM-37"] = iam37
    checks["IAM-38"] = workshop(
        "IAM-38",
        "Verify offboarding, certificate renewal and incident procedures are documented.",
    )

    def iam39(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-39", ctx)
        if gate:
            return gate
        status_data = ctx.invoke_aws_cli(["configservice", "describe-configuration-recorder-status"])
        rules_data = ctx.invoke_aws_cli(["configservice", "list-config-rules", "--max-results", "100"])
        if status_data is None and rules_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-39")
        recorder_active = False
        if status_data and has_property(status_data, "ConfigurationRecordersStatus"):
            for status in cli_array(property_value(status_data, ["ConfigurationRecordersStatus"])):
                if not isinstance(status, dict):
                    continue
                if property_value(status, ["recording"]) is True:
                    recorder_active = True
                    break
        target_rule_names = (
            "iam-no-inline-policy-check",
            "iam-policy-no-statements-with-admin-access",
            "iam-root-access-key-check",
        )
        iam_rules: list[str] = []
        matched_target_rules: list[str] = []
        if rules_data and has_property(rules_data, "ConfigRules"):
            for rule in cli_array(property_value(rules_data, ["ConfigRules"])):
                if not isinstance(rule, dict):
                    continue
                rule_name = str(property_value(rule, ["ConfigRuleName"]) or "")
                if re.search(r"IAM|iam", rule_name):
                    iam_rules.append(rule_name)
                lower_name = rule_name.lower()
                if any(target in lower_name for target in target_rule_names):
                    matched_target_rules.append(rule_name)
        evidence = {
            "recorder_active": recorder_active,
            "iam_rule_count": collection_count(iam_rules),
            "iam_rule_names": list(iam_rules),
            "matched_target_rules": list(matched_target_rules),
        }
        if recorder_active and collection_count(matched_target_rules) >= 2:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-39",
                "PASS",
                evidence,
                "Config recorder active with targeted IAM managed rules",
            )
        if recorder_active and collection_count(iam_rules) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-39",
                "PARTIAL",
                evidence,
                "Config recorder active with IAM rules but missing some targeted IAM managed rules",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "IAM-39", "FAIL", evidence, "No Config recording or no IAM Config rules"
        )

    checks["IAM-39"] = iam39

    def iam40(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-40", ctx)
        if gate:
            return gate
        roles = _iam_all_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-40")
        sample_names: list[str] = []
        prefixes: dict[str, int] = {}
        sample_limit = 50
        count = 0
        for role in roles:
            if count >= sample_limit:
                break
            role_name = str(property_value(role, ["RoleName"]) or "")
            sample_names.append(role_name)
            prefix = role_name
            match = re.match(r"^([^-/_]+)", role_name)
            if match:
                prefix = match.group(1)
            prefixes[prefix] = prefixes.get(prefix, 0) + 1
            count += 1
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-40",
            "PARTIAL",
            {
                "sampled_role_count": collection_count(sample_names),
                "sample_role_names": list(sample_names),
                "prefix_counts": prefixes,
            },
            "Verify naming convention document exists. Spot-check role names against convention.",
        )

    checks["IAM-40"] = iam40

    def iam41(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-41", ctx)
        if gate:
            return gate

        credential_report = _get_iam_credential_report(ctx)
        auth_details = ctx.invoke_aws_cli(
            [
                "iam",
                "get-account-authorization-details",
                "--filter",
                "LocalManagedPolicy",
                "ManagedPolicy",
                "Role",
                "User",
                "Group",
            ]
        )
        role_count = 0
        if auth_details and has_property(auth_details, "RoleDetailList"):
            role_count = collection_count(cli_array(property_value(auth_details, ["RoleDetailList"])))

        permission_set_count = 0
        assignment_count = 0
        instances = _iam_sso_instances(ctx)
        if instances:
            for instance in instances:
                instance_arn = str(property_value(instance, ["InstanceArn"]) or "")
                if not instance_arn:
                    continue
                permission_sets = _iam_permission_set_details(ctx, instance_arn)
                if permission_sets is None:
                    continue
                permission_set_count += collection_count(permission_sets)
                for permission_set in permission_sets:
                    ps_arn = str(property_value(permission_set, ["PermissionSetArn"]) or "")
                    if not ps_arn:
                        continue
                    accounts_data = ctx.invoke_aws_cli(
                        [
                            "sso-admin",
                            "list-accounts-for-provisioned-permission-set",
                            "--instance-arn",
                            instance_arn,
                            "--permission-set-arn",
                            ps_arn,
                        ]
                    )
                    if accounts_data and has_property(accounts_data, "AccountIds"):
                        assignment_count += collection_count(cli_array(property_value(accounts_data, ["AccountIds"])))

        evidence: dict[str, Any] = {
            "role_export_count": role_count,
            "identity_center_permission_set_count": permission_set_count,
            "permission_set_account_assignments": assignment_count,
        }
        if credential_report:
            evidence["credential_report_state"] = str(credential_report.get("state") or "")
            evidence["credential_report_generated_time"] = credential_report.get("generated_time")

        if auth_details is None and credential_report is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-41")

        export_ok = auth_details is not None and role_count >= 0
        credential_ok = bool(credential_report and credential_report.get("report"))
        sso_ok = permission_set_count == 0 or assignment_count > 0

        if export_ok and credential_ok and sso_ok:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-41",
                "PASS",
                evidence,
                "IAM policy export, credential report and Identity Center assignments are accessible",
            )
        if export_ok or credential_ok:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-41",
                "PARTIAL",
                evidence,
                "Some IAM audit exports succeeded; verify credential report and Identity Center assignments",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-41",
            "FAIL",
            evidence,
            "IAM audit exports are not fully accessible",
        )

    checks["IAM-41"] = iam41
    checks["IAM-42"] = workshop(
        "IAM-42",
        "Verify formal document defines Identity Center usage: scope, admin procedures, review process.",
    )

    def iam43(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-43", ctx)
        if gate:
            return gate
        instances = _iam_sso_instances(ctx)
        if instances is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-43")
        users = _iam_all_users(ctx)
        if users is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-43")
        console_user_count = 0
        for user in users:
            if _iam_user_has_console_access(ctx, str(property_value(user, ["UserName"]) or "")):
                console_user_count += 1
        instance_arn = None
        if collection_count(instances) > 0:
            first = instances[0] if isinstance(instances[0], dict) else None
            if first:
                instance_arn = str(property_value(first, ["InstanceArn"]) or "")
        evidence = {
            "identity_center_instance_arn": instance_arn,
            "local_console_user_count": console_user_count,
            "iam_user_count": collection_count(users),
        }
        if collection_count(instances) > 0 and console_user_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-43",
                "PASS",
                evidence,
                "Identity Center active with no local IAM console users",
            )
        if console_user_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-43",
                "FAIL",
                evidence,
                "Local IAM users with console access exist",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "IAM-43", "FAIL", evidence, "Identity Center not active"
        )

    checks["IAM-43"] = iam43

    def iam44(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-44", ctx)
        if gate:
            return gate
        instances = _iam_sso_instances(ctx)
        if instances is None or collection_count(instances) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-44",
                "FAIL",
                {"instance_count": 0},
                "No Identity Center instance found",
            )
        first_instance = instances[0] if isinstance(instances[0], dict) else {}
        instance_arn = str(property_value(first_instance, ["InstanceArn"]) or "")
        if not instance_arn.strip():
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-44")
        describe_data = ctx.invoke_aws_cli(["sso-admin", "describe-instance", "--instance-arn", instance_arn])
        apps_data = ctx.invoke_aws_cli(["sso-admin", "list-applications", "--instance-arn", instance_arn])
        if describe_data is None and apps_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-44")
        external_apps: list[str] = []
        if apps_data and has_property(apps_data, "Applications"):
            for app in cli_array(property_value(apps_data, ["Applications"])):
                if not isinstance(app, dict):
                    continue
                provider_arn = str(property_value(app, ["ApplicationProviderArn"]) or "")
                if provider_arn and not re.search(r"awsapps\.com", provider_arn):
                    external_apps.append(str(property_value(app, ["ApplicationArn"]) or ""))
        identity_store_id = None
        instance_detail = property_value(describe_data, ["Instance"]) if describe_data else None
        if instance_detail is not None:
            identity_store_id_value = property_value(instance_detail, ["IdentityStoreId"])
            if identity_store_id_value is not None:
                identity_store_id = str(identity_store_id_value)
        external_ids_found = 0
        federated_users = 0
        if identity_store_id:
            users_data = ctx.invoke_aws_cli(
                ["identitystore", "list-users", "--identity-store-id", identity_store_id, "--max-results", "50"]
            )
            if users_data and has_property(users_data, "Users"):
                for user in cli_array(property_value(users_data, ["Users"])):
                    if not isinstance(user, dict):
                        continue
                    federated_users += 1
                    if has_property(user, "ExternalIds") and collection_count(property_value(user, ["ExternalIds"])) > 0:
                        external_ids_found += 1
        evidence = {
            "instance_arn": instance_arn,
            "identity_store_id": identity_store_id,
            "external_app_count": collection_count(external_apps),
            "external_app_arns": list(external_apps),
            "identity_store_user_count": federated_users,
            "users_with_external_ids": external_ids_found,
        }
        if external_ids_found > 0 or collection_count(external_apps) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-44",
                "PASS",
                evidence,
                "External IdP federation detected via applications or identity store external IDs",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-44",
            "PARTIAL",
            evidence,
            "Internal IAM Identity Center (not externally federated)",
        )

    checks["IAM-44"] = iam44

    def iam45(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-45", ctx)
        if gate:
            return gate
        instances = _iam_sso_instances(ctx)
        if instances is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-45")
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-45",
            "PARTIAL",
            {"identity_center_instance_count": collection_count(instances)},
            "MFA enforcement configured in Guardian IdP upstream. Verify MFA=Required in Identity Center auth settings.",
        )

    checks["IAM-45"] = iam45

    def iam46(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-46", ctx)
        if gate:
            return gate
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-46",
            "PARTIAL",
            None,
            "Verify authentication policy is set to MFA required. Check session duration policy. Guardian constraints noted.",
        )

    checks["IAM-46"] = iam46

    def iam47(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-47", ctx)
        if gate:
            return gate
        instances = _iam_sso_instances(ctx)
        if instances is None or collection_count(instances) == 0:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-47")
        sample_names: list[str] = []
        permission_set_count = 0
        missing_description_count = 0
        inline_policy_count = 0
        managed_policy_count = 0
        for instance in instances:
            if not isinstance(instance, dict):
                continue
            instance_arn = str(property_value(instance, ["InstanceArn"]) or "")
            if not instance_arn.strip():
                continue
            permission_sets = _iam_permission_set_details(ctx, instance_arn)
            if permission_sets is None:
                continue
            for permission_set in permission_sets:
                permission_set_count += 1
                permission_set_name = str(property_value(permission_set, ["Name"]) or "")
                permission_set_arn = str(property_value(permission_set, ["PermissionSetArn"]) or "")
                description = str(property_value(permission_set, ["Description"]) or "")
                if not description.strip():
                    missing_description_count += 1
                if permission_set_arn:
                    inline_data = ctx.invoke_aws_cli(
                        [
                            "sso-admin",
                            "get-inline-policy-for-permission-set",
                            "--instance-arn",
                            instance_arn,
                            "--permission-set-arn",
                            permission_set_arn,
                        ]
                    )
                    if inline_data and has_property(inline_data, "InlinePolicy"):
                        inline_policy_count += 1
                    managed_data = ctx.invoke_aws_cli(
                        [
                            "sso-admin",
                            "list-managed-policies-in-permission-set",
                            "--instance-arn",
                            instance_arn,
                            "--permission-set-arn",
                            permission_set_arn,
                        ]
                    )
                    if managed_data and has_property(managed_data, "AttachedManagedPolicies"):
                        managed_policy_count += collection_count(
                            cli_array(property_value(managed_data, ["AttachedManagedPolicies"]))
                        )
                if collection_count(sample_names) < 10 and permission_set_name.strip():
                    sample_names.append(permission_set_name)
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-47",
            "PARTIAL",
            {
                "permission_set_count": permission_set_count,
                "sample_names": list(sample_names),
                "missing_description_count": missing_description_count,
                "permission_sets_with_inline_policy": inline_policy_count,
                "attached_managed_policy_count": managed_policy_count,
            },
            "Verify permission set naming convention and governance process exists.",
        )

    checks["IAM-47"] = iam47

    def iam48(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-48", ctx)
        if gate:
            return gate
        instances = _iam_sso_instances(ctx)
        if instances is None or collection_count(instances) == 0:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-48")
        admin_permission_sets: list[str] = []
        wildcard_inline_permission_sets: list[str] = []
        for instance in instances:
            if not isinstance(instance, dict):
                continue
            instance_arn = str(property_value(instance, ["InstanceArn"]) or "")
            if not instance_arn.strip():
                continue
            permission_sets = _iam_permission_set_details(ctx, instance_arn)
            if permission_sets is None:
                continue
            for permission_set in permission_sets:
                permission_set_arn = str(property_value(permission_set, ["PermissionSetArn"]) or "")
                if not permission_set_arn.strip():
                    continue
                permission_set_name = str(property_value(permission_set, ["Name"]) or "")
                inline_data = ctx.invoke_aws_cli(
                    [
                        "sso-admin",
                        "get-inline-policy-for-permission-set",
                        "--instance-arn",
                        instance_arn,
                        "--permission-set-arn",
                        permission_set_arn,
                    ]
                )
                if inline_data and has_property(inline_data, "InlinePolicy"):
                    inline_policy = str(property_value(inline_data, ["InlinePolicy"]) or "")
                    if re.search(r'"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"', inline_policy):
                        wildcard_inline_permission_sets.append(permission_set_name)
                if _iam_permission_set_has_administrator_access(ctx, instance_arn, permission_set_arn):
                    if collection_count(admin_permission_sets) < 10:
                        admin_permission_sets.append(permission_set_name)
        evidence = {
            "administrator_permission_sets": list(admin_permission_sets),
            "wildcard_inline_permission_sets": list(wildcard_inline_permission_sets),
        }
        if collection_count(wildcard_inline_permission_sets) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-48",
                "FAIL",
                evidence,
                "Permission sets with wildcard inline policies found",
            )
        if collection_count(admin_permission_sets) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-48",
                "FAIL",
                evidence,
                "Permission Sets with AdministratorAccess found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-48",
            "PASS",
            evidence,
            "No AdministratorAccess on standard Permission Sets",
        )

    checks["IAM-48"] = iam48

    def iam49(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-49", ctx)
        if gate:
            return gate
        instances = _iam_sso_instances(ctx)
        if instances is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-49")
        sample_names: list[str] = []
        for instance in instances:
            if not isinstance(instance, dict):
                continue
            instance_arn = str(property_value(instance, ["InstanceArn"]) or "")
            if not instance_arn.strip():
                continue
            permission_sets = _iam_permission_set_details(ctx, instance_arn)
            if permission_sets is None:
                continue
            for permission_set in permission_sets:
                permission_set_name = str(property_value(permission_set, ["Name"]) or "")
                if collection_count(sample_names) < 20 and permission_set_name.strip():
                    sample_names.append(permission_set_name)
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-49",
            "PARTIAL",
            {"sample_permission_set_names": list(sample_names)},
            "Verify separate Permission Sets exist for admin, security, ops, readonly, devops roles.",
        )

    checks["IAM-49"] = iam49

    def iam50(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-50", ctx)
        if gate:
            return gate
        instances = _iam_sso_instances(ctx)
        if instances is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-50")
        duration_buckets: dict[str, int] = {}
        long_duration_sets: list[str] = []
        permission_set_count = 0
        for instance in instances:
            if not isinstance(instance, dict):
                continue
            instance_arn = str(property_value(instance, ["InstanceArn"]) or "")
            if not instance_arn.strip():
                continue
            permission_sets = _iam_permission_set_details(ctx, instance_arn)
            if permission_sets is None:
                continue
            for permission_set in permission_sets:
                permission_set_count += 1
                duration = "PT1H"
                if has_property(permission_set, "SessionDuration"):
                    duration = str(property_value(permission_set, ["SessionDuration"]) or "PT1H")
                duration_buckets[duration] = duration_buckets.get(duration, 0) + 1
                if _iso_duration_hours(duration) > 8 and collection_count(long_duration_sets) < 10:
                    long_duration_sets.append(str(property_value(permission_set, ["Name"]) or ""))
        evidence = {
            "permission_set_count": permission_set_count,
            "duration_buckets": duration_buckets,
            "long_duration_names": list(long_duration_sets),
        }
        if collection_count(long_duration_sets) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-50",
                "FAIL",
                evidence,
                "Permission Sets exceed PT8H session duration",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-50",
            "PASS",
            evidence,
            "All Permission Sets are at most PT8H",
        )

    checks["IAM-50"] = iam50
    checks["IAM-51"] = workshop("IAM-51", "Verify ITSM integration with Identity Center for automated provisioning.")
    checks["IAM-52"] = workshop(
        "IAM-52",
        "Verify offboarding triggers immediate Identity Center account disable. Check LDAP sync (Aldab Sync) behavior.",
    )
    checks["IAM-53"] = workshop(
        "IAM-53",
        "Verify periodic review of Identity Center assignments exists. Check frequency and documentation.",
    )

    def iam54(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-54", ctx)
        if gate:
            return gate
        end_time = datetime.now(timezone.utc).isoformat()
        start_time = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        data = ctx.invoke_aws_cli(
            [
                "cloudtrail",
                "lookup-events",
                "--lookup-attributes",
                "AttributeKey=EventSource,AttributeValue=sso.amazonaws.com",
                "--start-time",
                start_time,
                "--end-time",
                end_time,
                "--max-results",
                "50",
            ]
        )
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-54")
        event_count = 0
        if has_property(data, "Events"):
            event_count = collection_count(property_value(data, ["Events"]))
        trail_data = ctx.invoke_aws_cli(["cloudtrail", "describe-trails"])
        multi_region_trails: list[str] = []
        active_multi_region_trails: list[str] = []
        organization_trails: list[str] = []
        active_organization_trails: list[str] = []
        if trail_data and has_property(trail_data, "trailList"):
            for trail in cli_array(property_value(trail_data, ["trailList"])):
                trail_name = str(property_value(trail, ["Name"]) or "")
                is_multi_region = property_value(trail, ["IsMultiRegionTrail"]) is True
                is_organization = property_value(trail, ["IsOrganizationTrail"]) is True
                if is_multi_region:
                    multi_region_trails.append(trail_name)
                if is_organization:
                    organization_trails.append(trail_name)
                status = ctx.invoke_aws_cli(["cloudtrail", "get-trail-status", "--name", trail_name])
                if status and property_value(status, ["IsLogging"]) is True:
                    if is_multi_region:
                        active_multi_region_trails.append(trail_name)
                    if is_organization:
                        active_organization_trails.append(trail_name)
        evidence = {
            "sso_event_count_last_7_days": event_count,
            "multi_region_trail_count": collection_count(multi_region_trails),
            "multi_region_trail_names": multi_region_trails[:10],
            "active_multi_region_trail_count": collection_count(active_multi_region_trails),
            "organization_trail_count": collection_count(organization_trails),
            "active_organization_trail_count": collection_count(active_organization_trails),
        }
        if event_count > 0 and collection_count(active_organization_trails) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-54",
                "PASS",
                evidence,
                "SSO events visible in CloudTrail and an active organization trail is configured",
            )
        if event_count > 0 and collection_count(active_multi_region_trails) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-54",
                "PARTIAL",
                evidence,
                "SSO events are visible but no active organization CloudTrail trail was detected",
            )
        if event_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-54",
                "PARTIAL",
                evidence,
                "SSO events are visible but no active multi-region CloudTrail trail was detected",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "IAM-54", "FAIL", evidence, "No SSO events in CloudTrail"
        )

    checks["IAM-54"] = iam54

    def iam55(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-55", ctx)
        if gate:
            return gate
        rules_data = ctx.invoke_aws_cli(["events", "list-rules"])
        if rules_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-55")
        sso_rules: list[str] = []
        rules_with_targets: list[str] = []
        if has_property(rules_data, "Rules"):
            for rule in cli_array(property_value(rules_data, ["Rules"])):
                if not isinstance(rule, dict):
                    continue
                rule_name = str(property_value(rule, ["Name"]) or "")
                event_pattern = str(property_value(rule, ["EventPattern"]) or "")
                if (
                    re.search(r"sso\.amazonaws\.com|CreateUser|PutInlinePolicyToPermissionSet", event_pattern)
                    or re.search(r"SSO|IdentityCenter|IAM", rule_name)
                ):
                    sso_rules.append(rule_name)
                    targets_data = ctx.invoke_aws_cli(["events", "list-targets-by-rule", "--rule", rule_name])
                    if targets_data and has_property(targets_data, "Targets"):
                        if collection_count(property_value(targets_data, ["Targets"])) > 0:
                            rules_with_targets.append(rule_name)
        evidence = {
            "sso_rule_names": list(sso_rules),
            "rules_with_active_targets": list(rules_with_targets),
        }
        if collection_count(rules_with_targets) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-55",
                "PASS",
                evidence,
                "EventBridge rules on critical IAM or SSO events have active targets",
            )
        if collection_count(sso_rules) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-55",
                "PARTIAL",
                evidence,
                "SSO or IAM EventBridge rules exist but no active targets were detected",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-55",
            "FAIL",
            evidence,
            "No SSO-specific alerting rules found",
        )

    checks["IAM-55"] = iam55

    if len(checks) != 55:
        raise RuntimeError(f"get_domain expected 55 IAM controls but defined {len(checks)}")

    return DomainModule(code="IAM", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
