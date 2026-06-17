"""IAM domain controls."""

from __future__ import annotations

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


def _iam_trust_policy_has_external_id(trust_policy_text: str) -> bool:
    if not trust_policy_text or not trust_policy_text.strip():
        return False
    return bool(re.search(r"ExternalId|sts:ExternalId", trust_policy_text))


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
    generate_data = ctx.invoke_aws_cli(["iam", "generate-credential-report"])
    if generate_data is None:
        return None

    for _ in range(10):
        state = str(property_value(generate_data, ["State"]) or "")
        if state == "COMPLETE":
            report_data = ctx.invoke_aws_cli(["iam", "get-credential-report"])
            generated_time = None
            if report_data and has_property(report_data, "GeneratedTime"):
                generated_time = str(property_value(report_data, ["GeneratedTime"]) or "")
            return {"state": state, "report": report_data, "generated_time": generated_time}
        if state == "FAILED":
            return {"state": state, "report": None, "generated_time": None}
        time.sleep(2)
        generate_data = ctx.invoke_aws_cli(["iam", "generate-credential-report"])
        if generate_data is None:
            return None

    return {"state": "TIMEOUT", "report": None, "generated_time": None}


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
        summary = _iam_account_summary_map(ctx)
        if summary is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-01")
        mfa_enabled = None
        if has_property(summary, "AccountMFAEnabled"):
            value = property_value(summary, ["AccountMFAEnabled"])
            mfa_enabled = int(value) if value is not None else None
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-01",
            "PARTIAL",
            {"AccountMFAEnabled": mfa_enabled},
            "Root last-used date requires credential report. Verify via console or credential report.",
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
        console_user_count = 0
        console_usernames: list[str] = []
        unclear_count = 0
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
            "unclear_status_count": unclear_count,
        }
        if console_user_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-05",
                "FAIL",
                evidence,
                "Local IAM users with console access exist",
            )
        if collection_count(users) > 0 and unclear_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-05",
                "PARTIAL",
                evidence,
                "Users exist but console access status unclear",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-05",
            "PASS",
            evidence,
            "No local IAM users with console access detected",
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
        }
        if collection_count(long_duration_sets) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-07",
                "FAIL",
                evidence,
                "One or more permission sets exceed PT8H session duration",
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
            "All permission sets are at most PT8H",
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
        if active_key_count > 5 and not identity_center_active:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-09",
                "FAIL",
                evidence,
                "Many static access keys found without Identity Center",
            )
        if identity_center_active and active_key_count <= 5:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-09",
                "PASS",
                evidence,
                "Identity Center active with minimal static access keys",
            )
        if active_key_count > 5:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-09",
                "FAIL",
                evidence,
                "Many users with static access keys for human access",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-09",
            "PASS",
            evidence,
            "Human access appears STS-based with limited static keys",
        )

    checks["IAM-09"] = iam09

    def iam11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        gate = _iam_global_control_gate(account_id, account_name, region, "IAM-11", ctx)
        if gate:
            return gate
        roles = _iam_all_roles(ctx)
        if roles is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-11")
        admin_roles: list[str] = []
        admin_role_count = 0
        for role in roles:
            role_name = str(property_value(role, ["RoleName"]) or "")
            has_admin = _iam_role_has_administrator_access(ctx, role_name)
            if has_admin is True:
                admin_role_count += 1
                if collection_count(admin_roles) < 10:
                    admin_roles.append(role_name)
        evidence = {
            "role_count": collection_count(roles),
            "administrator_role_count": admin_role_count,
            "administrator_roles": list(admin_roles),
        }
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
            if _iam_trust_policy_has_external_id(trust_text):
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
                "Cross-account roles without ExternalId condition found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-15",
            "PASS",
            evidence,
            "All cross-account roles have ExternalId condition",
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
        for role in roles:
            role_name = str(property_value(role, ["RoleName"]) or "")
            if not re.search(r"Deploy|Pipeline|CICD|Script", role_name):
                continue
            if _iam_role_has_administrator_access(ctx, role_name):
                pipeline_admin_roles.append(role_name)
        evidence = {"pipeline_admin_roles": list(pipeline_admin_roles)}
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
        if has_property(data, "OpenIDConnectProviderList"):
            for provider in cli_array(property_value(data, ["OpenIDConnectProviderList"])):
                if not isinstance(provider, dict):
                    continue
                if has_property(provider, "Arn"):
                    providers.append(str(property_value(provider, ["Arn"]) or ""))
        evidence = {"oidc_provider_arns": list(providers)}
        if collection_count(providers) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-20",
                "PASS",
                evidence,
                "OIDC provider configured for pipeline authentication",
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
        "Verify time-boxed elevation exists for break-glass access. Check CCOScriptAdmin RFC process.",
    )

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
        if collection_count(long_lifetime_profiles) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-32",
                "FAIL",
                evidence,
                "Profile certificate lifetime exceeds 90 days",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-32",
            "PASS",
            evidence,
            "Profile session durations are within 90 days",
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
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            policy_text = str(property_value(profile, ["SessionPolicy"]) or "")
            if re.search(r"serialNumber|aws:SourceIp|IpAddress", policy_text):
                profiles_with_conditions += 1
            else:
                profiles_without_conditions += 1
        evidence = {
            "profile_count": collection_count(profiles),
            "profiles_with_conditions": profiles_with_conditions,
            "profiles_without_conditions": profiles_without_conditions,
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
        status_data = ctx.invoke_aws_cli(["config", "describe-configuration-recorder-status"])
        rules_data = ctx.invoke_aws_cli(["config", "list-config-rules", "--max-results", "100"])
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
        iam_rules: list[str] = []
        if rules_data and has_property(rules_data, "ConfigRules"):
            for rule in cli_array(property_value(rules_data, ["ConfigRules"])):
                if not isinstance(rule, dict):
                    continue
                rule_name = str(property_value(rule, ["ConfigRuleName"]) or "")
                if re.search(r"IAM|iam", rule_name):
                    iam_rules.append(rule_name)
        evidence = {
            "recorder_active": recorder_active,
            "iam_rule_count": collection_count(iam_rules),
            "iam_rule_names": list(iam_rules),
        }
        if recorder_active and collection_count(iam_rules) > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "IAM-39", "PASS", evidence, "Config recorder active with IAM rules"
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
        if credential_report is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "IAM-41")
        state = str(credential_report.get("state") or "")
        report_data = credential_report.get("report")
        generated_date = credential_report.get("generated_time")
        evidence = {"generation_state": state, "generated_time": generated_date}
        if report_data:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-41",
                "PASS",
                evidence,
                "Credential report generated successfully",
            )
        if state == "TIMEOUT":
            notes = "Credential report generation did not complete within polling window"
        elif state == "FAILED":
            notes = "Credential report generation failed"
        else:
            notes = "Cannot generate credential report"
        return ctx.results.audit_result(account_id, account_name, region, "IAM-41", "FAIL", evidence, notes)

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
        evidence = {
            "instance_arn": instance_arn,
            "identity_store_id": identity_store_id,
            "external_app_count": collection_count(external_apps),
            "external_app_arns": list(external_apps),
        }
        if collection_count(external_apps) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-44",
                "PASS",
                evidence,
                "External IdP application configured",
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
                if collection_count(sample_names) < 10 and permission_set_name.strip():
                    sample_names.append(permission_set_name)
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "IAM-47",
            "PARTIAL",
            {"permission_set_count": permission_set_count, "sample_names": list(sample_names)},
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
                if _iam_permission_set_has_administrator_access(ctx, instance_arn, permission_set_arn):
                    if collection_count(admin_permission_sets) < 10:
                        admin_permission_sets.append(str(property_value(permission_set, ["Name"]) or ""))
        evidence = {"administrator_permission_sets": list(admin_permission_sets)}
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
        evidence = {"sso_event_count_last_7_days": event_count}
        if event_count > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "IAM-54", "PASS", evidence, "SSO events visible in CloudTrail"
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
        evidence = {"sso_rule_names": list(sso_rules)}
        if collection_count(sso_rules) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "IAM-55",
                "PASS",
                evidence,
                "EventBridge rules exist on critical IAM or SSO events",
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

    return DomainModule(code="IAM", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
