"""DAT domain - data protection controls."""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "DAT-01": "P0",
    "DAT-02": "P0",
    "DAT-03": "P0",
    "DAT-04": "P0",
    "DAT-05": "P0",
    "DAT-06": "P0",
    "DAT-07": "P1",
    "DAT-08": "P0",
    "DAT-09": "P0",
    "DAT-10": "P0",
    "DAT-11": "P0",
    "DAT-12": "P0",
    "DAT-13": "P0",
    "DAT-14": "P0",
    "DAT-15": "P0",
    "DAT-16": "P0",
    "DAT-17": "P0",
    "DAT-18": "P0",
    "DAT-19": "P0",
    "DAT-20": "P0",
    "DAT-21": "P0",
    "DAT-22": "P0",
    "DAT-23": "P1",
    "DAT-24": "P0",
    "DAT-25": "P0",
}


def _get_dat_cli_array(items: Any) -> list[Any]:
    return cli_array(items)


def _new_dat_list() -> list[Any]:
    return []


def _get_dat_collection_count(items: Any) -> int:
    return collection_count(items)


def _test_dat_has_property(obj: Any, property_name: str) -> bool:
    return has_property(obj, property_name)


def _get_dat_property_value(obj: Any, property_names: list[str]) -> Any:
    return property_value(obj, property_names)


def _invoke_aws_cli_in_region(ctx: CheckContext, arguments: list[str], region: str) -> Any | None:
    original_region = ctx.aws.region
    try:
        ctx.aws.region = region
        return ctx.invoke_aws_cli(arguments)
    finally:
        ctx.aws.region = original_region


def _get_dat_s3_bucket_names(ctx: CheckContext, region: str) -> list[str] | None:
    data = _invoke_aws_cli_in_region(ctx, ["s3api", "list-buckets"], region)
    if data is None:
        return None
    bucket_names: list[str] = []
    if _test_dat_has_property(data, "Buckets"):
        for bucket in _get_dat_cli_array(data.get("Buckets")):
            if _test_dat_has_property(bucket, "Name"):
                bucket_names.append(str(bucket.get("Name", "")))
    return bucket_names


def _test_dat_bucket_name_critical(bucket_name: str) -> bool:
    return re.search(r"log|backup|critical", bucket_name.lower()) is not None


def _test_dat_bucket_name_log_or_backup(bucket_name: str) -> bool:
    return re.search(r"log|backup", bucket_name.lower()) is not None


def _test_dat_bucket_policy_enforces_tls(policy_text: str) -> bool:
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError:
        return False
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if str(statement.get("Effect", "")).upper() != "Deny":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not any(action == "*" or str(action).startswith("s3:") for action in actions):
            continue
        condition = statement.get("Condition")
        if not isinstance(condition, dict):
            continue
        bool_condition = condition.get("Bool")
        if not isinstance(bool_condition, dict):
            continue
        if str(bool_condition.get("aws:SecureTransport", "")).lower() == "false":
            return True
    return False


def _test_dat_backup_policy_denies_delete_recovery(policy_text: str) -> bool:
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError:
        return False
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if str(statement.get("Effect", "")).upper() != "Deny":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            action_text = str(action)
            if action_text in {"backup:DeleteRecoveryPoint", "backup:*", "*"}:
                return True
            if "DeleteRecoveryPoint" in action_text:
                return True
    return False


def _test_dat_s3_bucket_public(ctx: CheckContext, region: str, bucket_name: str) -> bool:
    acl_data = _invoke_aws_cli_in_region(ctx, ["s3api", "get-bucket-acl", "--bucket", bucket_name], region)
    if acl_data is not None and _test_dat_has_property(acl_data, "Grants"):
        for grant in _get_dat_cli_array(acl_data.get("Grants")):
            grantee = _get_dat_property_value(grant, ["Grantee", "grantee"])
            uri = str(_get_dat_property_value(grantee, ["URI", "Uri", "uri"]) or "")
            permission = str(_get_dat_property_value(grant, ["Permission", "permission"]) or "")
            if re.search(r"AllUsers|AuthenticatedUsers", uri) and re.search(r"READ|FULL_CONTROL", permission):
                return True

    pab_data = _invoke_aws_cli_in_region(
        ctx, ["s3api", "get-public-access-block", "--bucket", bucket_name], region
    )
    if pab_data is not None and _test_dat_has_property(pab_data, "PublicAccessBlockConfiguration"):
        config = pab_data.get("PublicAccessBlockConfiguration")
        block_public_acls = bool(_get_dat_property_value(config, ["BlockPublicAcls"]) is True)
        ignore_public_acls = bool(_get_dat_property_value(config, ["IgnorePublicAcls"]) is True)
        block_public_policy = bool(_get_dat_property_value(config, ["BlockPublicPolicy"]) is True)
        restrict_public_buckets = bool(_get_dat_property_value(config, ["RestrictPublicBuckets"]) is True)
        all_true = block_public_acls and ignore_public_acls and block_public_policy and restrict_public_buckets
        if not all_true:
            return True

    return False


def _test_dat_s3_bucket_sse_kms(ctx: CheckContext, region: str, bucket_name: str) -> bool:
    data = _invoke_aws_cli_in_region(ctx, ["s3api", "get-bucket-encryption", "--bucket", bucket_name], region)
    if data is None:
        return False
    if not _test_dat_has_property(data, "ServerSideEncryptionConfiguration"):
        return False

    # Preserve PowerShell parity: DAT.ps1 checks ".Rules" on a boolean expression,
    # which evaluates as missing and returns false for this control path.
    config = _get_dat_property_value(data, ["ServerSideEncryptionConfiguration"])
    if not isinstance(config, dict):
        return False
    rules = _get_dat_property_value(config, ["Rules"])
    if not rules:
        return False

    for rule in _get_dat_cli_array(rules):
        if _test_dat_has_property(rule, "ApplyServerSideEncryptionByDefault"):
            apply_default = _get_dat_property_value(rule, ["ApplyServerSideEncryptionByDefault"])
            algorithm = str(_get_dat_property_value(apply_default, ["SSEAlgorithm"]) or "")
            if algorithm == "aws:kms":
                return True
    return False


def _get_dat_customer_master_keys(ctx: CheckContext, region: str) -> list[dict[str, Any]] | None:
    keys: list[dict[str, Any]] = []
    marker = None
    while True:
        arguments = ["kms", "list-keys", "--limit", "1000"]
        if marker:
            arguments.extend(["--marker", marker])
        list_data = _invoke_aws_cli_in_region(ctx, arguments, region)
        if list_data is None:
            return None

        if _test_dat_has_property(list_data, "Keys"):
            for key in _get_dat_cli_array(list_data.get("Keys")):
                if not _test_dat_has_property(key, "KeyId"):
                    continue
                describe_data = _invoke_aws_cli_in_region(
                    ctx, ["kms", "describe-key", "--key-id", str(key.get("KeyId", ""))], region
                )
                if describe_data is None or not _test_dat_has_property(describe_data, "KeyMetadata"):
                    continue
                metadata = describe_data.get("KeyMetadata")
                if str(_get_dat_property_value(metadata, ["KeyManager"]) or "") == "CUSTOMER":
                    if isinstance(metadata, dict):
                        keys.append(metadata)

        marker = None
        if _test_dat_has_property(list_data, "NextMarker"):
            next_marker = str(list_data.get("NextMarker") or "")
            truncated = _get_dat_property_value(list_data, ["Truncated"]) is True
            if next_marker and truncated:
                marker = next_marker
        if not marker:
            break
    return keys


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(control_id: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, control_id, notes)

        return _check

    checks["DAT-01"] = workshop(
        "DAT-01",
        "Verify a cloud data classification policy exists covering classes, encryption, logging, access, AWS scope and responsibilities.",
    )
    checks["DAT-02"] = workshop(
        "DAT-02",
        "Verify sensitive data locations are identified and automatic classification scope (Macie) is defined.",
    )
    checks["DAT-03"] = workshop("DAT-03", "Verify Macie is active for S3 classification. Link to DET-16/17 results.")

    def dat04(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        rcp_data = ctx.invoke_aws_cli(["organizations", "list-policies", "--filter", "RESOURCE_CONTROL_POLICY"])
        scp_data = ctx.invoke_aws_cli(["organizations", "list-policies", "--filter", "SERVICE_CONTROL_POLICY"])
        rcp_names: list[str] = []
        scp_exfiltration_names: list[str] = []
        if rcp_data and _test_dat_has_property(rcp_data, "Policies"):
            for policy in _get_dat_cli_array(rcp_data.get("Policies")):
                rcp_names.append(str(_get_dat_property_value(policy, ["Name"]) or ""))
        if scp_data and _test_dat_has_property(scp_data, "Policies"):
            for policy in _get_dat_cli_array(scp_data.get("Policies")):
                policy_id = str(_get_dat_property_value(policy, ["Id"]) or "")
                policy_name = str(_get_dat_property_value(policy, ["Name"]) or "")
                if not policy_id:
                    continue
                detail = ctx.invoke_aws_cli(["organizations", "describe-policy", "--policy-id", policy_id])
                content = str(
                    _get_dat_property_value(_get_dat_property_value(detail, ["Policy"]), ["Content"]) or ""
                )
                if re.search(r"PrincipalOrgID|s3:ResourceAccount|aws:PrincipalOrgID", content):
                    scp_exfiltration_names.append(policy_name)
        evidence = {
            "rcp_count": _get_dat_collection_count(rcp_names),
            "rcp_names": list(rcp_names),
            "scp_exfiltration_count": _get_dat_collection_count(scp_exfiltration_names),
            "scp_exfiltration_names": list(scp_exfiltration_names),
        }
        if _get_dat_collection_count(rcp_names) > 0 or _get_dat_collection_count(scp_exfiltration_names) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-04",
                "PARTIAL",
                evidence,
                "Organization policies found; verify DLP/exfiltration controls in workshop",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-04",
            "PARTIAL",
            evidence,
            "No RCP or exfiltration SCP patterns found; workshop verification required",
        )

    checks["DAT-04"] = dat04
    checks["DAT-05"] = workshop("DAT-05", "Verify Macie or equivalent DLP detection is active.")
    checks["DAT-06"] = workshop(
        "DAT-06",
        "Verify DLP violation workflow exists: qualification, containment, remediation and communication.",
    )
    checks["DAT-07"] = workshop(
        "DAT-07", "Verify CloudWatch log patterns do not expose PII. Manual log sampling required."
    )

    def dat08(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        volume_data = _invoke_aws_cli_in_region(ctx, ["ec2", "describe-volumes"], region)
        if volume_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-08")

        ebs_total = 0
        ebs_encrypted = 0
        ebs_unencrypted = 0
        if _test_dat_has_property(volume_data, "Volumes"):
            for volume in _get_dat_cli_array(volume_data.get("Volumes")):
                ebs_total += 1
                if _get_dat_property_value(volume, ["Encrypted"]) is True:
                    ebs_encrypted += 1
                else:
                    ebs_unencrypted += 1

        rds_data = _invoke_aws_cli_in_region(ctx, ["rds", "describe-db-instances"], region)
        if rds_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-08")

        rds_total = 0
        rds_encrypted = 0
        rds_unencrypted = 0
        if _test_dat_has_property(rds_data, "DBInstances"):
            for instance in _get_dat_cli_array(rds_data.get("DBInstances")):
                rds_total += 1
                if _get_dat_property_value(instance, ["StorageEncrypted"]) is True:
                    rds_encrypted += 1
                else:
                    rds_unencrypted += 1

        dynamo_total = 0
        dynamo_encrypted = 0
        dynamo_unencrypted = 0
        table_names: list[str] = []
        exclusive_start_table_name = None
        while True:
            table_args = ["dynamodb", "list-tables"]
            if exclusive_start_table_name:
                table_args.extend(["--exclusive-start-table-name", exclusive_start_table_name])
            table_list_data = _invoke_aws_cli_in_region(ctx, table_args, region)
            if table_list_data is None:
                return ctx.results.null_api_partial(account_id, account_name, region, "DAT-08")

            if _test_dat_has_property(table_list_data, "TableNames"):
                for table_name in _get_dat_cli_array(table_list_data.get("TableNames")):
                    table_names.append(str(table_name))

            exclusive_start_table_name = None
            if _test_dat_has_property(table_list_data, "LastEvaluatedTableName"):
                candidate = str(table_list_data.get("LastEvaluatedTableName") or "")
                if candidate:
                    exclusive_start_table_name = candidate
            if not exclusive_start_table_name:
                break

        for table_name in table_names:
            table_data = _invoke_aws_cli_in_region(
                ctx, ["dynamodb", "describe-table", "--table-name", table_name], region
            )
            if table_data is None:
                continue

            dynamo_total += 1
            is_encrypted = False
            table_obj = _get_dat_property_value(table_data, ["Table"])
            sse = _get_dat_property_value(table_obj, ["SSEDescription"])
            status = str(_get_dat_property_value(sse, ["Status"]) or "")
            sse_type = str(_get_dat_property_value(sse, ["SSEType"]) or "")
            if status == "ENABLED" and sse_type == "KMS":
                is_encrypted = True

            if is_encrypted:
                dynamo_encrypted += 1
            else:
                dynamo_unencrypted += 1

        bucket_names = _get_dat_s3_bucket_names(ctx, region)
        if bucket_names is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-08")

        s3_total = _get_dat_collection_count(bucket_names)
        s3_encrypted = 0
        s3_unencrypted = 0
        for bucket_name in bucket_names:
            if _test_dat_s3_bucket_sse_kms(ctx, region, bucket_name):
                s3_encrypted += 1
            else:
                s3_unencrypted += 1

        evidence = {
            "ebs": {"total": ebs_total, "encrypted": ebs_encrypted, "unencrypted": ebs_unencrypted},
            "rds": {"total": rds_total, "encrypted": rds_encrypted, "unencrypted": rds_unencrypted},
            "dynamodb": {"total": dynamo_total, "encrypted": dynamo_encrypted, "unencrypted": dynamo_unencrypted},
            "s3": {"total": s3_total, "sse_kms": s3_encrypted, "not_sse_kms": s3_unencrypted},
        }

        has_failure = ebs_unencrypted > 0 or rds_unencrypted > 0 or dynamo_unencrypted > 0 or s3_unencrypted > 0
        if has_failure:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-08",
                "FAIL",
                evidence,
                "One or more resources are not encrypted with managed keys",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-08",
            "PASS",
            evidence,
            "All assessed EBS, RDS, DynamoDB, and S3 resources meet encryption requirements",
        )

    checks["DAT-08"] = dat08

    def dat09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        lb_data = _invoke_aws_cli_in_region(ctx, ["elbv2", "describe-load-balancers"], region)
        if lb_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-09")

        load_balancers: list[Any] = []
        if _test_dat_has_property(lb_data, "LoadBalancers"):
            load_balancers = _get_dat_cli_array(lb_data.get("LoadBalancers"))

        http_listener_count = 0
        https_listener_count = 0
        http_without_redirect_count = 0
        weak_ssl_policy_count = 0
        failing_listeners: list[dict[str, str]] = []
        weak_ssl_listeners: list[dict[str, str]] = []
        weak_ssl_patterns = (
            "ELBSecurityPolicy-2016-08",
            "ELBSecurityPolicy-TLS-1-0",
            "ELBSecurityPolicy-TLS-1-1",
        )

        for load_balancer in load_balancers:
            if not _test_dat_has_property(load_balancer, "LoadBalancerArn"):
                continue
            listener_data = _invoke_aws_cli_in_region(
                ctx,
                ["elbv2", "describe-listeners", "--load-balancer-arn", str(load_balancer.get("LoadBalancerArn", ""))],
                region,
            )
            if listener_data is None or not _test_dat_has_property(listener_data, "Listeners"):
                continue

            for listener in _get_dat_cli_array(listener_data.get("Listeners")):
                protocol = str(listener.get("Protocol", "") or "")
                if protocol == "HTTPS":
                    https_listener_count += 1
                    ssl_policy = str(listener.get("SslPolicy", "") or "")
                    if not ssl_policy or any(pattern in ssl_policy for pattern in weak_ssl_patterns):
                        weak_ssl_policy_count += 1
                        if _get_dat_collection_count(weak_ssl_listeners) < 5:
                            weak_ssl_listeners.append(
                                {
                                    "load_balancer": str(load_balancer.get("LoadBalancerName", "")),
                                    "listener_arn": str(listener.get("ListenerArn", "")),
                                    "ssl_policy": ssl_policy or "unset",
                                }
                            )
                    continue
                if protocol != "HTTP":
                    continue

                http_listener_count += 1
                has_redirect = False
                if _test_dat_has_property(listener, "DefaultActions"):
                    for action in _get_dat_cli_array(listener.get("DefaultActions")):
                        if str(action.get("Type", "") or "") == "redirect":
                            has_redirect = True
                            break
                if not has_redirect:
                    http_without_redirect_count += 1
                    if _get_dat_collection_count(failing_listeners) < 5:
                        failing_listeners.append(
                            {
                                "load_balancer": str(load_balancer.get("LoadBalancerName", "")),
                                "listener_arn": str(listener.get("ListenerArn", "")),
                                "protocol": protocol,
                            }
                        )

        evidence = {
            "load_balancer_count": _get_dat_collection_count(load_balancers),
            "http_listener_count": http_listener_count,
            "https_listener_count": https_listener_count,
            "http_without_redirect_count": http_without_redirect_count,
            "weak_ssl_policy_count": weak_ssl_policy_count,
            "failing_listeners": list(failing_listeners),
            "weak_ssl_listeners": list(weak_ssl_listeners),
        }
        if http_without_redirect_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-09",
                "FAIL",
                evidence,
                "One or more HTTP listeners exist without redirect to HTTPS",
            )
        if weak_ssl_policy_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-09",
                "FAIL",
                evidence,
                "One or more HTTPS listeners use weak or missing TLS policies",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-09",
            "PASS",
            evidence,
            "All ALB listeners use HTTPS or HTTP redirects to HTTPS",
        )

    checks["DAT-09"] = dat09

    def dat10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        customer_keys = _get_dat_customer_master_keys(ctx, region)
        if customer_keys is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-10")

        keys_with_policies = 0
        unreadable_policy_count = 0
        for key in customer_keys:
            key_id = str(key.get("KeyId", ""))
            policy_data = _invoke_aws_cli_in_region(ctx, ["kms", "list-key-policies", "--key-id", key_id], region)
            if policy_data is None:
                unreadable_policy_count += 1
                continue
            if _test_dat_has_property(policy_data, "PolicyNames"):
                if _get_dat_collection_count(policy_data.get("PolicyNames")) > 0:
                    keys_with_policies += 1

        kms_event_count = 0
        for event_name in ("DeleteKey", "DisableKey", "ScheduleKeyDeletion"):
            event_data = _invoke_aws_cli_in_region(
                ctx,
                [
                    "cloudtrail",
                    "lookup-events",
                    "--lookup-attributes",
                    f"AttributeKey=EventName,AttributeValue={event_name}",
                    "--max-results",
                    "10",
                ],
                region,
            )
            if event_data and _test_dat_has_property(event_data, "Events"):
                kms_event_count += _get_dat_collection_count(event_data.get("Events"))

        evidence = {
            "cmk_count": _get_dat_collection_count(customer_keys),
            "keys_with_policies": keys_with_policies,
            "unreadable_policy_count": unreadable_policy_count,
            "kms_admin_event_count": kms_event_count,
        }
        if unreadable_policy_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-10",
                "PARTIAL",
                evidence,
                "Cannot read key policies for one or more CMKs",
            )
        if _get_dat_collection_count(customer_keys) > 0 and keys_with_policies > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "DAT-10", "PASS", evidence, "CMKs exist with defined key policies"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "DAT-10", "FAIL", evidence, "No CMKs with readable key policies found"
        )

    checks["DAT-10"] = dat10

    def dat11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        customer_keys = _get_dat_customer_master_keys(ctx, region)
        if customer_keys is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-11")

        enabled_count = 0
        disabled_count = 0
        disabled_key_ids: list[str] = []
        for key in customer_keys:
            key_id = str(key.get("KeyId", ""))
            rotation_data = _invoke_aws_cli_in_region(ctx, ["kms", "get-key-rotation-status", "--key-id", key_id], region)
            if rotation_data is None:
                disabled_count += 1
                if _get_dat_collection_count(disabled_key_ids) < 10:
                    disabled_key_ids.append(key_id)
                continue
            if _get_dat_property_value(rotation_data, ["KeyRotationEnabled"]) is True:
                enabled_count += 1
            else:
                disabled_count += 1
                if _get_dat_collection_count(disabled_key_ids) < 10:
                    disabled_key_ids.append(key_id)

        evidence = {
            "cmk_count": _get_dat_collection_count(customer_keys),
            "rotation_enabled_count": enabled_count,
            "rotation_disabled_count": disabled_count,
            "keys_without_rotation": list(disabled_key_ids),
        }
        if disabled_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-11",
                "FAIL",
                evidence,
                "One or more CMKs do not have rotation enabled",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "DAT-11", "PASS", evidence, "All CMKs have rotation enabled"
        )

    checks["DAT-11"] = dat11

    def dat12(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        customer_keys = _get_dat_customer_master_keys(ctx, region)
        if customer_keys is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-12")

        scheduled_count = 0
        scheduled_key_ids: list[str] = []
        for key in customer_keys:
            if _test_dat_has_property(key, "DeletionDate") and key.get("DeletionDate") is not None:
                scheduled_count += 1
                if _get_dat_collection_count(scheduled_key_ids) < 10:
                    scheduled_key_ids.append(str(key.get("KeyId", "")))

        evidence = {
            "cmk_count": _get_dat_collection_count(customer_keys),
            "scheduled_deletion_count": scheduled_count,
            "key_ids": list(scheduled_key_ids),
        }
        if scheduled_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-12",
                "FAIL",
                evidence,
                "One or more CMKs are scheduled for deletion",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "DAT-12", "PASS", evidence, "No keys scheduled for deletion"
        )

    checks["DAT-12"] = dat12

    def dat13(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        customer_keys = _get_dat_customer_master_keys(ctx, region)
        if customer_keys is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-13")

        total_grant_count = 0
        external_grant_count = 0
        external_grants: list[dict[str, str]] = []
        for key in customer_keys:
            key_id = str(key.get("KeyId", ""))
            grant_data = _invoke_aws_cli_in_region(ctx, ["kms", "list-grants", "--key-id", key_id], region)
            if grant_data is None or not _test_dat_has_property(grant_data, "Grants"):
                continue
            for grant in _get_dat_cli_array(grant_data.get("Grants")):
                total_grant_count += 1
                grantee = str(grant.get("GranteePrincipal", "") or "")
                if not grantee:
                    continue
                if account_id not in grantee:
                    external_grant_count += 1
                    if _get_dat_collection_count(external_grants) < 10:
                        external_grants.append({"key_id": key_id, "grantee": grantee})

        evidence = {
            "total_grant_count": total_grant_count,
            "external_grant_count": external_grant_count,
            "external_grants": list(external_grants),
        }
        if external_grant_count > 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "DAT-13", "FAIL", evidence, "Active grants to external principals found"
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "DAT-13", "PASS", evidence, "No external KMS grants found"
        )

    checks["DAT-13"] = dat13

    def dat14(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = _invoke_aws_cli_in_region(
            ctx, ["s3control", "get-public-access-block", "--account-id", account_id], region
        )
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-14")

        config = data.get("PublicAccessBlockConfiguration") if _test_dat_has_property(
            data, "PublicAccessBlockConfiguration"
        ) else None
        block_public_acls = bool(_get_dat_property_value(config, ["BlockPublicAcls"]) is True)
        ignore_public_acls = bool(_get_dat_property_value(config, ["IgnorePublicAcls"]) is True)
        block_public_policy = bool(_get_dat_property_value(config, ["BlockPublicPolicy"]) is True)
        restrict_public_buckets = bool(_get_dat_property_value(config, ["RestrictPublicBuckets"]) is True)

        evidence = {
            "BlockPublicAcls": block_public_acls,
            "IgnorePublicAcls": ignore_public_acls,
            "BlockPublicPolicy": block_public_policy,
            "RestrictPublicBuckets": restrict_public_buckets,
        }
        if block_public_acls and ignore_public_acls and block_public_policy and restrict_public_buckets:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-14",
                "PASS",
                evidence,
                "Account-level S3 Block Public Access is fully enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-14",
            "FAIL",
            evidence,
            "One or more account-level S3 Block Public Access settings is disabled",
        )

    checks["DAT-14"] = dat14

    def dat15(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        bucket_names = _get_dat_s3_bucket_names(ctx, region)
        if bucket_names is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-15")

        public_bucket_count = 0
        public_bucket_names: list[str] = []
        for bucket_name in bucket_names:
            if _test_dat_s3_bucket_public(ctx, region, bucket_name):
                public_bucket_count += 1
                if _get_dat_collection_count(public_bucket_names) < 5:
                    public_bucket_names.append(bucket_name)

        evidence = {
            "bucket_count": _get_dat_collection_count(bucket_names),
            "public_bucket_count": public_bucket_count,
            "public_bucket_names": list(public_bucket_names),
        }
        if public_bucket_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-15",
                "FAIL",
                evidence,
                "One or more buckets appear publicly accessible",
            )
        return ctx.results.audit_result(
            account_id, account_name, region, "DAT-15", "PASS", evidence, "No publicly accessible buckets detected"
        )

    checks["DAT-15"] = dat15

    def dat16(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        bucket_names = _get_dat_s3_bucket_names(ctx, region)
        if bucket_names is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-16")

        buckets_with_policy = 0
        buckets_without_policy = 0
        public_policy_buckets: list[str] = []
        buckets_without_tls_deny: list[str] = []
        for bucket_name in bucket_names:
            policy_data = _invoke_aws_cli_in_region(
                ctx, ["s3api", "get-bucket-policy", "--bucket", bucket_name], region
            )
            if policy_data is None:
                buckets_without_policy += 1
                continue
            policy_text = str(_get_dat_property_value(policy_data, ["Policy"]) or "")
            if not policy_text:
                buckets_without_policy += 1
                continue
            buckets_with_policy += 1
            if re.search(r'"Principal"\s*:\s*"\*"', policy_text) or re.search(
                r'"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"\s*\}', policy_text
            ):
                if _get_dat_collection_count(public_policy_buckets) < 5:
                    public_policy_buckets.append(bucket_name)
            if not _test_dat_bucket_policy_enforces_tls(policy_text):
                if _get_dat_collection_count(buckets_without_tls_deny) < 5:
                    buckets_without_tls_deny.append(bucket_name)

        evidence = {
            "bucket_count": _get_dat_collection_count(bucket_names),
            "buckets_with_policy": buckets_with_policy,
            "buckets_without_policy": buckets_without_policy,
            "public_policy_buckets": list(public_policy_buckets),
            "buckets_without_tls_deny": list(buckets_without_tls_deny),
        }
        if _get_dat_collection_count(public_policy_buckets) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-16",
                "FAIL",
                evidence,
                "One or more bucket policies allow public principal access",
            )
        if _get_dat_collection_count(buckets_without_tls_deny) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-16",
                "FAIL",
                evidence,
                "One or more bucket policies are missing a Deny rule for aws:SecureTransport=false",
            )
        if buckets_without_policy > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-16",
                "PARTIAL",
                evidence,
                "Some buckets have no bucket policy; verify least-privilege access in workshop",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-16",
            "PASS",
            evidence,
            "All buckets have policies without public principal patterns",
        )

    checks["DAT-16"] = dat16

    def dat17(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        bucket_names = _get_dat_s3_bucket_names(ctx, region)
        if bucket_names is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-17")

        critical_buckets: list[str] = []
        for bucket_name in bucket_names:
            if _test_dat_bucket_name_critical(bucket_name):
                critical_buckets.append(bucket_name)

        if _get_dat_collection_count(critical_buckets) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-17",
                "PARTIAL",
                {
                    "bucket_count": _get_dat_collection_count(bucket_names),
                    "critical_bucket_count": 0,
                    "versioning_enabled": 0,
                    "versioning_disabled": 0,
                },
                "Cannot determine which buckets are critical without consistent tags",
            )

        versioning_enabled = 0
        versioning_disabled = 0
        disabled_buckets: list[str] = []
        for bucket_name in critical_buckets:
            version_data = _invoke_aws_cli_in_region(
                ctx, ["s3api", "get-bucket-versioning", "--bucket", bucket_name], region
            )
            status = None
            if version_data and _test_dat_has_property(version_data, "Status"):
                status = str(version_data.get("Status", ""))
            if status == "Enabled":
                versioning_enabled += 1
            else:
                versioning_disabled += 1
                if _get_dat_collection_count(disabled_buckets) < 5:
                    disabled_buckets.append(bucket_name)

        evidence = {
            "bucket_count": _get_dat_collection_count(bucket_names),
            "critical_bucket_count": _get_dat_collection_count(critical_buckets),
            "versioning_enabled": versioning_enabled,
            "versioning_disabled": versioning_disabled,
            "disabled_buckets": list(disabled_buckets),
        }
        if versioning_disabled > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-17",
                "FAIL",
                evidence,
                "One or more critical buckets do not have versioning enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-17",
            "PASS",
            evidence,
            "Versioning is enabled on identified critical buckets",
        )

    checks["DAT-17"] = dat17

    def dat18(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        bucket_names = _get_dat_s3_bucket_names(ctx, region)
        if bucket_names is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-18")

        target_buckets: list[str] = []
        for bucket_name in bucket_names:
            if _test_dat_bucket_name_log_or_backup(bucket_name):
                target_buckets.append(bucket_name)

        if _get_dat_collection_count(target_buckets) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-18",
                "PARTIAL",
                {"bucket_count": _get_dat_collection_count(bucket_names), "assessed_buckets": []},
                "No log or backup buckets identified by naming convention",
            )

        compliance_count = 0
        governance_only_count = 0
        missing_lock_count = 0
        bucket_statuses: list[dict[str, str]] = []
        for bucket_name in target_buckets:
            lock_data = _invoke_aws_cli_in_region(
                ctx, ["s3api", "get-object-lock-configuration", "--bucket", bucket_name], region
            )
            if lock_data is None:
                missing_lock_count += 1
                if _get_dat_collection_count(bucket_statuses) < 10:
                    bucket_statuses.append({"bucket": bucket_name, "mode": "NONE"})
                continue

            mode = "NONE"
            lock_config = _get_dat_property_value(lock_data, ["ObjectLockConfiguration"])
            lock_enabled = _get_dat_property_value(lock_config, ["ObjectLockEnabled"])
            if lock_config and lock_enabled:
                retention = _get_dat_property_value(_get_dat_property_value(lock_config, ["Rule"]), ["DefaultRetention"])
                if retention:
                    mode = str(_get_dat_property_value(retention, ["Mode"]) or "")
                else:
                    mode = "ENABLED"

            if mode == "COMPLIANCE":
                compliance_count += 1
            elif mode == "GOVERNANCE":
                governance_only_count += 1
            else:
                missing_lock_count += 1

            if _get_dat_collection_count(bucket_statuses) < 10:
                bucket_statuses.append({"bucket": bucket_name, "mode": mode})

        evidence = {
            "assessed_bucket_count": _get_dat_collection_count(target_buckets),
            "compliance_mode_count": compliance_count,
            "governance_mode_count": governance_only_count,
            "missing_lock_count": missing_lock_count,
            "bucket_statuses": list(bucket_statuses),
        }
        if compliance_count == _get_dat_collection_count(target_buckets):
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-18",
                "PASS",
                evidence,
                "Object Lock enabled in COMPLIANCE mode on assessed buckets",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-18",
            "FAIL",
            evidence,
            "No Object Lock or GOVERNANCE mode only on one or more log or backup buckets",
        )

    checks["DAT-18"] = dat18

    def dat19(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        default_data = _invoke_aws_cli_in_region(ctx, ["ec2", "get-ebs-encryption-by-default"], region)
        if default_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-19")

        enabled = bool(_get_dat_property_value(default_data, ["EbsEncryptionByDefault"]) is True)
        volume_data = _invoke_aws_cli_in_region(
            ctx, ["ec2", "describe-volumes", "--filters", "Name=encrypted,Values=false"], region
        )
        if volume_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-19")

        unencrypted_volume_count = 0
        if _test_dat_has_property(volume_data, "Volumes"):
            unencrypted_volume_count = _get_dat_collection_count(volume_data.get("Volumes"))

        evidence = {"ebs_encryption_by_default": enabled, "unencrypted_volume_count": unencrypted_volume_count}
        if enabled and unencrypted_volume_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-19",
                "PASS",
                evidence,
                "EBS default encryption is enabled and no unencrypted volumes found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-19",
            "FAIL",
            evidence,
            "EBS default encryption is disabled or unencrypted volumes exist",
        )

    checks["DAT-19"] = dat19

    def dat20(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        snapshot_data = _invoke_aws_cli_in_region(ctx, ["ec2", "describe-snapshots", "--owner-ids", "self"], region)
        if snapshot_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-20")

        snapshots: list[Any] = []
        if _test_dat_has_property(snapshot_data, "Snapshots"):
            snapshots = _get_dat_cli_array(snapshot_data.get("Snapshots"))

        encrypted_count = 0
        unencrypted_count = 0
        public_share_count = 0
        failing_snapshots: list[dict[str, str]] = []
        for snapshot in snapshots:
            if _get_dat_property_value(snapshot, ["Encrypted"]) is True:
                encrypted_count += 1
            else:
                unencrypted_count += 1
                if _get_dat_collection_count(failing_snapshots) < 10:
                    failing_snapshots.append(
                        {"snapshot_id": str(snapshot.get("SnapshotId", "")), "reason": "unencrypted"}
                    )

            if not _test_dat_has_property(snapshot, "SnapshotId"):
                continue
            snapshot_id = str(snapshot.get("SnapshotId", ""))
            attribute_data = _invoke_aws_cli_in_region(
                ctx,
                [
                    "ec2",
                    "describe-snapshot-attribute",
                    "--snapshot-id",
                    snapshot_id,
                    "--attribute",
                    "createVolumePermission",
                ],
                region,
            )
            if attribute_data is None or not _test_dat_has_property(attribute_data, "CreateVolumePermissions"):
                continue
            for permission in _get_dat_cli_array(attribute_data.get("CreateVolumePermissions")):
                if str(permission.get("Group", "") or "") == "all":
                    public_share_count += 1
                    if _get_dat_collection_count(failing_snapshots) < 10:
                        failing_snapshots.append({"snapshot_id": snapshot_id, "reason": "public_share"})
                    break

        evidence = {
            "snapshot_count": _get_dat_collection_count(snapshots),
            "encrypted_count": encrypted_count,
            "unencrypted_count": unencrypted_count,
            "public_share_count": public_share_count,
            "failing_snapshots": list(failing_snapshots),
        }
        if unencrypted_count > 0 or public_share_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-20",
                "FAIL",
                evidence,
                "Unencrypted snapshots or public snapshot sharing found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-20",
            "PASS",
            evidence,
            "All owned snapshots are encrypted and not publicly shared",
        )

    checks["DAT-20"] = dat20

    def dat21(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        rds_data = _invoke_aws_cli_in_region(ctx, ["rds", "describe-db-instances"], region)
        if rds_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-21")

        instances: list[Any] = []
        if _test_dat_has_property(rds_data, "DBInstances"):
            instances = _get_dat_cli_array(rds_data.get("DBInstances"))

        encrypted_count = 0
        not_public_count = 0
        failing_instances: list[dict[str, Any]] = []
        for instance in instances:
            instance_id = str(instance.get("DBInstanceIdentifier", ""))
            is_encrypted = _get_dat_property_value(instance, ["StorageEncrypted"]) is True
            is_public = _get_dat_property_value(instance, ["PubliclyAccessible"]) is True

            if is_encrypted:
                encrypted_count += 1
            if not is_public:
                not_public_count += 1
            if not is_encrypted or is_public:
                if _get_dat_collection_count(failing_instances) < 10:
                    failing_instances.append(
                        {
                            "instance_id": instance_id,
                            "storage_encrypted": is_encrypted,
                            "publicly_accessible": is_public,
                        }
                    )

        evidence = {
            "instance_count": _get_dat_collection_count(instances),
            "encrypted_count": encrypted_count,
            "not_public_count": not_public_count,
            "failing_instances": list(failing_instances),
        }
        if _get_dat_collection_count(failing_instances) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-21",
                "FAIL",
                evidence,
                "One or more RDS instances are unencrypted or publicly accessible",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-21",
            "PASS",
            evidence,
            "All RDS instances are encrypted and not publicly accessible",
        )

    checks["DAT-21"] = dat21

    def dat22(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        vault_data = _invoke_aws_cli_in_region(ctx, ["backup", "list-backup-vaults"], region)
        if vault_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-22")

        vault_names: list[str] = []
        if _test_dat_has_property(vault_data, "BackupVaultList"):
            for vault in _get_dat_cli_array(vault_data.get("BackupVaultList")):
                if _test_dat_has_property(vault, "BackupVaultName"):
                    vault_names.append(str(vault.get("BackupVaultName", "")))

        if _get_dat_collection_count(vault_names) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "DAT-22", "PARTIAL", {"vault_count": 0}, "No backup vaults found to assess"
            )

        encrypted_vault_count = 0
        failing_vault_count = 0
        vault_evidence: list[dict[str, Any]] = []
        for vault_name in vault_names:
            describe_data = _invoke_aws_cli_in_region(
                ctx, ["backup", "describe-backup-vault", "--backup-vault-name", vault_name], region
            )
            if describe_data is None:
                failing_vault_count += 1
                continue

            encryption_key_arn = None
            if _test_dat_has_property(describe_data, "EncryptionKeyArn"):
                value = describe_data.get("EncryptionKeyArn")
                encryption_key_arn = str(value) if value is not None else None

            access_policy_present = False
            delete_recovery_point_denied = False
            if _test_dat_has_property(describe_data, "AccessPolicy"):
                access_policy_value = str(describe_data.get("AccessPolicy") or "")
                if access_policy_value:
                    access_policy_present = True
                    delete_recovery_point_denied = _test_dat_backup_policy_denies_delete_recovery(
                        access_policy_value
                    )

            vault_ok = bool(encryption_key_arn) and access_policy_present and delete_recovery_point_denied
            if vault_ok:
                encrypted_vault_count += 1
            else:
                failing_vault_count += 1

            if _get_dat_collection_count(vault_evidence) < 10:
                vault_evidence.append(
                    {
                        "vault_name": vault_name,
                        "encryption_key_arn": encryption_key_arn,
                        "access_policy_set": access_policy_present,
                        "delete_recovery_point_denied": delete_recovery_point_denied,
                    }
                )

        evidence = {
            "vault_count": _get_dat_collection_count(vault_names),
            "encrypted_vault_count": encrypted_vault_count,
            "failing_vault_count": failing_vault_count,
            "vaults": list(vault_evidence),
        }
        if failing_vault_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-22",
                "FAIL",
                evidence,
                "One or more backup vaults lack CMK encryption, access policy, or DeleteRecoveryPoint deny",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-22",
            "PASS",
            evidence,
            "Backup vaults are encrypted with CMKs and restrict recovery point deletion",
        )

    checks["DAT-22"] = dat22
    checks["DAT-23"] = workshop("DAT-23", "Verify data deletion procedure exists for decommissioned resources.")

    def dat24(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        secrets_data = _invoke_aws_cli_in_region(
            ctx, ["secretsmanager", "list-secrets", "--max-results", "100"], region
        )
        if secrets_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-24")

        secrets_count = 0
        if _test_dat_has_property(secrets_data, "SecretList"):
            secrets_count = _get_dat_collection_count(secrets_data.get("SecretList"))

        ssm_data = _invoke_aws_cli_in_region(ctx, ["ssm", "describe-parameters"], region)
        if ssm_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "DAT-24")

        string_param_count = 0
        secure_string_count = 0
        if _test_dat_has_property(ssm_data, "Parameters"):
            for parameter in _get_dat_cli_array(ssm_data.get("Parameters")):
                param_type = str(parameter.get("Type", "") or "")
                if param_type == "String":
                    string_param_count += 1
                if param_type == "SecureString":
                    secure_string_count += 1

        evidence = {
            "secrets_manager_count": secrets_count,
            "ssm_string_count": string_param_count,
            "ssm_securestring_count": secure_string_count,
        }
        if string_param_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-24",
                "PARTIAL",
                evidence,
                "SSM String parameters exist; verify they do not contain secrets during workshop",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-24",
            "PASS",
            evidence,
            "No SSM String parameters found; secrets should be stored in Secrets Manager",
        )

    checks["DAT-24"] = dat24

    def dat25(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        secrets: list[Any] = []
        next_token = None
        while True:
            args = ["secretsmanager", "list-secrets", "--max-results", "100"]
            if next_token:
                args.extend(["--next-token", next_token])
            secrets_data = _invoke_aws_cli_in_region(ctx, args, region)
            if secrets_data is None:
                return ctx.results.null_api_partial(account_id, account_name, region, "DAT-25")
            if _test_dat_has_property(secrets_data, "SecretList"):
                secrets.extend(_get_dat_cli_array(secrets_data.get("SecretList")))
            next_token = None
            if _test_dat_has_property(secrets_data, "NextToken"):
                candidate = str(secrets_data.get("NextToken") or "")
                if candidate:
                    next_token = candidate
            if not next_token:
                break

        if _get_dat_collection_count(secrets) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-25",
                "PARTIAL",
                {"secret_count": 0},
                "No Secrets Manager secrets found to assess rotation",
            )

        rotation_enabled_count = 0
        rotation_disabled_count = 0
        names_without_rotation: list[str] = []
        for secret in secrets:
            if _get_dat_property_value(secret, ["RotationEnabled"]) is True:
                rotation_enabled_count += 1
            else:
                rotation_disabled_count += 1
                if _get_dat_collection_count(names_without_rotation) < 10 and _test_dat_has_property(secret, "Name"):
                    names_without_rotation.append(str(secret.get("Name", "")))

        evidence = {
            "secret_count": _get_dat_collection_count(secrets),
            "rotation_enabled_count": rotation_enabled_count,
            "rotation_disabled_count": rotation_disabled_count,
            "names_without_rotation": list(names_without_rotation),
        }
        if rotation_disabled_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "DAT-25",
                "FAIL",
                evidence,
                "One or more secrets do not have rotation enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "DAT-25",
            "PASS",
            evidence,
            "All Secrets Manager secrets have rotation enabled",
        )

    checks["DAT-25"] = dat25

    return DomainModule(code="DAT", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
