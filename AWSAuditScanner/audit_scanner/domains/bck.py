"""BCK domain - backup and recovery controls (aligned with official tracker IDs)."""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {
    "BCK-01": "P0",
    "BCK-02": "P0",
    "BCK-03": "P0",
    "BCK-04": "P0",
    "BCK-05": "P0",
    "BCK-06": "P0",
    "BCK-07": "P0",
    "BCK-08": "P0",
    "BCK-09": "P0",
    "BCK-10": "P0",
    "BCK-11": "P0",
    "BCK-12": "P0",
    "BCK-13": "P1",
    "BCK-14": "P1",
    "BCK-15": "P0",
    "BCK-16": "P1",
    "BCK-17": "P1",
    "BCK-18": "P1",
    "BCK-19": "P1",
    "BCK-20": "P2",
}


def _bck_backup_plans(ctx: CheckContext) -> list[dict[str, Any]] | None:
    plans: list[dict[str, Any]] = []
    token: str | None = None

    while True:
        arguments = ["backup", "list-backup-plans"]
        if token:
            arguments.extend(["--next-token", token])

        data = ctx.invoke_aws_cli(arguments)
        if data is None:
            return None

        if has_property(data, "BackupPlansList"):
            plans.extend(cli_array(data.get("BackupPlansList")))

        token = None
        if has_property(data, "NextToken"):
            next_token = str(data.get("NextToken") or "").strip()
            if next_token:
                token = next_token
        if not token:
            break

    return plans


def _bck_backup_vaults(ctx: CheckContext) -> list[dict[str, Any]] | None:
    data = ctx.invoke_aws_cli(["backup", "list-backup-vaults"])
    if data is None:
        return None
    if has_property(data, "BackupVaultList"):
        return [vault for vault in cli_array(data.get("BackupVaultList")) if isinstance(vault, dict)]
    return []


def _bck_backup_plan_details(ctx: CheckContext, backup_plan_id: str) -> dict[str, Any] | None:
    return ctx.invoke_aws_cli(["backup", "get-backup-plan", "--backup-plan-id", backup_plan_id])


def _bck_describe_backup_vault(ctx: CheckContext, vault_name: str) -> dict[str, Any] | None:
    return ctx.invoke_aws_cli(["backup", "describe-backup-vault", "--backup-vault-name", vault_name])


def _bck_arn_resource_type(resource_text: str) -> str | None:
    patterns: list[tuple[str, str]] = [
        (r":ec2:", "EC2"),
        (r":rds:", "RDS"),
        (r":aurora:", "Aurora"),
        (r":elasticfilesystem:", "EFS"),
        (r":dynamodb:", "DynamoDB"),
        (r":redshift:", "Redshift"),
        (r":fsx:", "FSx"),
        (r":s3:", "S3"),
        (r":documentdb:", "DocumentDB"),
        (r":neptune:", "Neptune"),
        (r":storagegateway:", "StorageGateway"),
        (r":timestream:", "Timestream"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, resource_text, re.IGNORECASE):
            return label
    return None


def _bck_selection_resource_types(ctx: CheckContext, backup_plan_id: str) -> list[str]:
    list_data = ctx.invoke_aws_cli(["backup", "list-backup-selections", "--backup-plan-id", backup_plan_id])
    if list_data is None or not has_property(list_data, "BackupSelectionsList"):
        return []

    resource_types: list[str] = []
    for selection in cli_array(list_data.get("BackupSelectionsList")):
        if not has_property(selection, "SelectionId"):
            continue
        selection_id = str(property_value(selection, ["SelectionId"]) or "")
        if not selection_id:
            continue

        detail_data = ctx.invoke_aws_cli(
            [
                "backup",
                "get-backup-selection",
                "--backup-plan-id",
                backup_plan_id,
                "--selection-id",
                selection_id,
            ]
        )
        if detail_data is None:
            continue

        backup_selection = property_value(detail_data, ["BackupSelection"])
        resources = cli_array(property_value(backup_selection, ["Resources"]))
        for resource in resources:
            resource_text = str(resource)
            resource_type = _bck_arn_resource_type(resource_text)
            if resource_type and resource_type not in resource_types:
                resource_types.append(resource_type)

        tags = property_value(backup_selection, ["ListOfTags"])
        if collection_count(tags) > 0 and "TAGGED" not in resource_types:
            resource_types.append("TAGGED")

    return resource_types


def _bck_schedule_frequent_enough(schedule_expression: str) -> bool:
    schedule = schedule_expression.lower()
    if re.search(r"rate\((\d+)\s+hour", schedule):
        return True
    if re.search(r"rate\(1\s+day", schedule):
        return True
    if re.search(r"cron\(", schedule):
        if not re.search(r"sun|mon|tue|wed|thu|fri|sat|\? \* \d|\? \* [0-9]", schedule):
            return True
    day_match = re.search(r"rate\((\d+)\s+day", schedule)
    if day_match:
        days = int(day_match.group(1))
        if days <= 1:
            return True
    return False


def _bck_account_id_from_arn(arn: str) -> str | None:
    match = re.search(r"arn:aws:[^:]*:[^:]*:(\d{12}):", arn)
    if match:
        return match.group(1)
    return None


def _bck_plan_schedule_evidence(ctx: CheckContext, plans: list[dict[str, Any]]) -> dict[str, Any]:
    schedules: list[dict[str, str]] = []
    infrequent_count = 0

    for plan in plans:
        plan_id = str(property_value(plan, ["BackupPlanId"]) or "")
        plan_name = str(property_value(plan, ["BackupPlanName"]) or "")
        if not plan_id:
            continue

        plan_details = _bck_backup_plan_details(ctx, plan_id)
        backup_plan = property_value(plan_details, ["BackupPlan"]) if plan_details else None
        rules = cli_array(property_value(backup_plan, ["Rules"])) if backup_plan else []
        for rule in rules:
            schedule = str(property_value(rule, ["ScheduleExpression"]) or "")
            schedules.append(
                {
                    "plan_name": plan_name,
                    "rule_name": str(property_value(rule, ["RuleName"]) or ""),
                    "schedule": schedule,
                }
            )
            if not _bck_schedule_frequent_enough(schedule):
                infrequent_count += 1

    return {
        "schedule_count": collection_count(schedules),
        "infrequent_count": infrequent_count,
        "schedules": schedules,
    }


def _bck_plan_retention_evidence(ctx: CheckContext, plans: list[dict[str, Any]]) -> dict[str, Any]:
    rule_evidence: list[dict[str, Any]] = []
    failing_rules = 0

    for plan in plans:
        plan_id = str(property_value(plan, ["BackupPlanId"]) or "")
        plan_name = str(property_value(plan, ["BackupPlanName"]) or "")
        if not plan_id:
            continue

        plan_details = _bck_backup_plan_details(ctx, plan_id)
        backup_plan = property_value(plan_details, ["BackupPlan"]) if plan_details else None
        rules = cli_array(property_value(backup_plan, ["Rules"])) if backup_plan else []
        for rule in rules:
            lifecycle = property_value(rule, ["Lifecycle"])
            delete_after_days = int(property_value(lifecycle, ["DeleteAfterDays"]) or 0) if lifecycle else 0
            rule_evidence.append(
                {
                    "plan_name": plan_name,
                    "rule_name": str(property_value(rule, ["RuleName"]) or ""),
                    "delete_after_days": delete_after_days,
                }
            )
            if delete_after_days < 30:
                failing_rules += 1

    return {
        "rule_count": collection_count(rule_evidence),
        "failing_rules": failing_rules,
        "rules": rule_evidence,
    }


def _bck_rds_retention_evidence(ctx: CheckContext) -> dict[str, Any] | None:
    data = ctx.invoke_aws_cli(["rds", "describe-db-instances"])
    if data is None:
        return None

    instances = cli_array(data.get("DBInstances")) if has_property(data, "DBInstances") else []
    failing_instances: list[str] = []
    instance_evidence: list[dict[str, Any]] = []

    for instance in instances:
        retention = int(property_value(instance, ["BackupRetentionPeriod"]) or 0)
        instance_id = str(property_value(instance, ["DBInstanceIdentifier"]) or "")
        instance_evidence.append({"instance_id": instance_id, "retention": retention})
        if retention < 7 and collection_count(failing_instances) < 10:
            failing_instances.append(instance_id)

    return {
        "instance_count": collection_count(instances),
        "instances": instance_evidence,
        "failing_instances": failing_instances,
    }


def _bck_efs_backup_evidence(ctx: CheckContext) -> dict[str, Any] | None:
    data = ctx.invoke_aws_cli(["efs", "describe-file-systems"])
    if data is None:
        return None

    file_systems = cli_array(data.get("FileSystems")) if has_property(data, "FileSystems") else []
    enabled_count = 0
    disabled_count = 0
    efs_evidence: list[dict[str, Any]] = []

    for file_system in file_systems:
        file_system_id = str(property_value(file_system, ["FileSystemId"]) or "")
        policy_data = ctx.invoke_aws_cli(["efs", "describe-backup-policy", "--file-system-id", file_system_id])
        status: str | None = None
        backup_policy = property_value(policy_data, ["BackupPolicy"]) if policy_data else None
        if backup_policy:
            status = str(property_value(backup_policy, ["Status"]) or "")
        if status == "ENABLED":
            enabled_count += 1
        else:
            disabled_count += 1
        if collection_count(efs_evidence) < 10:
            efs_evidence.append({"file_system_id": file_system_id, "backup_status": status})

    return {
        "efs_count": collection_count(file_systems),
        "enabled_count": enabled_count,
        "disabled_count": disabled_count,
        "file_systems": efs_evidence,
    }


def _bck_dynamodb_pitr_evidence(ctx: CheckContext) -> dict[str, Any] | None:
    table_names: list[str] = []
    exclusive_start: str | None = None

    while True:
        arguments = ["dynamodb", "list-tables"]
        if exclusive_start:
            arguments.extend(["--exclusive-start-table-name", exclusive_start])
        list_data = ctx.invoke_aws_cli(arguments)
        if list_data is None:
            return None
        if has_property(list_data, "TableNames"):
            table_names.extend([str(name) for name in cli_array(list_data.get("TableNames"))])
        exclusive_start = None
        if has_property(list_data, "LastEvaluatedTableName"):
            token = str(property_value(list_data, ["LastEvaluatedTableName"]) or "").strip()
            if token:
                exclusive_start = token
        if not exclusive_start:
            break

    enabled_count = 0
    disabled_count = 0
    table_evidence: list[dict[str, Any]] = []

    for table_name in table_names:
        backup_data = ctx.invoke_aws_cli(["dynamodb", "describe-continuous-backups", "--table-name", table_name])
        pitr_status: str | None = None
        cb_desc = property_value(backup_data, ["ContinuousBackupsDescription"]) if backup_data else None
        pitr_desc = property_value(cb_desc, ["PointInTimeRecoveryDescription"]) if cb_desc else None
        if pitr_desc:
            pitr_status = str(property_value(pitr_desc, ["PointInTimeRecoveryStatus"]) or "")
        if pitr_status == "ENABLED":
            enabled_count += 1
        else:
            disabled_count += 1
        if collection_count(table_evidence) < 10:
            table_evidence.append({"table_name": table_name, "pitr_status": pitr_status})

    return {
        "table_count": collection_count(table_names),
        "enabled_count": enabled_count,
        "disabled_count": disabled_count,
        "tables": table_evidence,
    }


def _bck_redshift_retention_evidence(ctx: CheckContext) -> dict[str, Any] | None:
    data = ctx.invoke_aws_cli(["redshift", "describe-clusters"])
    if data is None:
        return None

    clusters = cli_array(data.get("Clusters")) if has_property(data, "Clusters") else []
    failing_clusters: list[str] = []
    cluster_evidence: list[dict[str, Any]] = []

    for cluster in clusters:
        cluster_id = str(property_value(cluster, ["ClusterIdentifier"]) or "")
        retention = int(property_value(cluster, ["AutomatedSnapshotRetentionPeriod"]) or 0)
        cluster_evidence.append({"cluster_id": cluster_id, "retention_days": retention})
        if retention < 7 and collection_count(failing_clusters) < 10:
            failing_clusters.append(cluster_id)

    return {
        "cluster_count": collection_count(clusters),
        "clusters": cluster_evidence,
        "failing_clusters": failing_clusters,
    }


def _bck_protected_resource_evidence(ctx: CheckContext) -> dict[str, Any] | None:
    resources: list[dict[str, Any]] = []
    token: str | None = None

    while True:
        arguments = ["backup", "list-protected-resources"]
        if token:
            arguments.extend(["--next-token", token])
        data = ctx.invoke_aws_cli(arguments)
        if data is None:
            return None
        if has_property(data, "Results"):
            resources.extend(cli_array(data.get("Results")))
        token = None
        if has_property(data, "NextToken"):
            next_token = str(property_value(data, ["NextToken"]) or "").strip()
            if next_token:
                token = next_token
        if not token:
            break

    type_counts: dict[str, int] = {}
    for resource in resources:
        resource_type = str(property_value(resource, ["ResourceType"]) or "")
        type_counts[resource_type] = type_counts.get(resource_type, 0) + 1

    return {
        "protected_resource_count": collection_count(resources),
        "resource_type_counts": type_counts,
    }


def _bck_vault_encryption_evidence(ctx: CheckContext, vaults: list[dict[str, Any]]) -> dict[str, Any]:
    vault_evidence: list[dict[str, Any]] = []
    failing_vaults = 0

    for vault in vaults:
        vault_name = str(property_value(vault, ["BackupVaultName"]) or "")
        detail_data = _bck_describe_backup_vault(ctx, vault_name)
        if detail_data is None:
            failing_vaults += 1
            continue

        encryption_key_arn: str | None = None
        if has_property(detail_data, "EncryptionKeyArn"):
            value = str(property_value(detail_data, ["EncryptionKeyArn"]) or "")
            encryption_key_arn = value or None

        is_cmk = False
        if encryption_key_arn and not re.search(r":alias/aws/", encryption_key_arn):
            if re.search(r"arn:aws:kms:", encryption_key_arn):
                is_cmk = True

        vault_evidence.append(
            {
                "vault_name": vault_name,
                "encryption_key_arn": encryption_key_arn,
                "cmk": is_cmk,
            }
        )
        if not is_cmk:
            failing_vaults += 1

    return {
        "vault_count": collection_count(vaults),
        "vaults": vault_evidence,
        "failing_vaults": failing_vaults,
    }


def _bck_vault_deletion_evidence(ctx: CheckContext, vaults: list[dict[str, Any]]) -> dict[str, Any]:
    vault_evidence: list[dict[str, Any]] = []
    failing_vaults = 0

    for vault in vaults:
        vault_name = str(property_value(vault, ["BackupVaultName"]) or "")
        policy_data = ctx.invoke_aws_cli(
            ["backup", "get-backup-vault-access-policy", "--backup-vault-name", vault_name]
        )

        has_policy = policy_data is not None
        restricts_delete = False
        policy_text = str(property_value(policy_data, ["Policy"]) or "")
        if has_policy and policy_text:
            if re.search(r"backup:DeleteRecoveryPoint", policy_text):
                if re.search(r'"Effect"\s*:\s*"Deny"', policy_text):
                    restricts_delete = True
                if re.search(r"Condition", policy_text):
                    restricts_delete = True

        vault_evidence.append(
            {
                "vault_name": vault_name,
                "policy_present": has_policy,
                "restricts_delete": restricts_delete,
            }
        )
        if not has_policy or not restricts_delete:
            failing_vaults += 1

    return {
        "vault_count": collection_count(vaults),
        "vaults": vault_evidence,
        "failing_vaults": failing_vaults,
    }


def _bck_vault_lock_evidence(ctx: CheckContext, vaults: list[dict[str, Any]]) -> dict[str, Any]:
    vault_evidence: list[dict[str, Any]] = []
    locked_count = 0
    unlocked_count = 0

    for vault in vaults:
        vault_name = str(property_value(vault, ["BackupVaultName"]) or "")
        detail_data = _bck_describe_backup_vault(ctx, vault_name)
        locked = False
        min_retention_days: int | None = None
        max_retention_days: int | None = None
        lock_date: str | None = None

        if detail_data:
            if has_property(detail_data, "Locked"):
                locked = bool(property_value(detail_data, ["Locked"]))
            if has_property(detail_data, "MinRetentionDays"):
                min_retention_days = int(property_value(detail_data, ["MinRetentionDays"]) or 0)
            if has_property(detail_data, "MaxRetentionDays"):
                max_retention_days = int(property_value(detail_data, ["MaxRetentionDays"]) or 0)
            if has_property(detail_data, "LockDate"):
                lock_date = str(property_value(detail_data, ["LockDate"]) or "") or None

        if locked:
            locked_count += 1
        else:
            unlocked_count += 1

        vault_evidence.append(
            {
                "vault_name": vault_name,
                "locked": locked,
                "min_retention_days": min_retention_days,
                "max_retention_days": max_retention_days,
                "lock_date": lock_date,
            }
        )

    return {
        "vault_count": collection_count(vaults),
        "locked_count": locked_count,
        "unlocked_count": unlocked_count,
        "vaults": vault_evidence,
    }


def _bck_org_backup_centralization_evidence(ctx: CheckContext) -> dict[str, Any]:
    delegated_data = ctx.invoke_aws_cli(["organizations", "list-delegated-administrators"])
    backup_policy_data = ctx.invoke_aws_cli(["organizations", "list-policies", "--filter", "BACKUP_POLICY"])

    backup_delegated_admins: list[str] = []
    if delegated_data and has_property(delegated_data, "DelegatedAdministrators"):
        for admin in cli_array(property_value(delegated_data, ["DelegatedAdministrators"])):
            if not isinstance(admin, dict):
                continue
            service_principal = str(property_value(admin, ["ServicePrincipal"]) or "")
            if "backup" not in service_principal.lower():
                continue
            account_id = str(
                property_value(admin, ["Id"])
                or property_value(admin, ["AccountId"])
                or property_value(admin, ["Arn"])
                or ""
            )
            if account_id and collection_count(backup_delegated_admins) < 10:
                backup_delegated_admins.append(account_id)

    backup_policy_names: list[str] = []
    if backup_policy_data and has_property(backup_policy_data, "Policies"):
        for policy in cli_array(property_value(backup_policy_data, ["Policies"])):
            if not isinstance(policy, dict):
                continue
            policy_name = str(property_value(policy, ["Name"]) or "")
            if policy_name:
                backup_policy_names.append(policy_name)

    return {
        "backup_delegated_admin_count": collection_count(backup_delegated_admins),
        "backup_delegated_admins": list(backup_delegated_admins),
        "org_backup_policy_count": collection_count(backup_policy_names),
        "org_backup_policy_names": list(backup_policy_names),
    }


def _bck_vault_policy_access_restricted(policy_text: str) -> bool:
    if not policy_text.strip():
        return False
    if re.search(r'"Principal"\s*:\s*"\*"', policy_text):
        return False
    if re.search(r'"AWS"\s*:\s*"\*"', policy_text):
        return False
    return bool(re.search(r"backup:", policy_text, re.IGNORECASE))


def _bck_scp_delete_recovery_point_evidence(ctx: CheckContext) -> dict[str, Any] | None:
    policy_data = ctx.invoke_aws_cli(["organizations", "list-policies", "--filter", "SERVICE_CONTROL_POLICY"])
    if policy_data is None:
        return None

    matching_policies: list[str] = []
    if has_property(policy_data, "Policies"):
        for policy in cli_array(property_value(policy_data, ["Policies"])):
            if not isinstance(policy, dict):
                continue
            policy_id = str(property_value(policy, ["Id"]) or "")
            policy_name = str(property_value(policy, ["Name"]) or "")
            if not policy_id:
                continue
            detail = ctx.invoke_aws_cli(["organizations", "describe-policy", "--policy-id", policy_id])
            content = str(property_value(property_value(detail, ["Policy"]), ["Content"]) or "")
            if re.search(r"DeleteRecoveryPoint", content, re.IGNORECASE) and re.search(
                r"Deny", content, re.IGNORECASE
            ):
                matching_policies.append(policy_name)

    return {
        "scp_count_with_delete_deny": collection_count(matching_policies),
        "matching_policy_names": list(matching_policies),
    }


def _bck_backup_alerting_evidence(ctx: CheckContext) -> dict[str, Any]:
    failed_jobs_data = ctx.invoke_aws_cli(["backup", "list-backup-jobs", "--by-state", "FAILED", "--max-results", "50"])
    rules_data = ctx.invoke_aws_cli(["events", "list-rules"])
    alarms_data = ctx.invoke_aws_cli(["cloudwatch", "describe-alarms"])

    failed_jobs: list[dict[str, Any]] = []
    if failed_jobs_data and has_property(failed_jobs_data, "BackupJobs"):
        for job in cli_array(property_value(failed_jobs_data, ["BackupJobs"])):
            if not isinstance(job, dict):
                continue
            failed_jobs.append(
                {
                    "resource_type": str(property_value(job, ["ResourceType"]) or ""),
                    "state": str(property_value(job, ["State"]) or ""),
                    "creation_date": str(property_value(job, ["CreationDate"]) or ""),
                }
            )

    matching_rules: list[str] = []
    if rules_data and has_property(rules_data, "Rules"):
        for rule in cli_array(property_value(rules_data, ["Rules"])):
            if not isinstance(rule, dict):
                continue
            rule_name = str(property_value(rule, ["Name"]) or "")
            event_pattern = str(property_value(rule, ["EventPattern"]) or "")
            if re.search(r"backup|Backup|DeleteRecoveryPoint", event_pattern) or re.search(
                r"backup|Backup|DeleteRecoveryPoint", rule_name, re.IGNORECASE
            ):
                matching_rules.append(rule_name)

    matching_alarms: list[str] = []
    if alarms_data and has_property(alarms_data, "MetricAlarms"):
        for alarm in cli_array(property_value(alarms_data, ["MetricAlarms"])):
            if not isinstance(alarm, dict):
                continue
            alarm_name = str(property_value(alarm, ["AlarmName"]) or "")
            if re.search(r"backup|Backup", alarm_name, re.IGNORECASE):
                matching_alarms.append(alarm_name)

    return {
        "recent_failed_job_count": collection_count(failed_jobs),
        "recent_failed_jobs": list(failed_jobs[:10]),
        "matching_rule_names": list(matching_rules),
        "matching_alarm_names": list(matching_alarms),
    }


def _bck_vault_isolation_evidence(ctx: CheckContext, vaults: list[dict[str, Any]], account_id: str) -> dict[str, Any]:
    deletion_evidence = _bck_vault_deletion_evidence(ctx, vaults)
    vault_evidence: list[dict[str, Any]] = []
    cross_account_count = 0
    restrictive_access_count = 0

    for vault in vaults:
        vault_arn = str(property_value(vault, ["BackupVaultArn"]) or "")
        vault_name = str(property_value(vault, ["BackupVaultName"]) or "")
        vault_account = _bck_account_id_from_arn(vault_arn)
        is_cross_account = bool(vault_account and vault_account != account_id)
        if is_cross_account:
            cross_account_count += 1

        policy_data = ctx.invoke_aws_cli(
            ["backup", "get-backup-vault-access-policy", "--backup-vault-name", vault_name]
        )
        policy_text = str(property_value(policy_data, ["Policy"]) or "")
        access_restricted = _bck_vault_policy_access_restricted(policy_text)
        if access_restricted:
            restrictive_access_count += 1

        vault_evidence.append(
            {
                "vault_name": vault_name,
                "vault_arn": vault_arn,
                "account_id": vault_account,
                "cross_account": is_cross_account,
                "access_policy_restricted": access_restricted,
            }
        )

    restrictive_vaults = sum(
        1
        for vault in deletion_evidence.get("vaults", [])
        if vault.get("policy_present") and vault.get("restricts_delete")
    )

    return {
        "vault_count": collection_count(vaults),
        "cross_account_count": cross_account_count,
        "restrictive_access_count": restrictive_access_count,
        "restrictive_vault_count": restrictive_vaults,
        "vaults": vault_evidence,
        "access_policies": deletion_evidence.get("vaults", []),
    }


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(cid: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, cid, notes)

        return _check

    checks["BCK-01"] = workshop(
        "BCK-01",
        "Verify formal backup strategy for the AWS socle exists. Perimeters, frequencies, retentions, exclusions and responsibilities are defined.",
    )

    def bck02(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        org_evidence = _bck_org_backup_centralization_evidence(ctx)
        plans = _bck_backup_plans(ctx)
        vaults = _bck_backup_vaults(ctx)
        if plans is None and vaults is None and org_evidence["backup_delegated_admin_count"] == 0:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-02")

        plan_count = collection_count(plans or [])
        vault_count = collection_count(vaults or [])
        evidence = {
            "organization": org_evidence,
            "plan_count": plan_count,
            "vault_count": vault_count,
        }

        org_centralized = (
            org_evidence["backup_delegated_admin_count"] > 0 or org_evidence["org_backup_policy_count"] > 0
        )
        local_deployed = plan_count > 0 and vault_count > 0

        if org_centralized and local_deployed:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-02",
                "PASS",
                evidence,
                "AWS Backup is centrally governed with organization policies and local plans/vaults",
            )
        if org_centralized or local_deployed:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-02",
                "PARTIAL",
                evidence,
                "AWS Backup centralization is partially evidenced (organization and/or local deployment)",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-02",
            "FAIL",
            evidence,
            "No organization-level AWS Backup governance or local plans/vaults found",
        )

    checks["BCK-02"] = bck02

    def bck03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        plans = _bck_backup_plans(ctx)
        if plans is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-03")

        covered_types: list[str] = []
        plan_evidence: list[dict[str, Any]] = []
        for plan in plans:
            plan_id = str(property_value(plan, ["BackupPlanId"]) or "")
            plan_name = str(property_value(plan, ["BackupPlanName"]) or "")
            types = _bck_selection_resource_types(ctx, plan_id) if plan_id else []
            for resource_type in types:
                if resource_type not in covered_types:
                    covered_types.append(resource_type)
            plan_evidence.append({"plan_id": plan_id, "plan_name": plan_name, "resource_types": list(types)})

        efs_evidence = _bck_efs_backup_evidence(ctx)
        if efs_evidence is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-03")

        dynamodb_evidence = _bck_dynamodb_pitr_evidence(ctx)
        if dynamodb_evidence is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-03")

        protected_evidence = _bck_protected_resource_evidence(ctx)
        if protected_evidence is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-03")

        type_counts = protected_evidence.get("resource_type_counts", {})
        has_plan_ec2 = "EC2" in covered_types or "TAGGED" in covered_types
        has_plan_rds = "RDS" in covered_types or "Aurora" in covered_types or "TAGGED" in covered_types
        has_plan_efs = "EFS" in covered_types or "TAGGED" in covered_types
        has_plan_dynamo = "DynamoDB" in covered_types or "TAGGED" in covered_types
        has_plan_fsx = "FSx" in covered_types or "TAGGED" in covered_types
        fsx_in_scope = int(type_counts.get("FSx", 0) or 0) > 0
        plans_cover_core = has_plan_ec2 and has_plan_rds and has_plan_efs and has_plan_dynamo
        plans_cover_fsx = not fsx_in_scope or has_plan_fsx
        plans_cover_all = plans_cover_core and plans_cover_fsx

        efs_ok = efs_evidence["efs_count"] == 0 or efs_evidence["disabled_count"] == 0
        dynamo_ok = dynamodb_evidence["table_count"] == 0 or dynamodb_evidence["disabled_count"] == 0
        protected_ok = (
            protected_evidence["protected_resource_count"] == 0
            or (
                ("EC2" in type_counts or "EBS" in type_counts)
                and ("RDS" in type_counts or "Aurora" in type_counts)
                and ("EFS" in type_counts)
                and (not fsx_in_scope or "FSx" in type_counts)
            )
        )

        resource_presence = {
            "backup_plans": collection_count(plans),
            "efs_file_systems": efs_evidence["efs_count"],
            "dynamodb_tables": dynamodb_evidence["table_count"],
            "protected_resources": protected_evidence["protected_resource_count"],
        }
        if sum(resource_presence.values()) == 0:
            return ctx.results.not_applicable_no_resources(
                account_id,
                account_name,
                region,
                "BCK-03",
                {"resource_presence": resource_presence, "plans": plan_evidence},
            )

        evidence = {
            "plan_count": collection_count(plans),
            "plans": plan_evidence,
            "covered_types": covered_types,
            "efs": efs_evidence,
            "dynamodb": dynamodb_evidence,
            "protected_resources": protected_evidence,
        }

        checks_passed = sum([plans_cover_all, efs_ok, dynamo_ok, protected_ok])
        if checks_passed == 4:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-03",
                "PASS",
                evidence,
                "Critical services are covered by backups across plans, EFS, DynamoDB and protected resources",
            )
        if checks_passed > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-03",
                "PARTIAL",
                evidence,
                "Backup coverage exists but not all critical resource types are fully covered",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-03",
            "FAIL",
            evidence,
            "Critical services are not adequately covered by backups",
        )

    checks["BCK-03"] = bck03

    def bck04(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        plans = _bck_backup_plans(ctx)
        if plans is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-04")
        if collection_count(plans) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-04", "FAIL", {"plan_count": 0}, "No backup plans found"
            )

        evidence = _bck_plan_schedule_evidence(ctx, plans)
        if evidence["schedule_count"] == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-04", "FAIL", evidence, "No backup rules found"
            )
        if evidence["infrequent_count"] == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-04",
                "PASS",
                evidence,
                "Backup schedules are daily or more frequent",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-04",
            "FAIL",
            evidence,
            "One or more backup schedules are weekly or less frequent",
        )

    checks["BCK-04"] = bck04

    def bck05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        plans = _bck_backup_plans(ctx)
        if plans is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-05")

        plan_retention = _bck_plan_retention_evidence(ctx, plans)
        rds_retention = _bck_rds_retention_evidence(ctx)
        efs_evidence = _bck_efs_backup_evidence(ctx)
        dynamodb_evidence = _bck_dynamodb_pitr_evidence(ctx)
        protected_evidence = _bck_protected_resource_evidence(ctx)
        redshift_evidence = _bck_redshift_retention_evidence(ctx)
        if (
            rds_retention is None
            or efs_evidence is None
            or dynamodb_evidence is None
            or protected_evidence is None
            or redshift_evidence is None
        ):
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-05")

        targets = {
            "backup_plan_rules": plan_retention["rule_count"],
            "rds_instances": rds_retention["instance_count"],
            "efs_file_systems": efs_evidence["efs_count"],
            "dynamodb_tables": dynamodb_evidence["table_count"],
            "protected_resources": protected_evidence["protected_resource_count"],
            "redshift_clusters": redshift_evidence["cluster_count"],
        }
        evidence = {
            "targets": targets,
            "backup_plan_rules": plan_retention,
            "rds_instances": rds_retention,
            "efs": efs_evidence,
            "dynamodb": dynamodb_evidence,
            "protected_resources": protected_evidence,
            "redshift_clusters": redshift_evidence,
        }
        if sum(targets.values()) == 0:
            return ctx.results.not_applicable_no_resources(account_id, account_name, region, "BCK-05", evidence)

        plan_ok = plan_retention["rule_count"] == 0 or plan_retention["failing_rules"] == 0
        rds_ok = rds_retention["instance_count"] == 0 or collection_count(rds_retention["failing_instances"]) == 0
        efs_ok = efs_evidence["efs_count"] == 0 or efs_evidence["disabled_count"] == 0
        dynamo_ok = dynamodb_evidence["table_count"] == 0 or dynamodb_evidence["disabled_count"] == 0
        redshift_ok = (
            redshift_evidence["cluster_count"] == 0
            or collection_count(redshift_evidence["failing_clusters"]) == 0
        )

        if plan_ok and rds_ok and efs_ok and dynamo_ok and redshift_ok:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-05",
                "PASS",
                evidence,
                "Retention periods are defined and applied on backup plans and in-scope data services",
            )
        if plan_ok or rds_ok or efs_ok or dynamo_ok or redshift_ok:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-05",
                "PARTIAL",
                evidence,
                "Retention is applied on some but not all backup targets",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-05",
            "FAIL",
            evidence,
            "Retention periods are missing or below required thresholds",
        )

    checks["BCK-05"] = bck05

    def bck06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        vaults = _bck_backup_vaults(ctx)
        if vaults is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-06")
        if collection_count(vaults) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-06", "FAIL", {"vault_count": 0}, "No backup vaults found"
            )

        evidence = _bck_vault_encryption_evidence(ctx, vaults)
        if evidence["failing_vaults"] == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-06",
                "PASS",
                evidence,
                "All backup vaults are encrypted with customer-managed keys",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-06",
            "FAIL",
            evidence,
            "One or more backup vaults lack CMK encryption",
        )

    checks["BCK-06"] = bck06

    def bck07(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        vaults = _bck_backup_vaults(ctx)
        if vaults is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-07")
        if collection_count(vaults) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-07", "FAIL", {"vault_count": 0}, "No backup vaults found"
            )

        evidence = _bck_vault_isolation_evidence(ctx, vaults, account_id)
        if evidence["cross_account_count"] > 0 and evidence["restrictive_access_count"] == evidence["vault_count"]:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-07",
                "PASS",
                evidence,
                "Backup vaults are isolated with restricted access policies",
            )
        if evidence["cross_account_count"] > 0 or evidence["restrictive_access_count"] > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-07",
                "PARTIAL",
                evidence,
                "Some isolation signals exist but vault access is not fully restricted",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-07",
            "FAIL",
            evidence,
            "Backups are not isolated from source environments",
        )

    checks["BCK-07"] = bck07

    def bck08(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        vaults = _bck_backup_vaults(ctx)
        if vaults is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-08")
        if collection_count(vaults) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-08", "FAIL", {"vault_count": 0}, "No backup vaults found"
            )

        evidence = _bck_vault_lock_evidence(ctx, vaults)
        if evidence["locked_count"] == evidence["vault_count"]:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-08",
                "PASS",
                evidence,
                "Vault Lock is enabled on all backup vaults",
            )
        if evidence["locked_count"] > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-08",
                "PARTIAL",
                evidence,
                "Vault Lock is enabled on some but not all backup vaults",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-08",
            "FAIL",
            evidence,
            "No backup vault has Vault Lock enabled",
        )

    checks["BCK-08"] = bck08

    def bck09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        vaults = _bck_backup_vaults(ctx)
        if vaults is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-09")
        if collection_count(vaults) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-09", "FAIL", {"vault_count": 0}, "No backup vaults found"
            )

        evidence = _bck_vault_deletion_evidence(ctx, vaults)
        scp_evidence = _bck_scp_delete_recovery_point_evidence(ctx)
        delete_alert_rules: list[str] = []
        rules_data = ctx.invoke_aws_cli(["events", "list-rules"])
        if rules_data and has_property(rules_data, "Rules"):
            for rule in cli_array(property_value(rules_data, ["Rules"])):
                if not isinstance(rule, dict):
                    continue
                rule_name = str(property_value(rule, ["Name"]) or "")
                event_pattern = str(property_value(rule, ["EventPattern"]) or "")
                if re.search(r"DeleteRecoveryPoint", event_pattern, re.IGNORECASE):
                    delete_alert_rules.append(rule_name)

        combined_evidence = {
            "vault_policies": evidence,
            "scp_delete_deny": scp_evidence,
            "delete_alert_rules": list(delete_alert_rules),
        }
        vault_ok = evidence["failing_vaults"] == 0
        scp_ok = scp_evidence is not None and scp_evidence["scp_count_with_delete_deny"] > 0
        alert_ok = collection_count(delete_alert_rules) > 0

        if vault_ok and (scp_ok or alert_ok):
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-09",
                "PASS",
                combined_evidence,
                "Backup deletion is restricted and SCP or alerting on deletion is present",
            )
        if vault_ok:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-09",
                "PARTIAL",
                combined_evidence,
                "Vault deletion is restricted but SCP/alerting on DeleteRecoveryPoint not evidenced",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-09",
            "FAIL",
            combined_evidence,
            "Missing vault policy or unrestricted backup deletion allowed",
        )

    checks["BCK-09"] = bck09

    def bck10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["backup", "list-copy-jobs", "--by-state", "COMPLETED", "--max-results", "100"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-10")

        copy_jobs: list[dict[str, Any]] = []
        cross_region_count = 0
        if has_property(data, "CopyJobs"):
            for job in cli_array(data.get("CopyJobs")):
                destination_arn = str(property_value(job, ["DestinationBackupVaultArn"]) or "")
                destination_region: str | None = None
                match = re.search(r"arn:aws:backup:([^:]+):", destination_arn)
                if match:
                    destination_region = match.group(1)
                is_cross_region = bool(destination_region and destination_region != region)
                if is_cross_region:
                    cross_region_count += 1
                copy_jobs.append(
                    {
                        "job_id": str(property_value(job, ["CopyJobId"]) or ""),
                        "destination_arn": destination_arn,
                        "destination_region": destination_region,
                        "cross_region": is_cross_region,
                    }
                )

        evidence = {
            "copy_job_count": collection_count(copy_jobs),
            "cross_region_count": cross_region_count,
            "copy_jobs": copy_jobs,
        }
        if cross_region_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-10",
                "PASS",
                evidence,
                "Cross-region backup copies detected",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-10",
            "FAIL",
            evidence,
            "No completed cross-region backup copies found",
        )

    checks["BCK-10"] = bck10

    def bck11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        vaults = _bck_backup_vaults(ctx)
        if vaults is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-11")

        vault_evidence: list[dict[str, Any]] = []
        cross_account_vault_count = 0
        for vault in vaults or []:
            vault_arn = str(property_value(vault, ["BackupVaultArn"]) or "")
            vault_name = str(property_value(vault, ["BackupVaultName"]) or "")
            vault_account = _bck_account_id_from_arn(vault_arn)
            is_cross_account = bool(vault_account and vault_account != account_id)
            if is_cross_account:
                cross_account_vault_count += 1
            vault_evidence.append(
                {
                    "vault_name": vault_name,
                    "vault_arn": vault_arn,
                    "account_id": vault_account,
                    "cross_account": is_cross_account,
                }
            )

        copy_data = ctx.invoke_aws_cli(["backup", "list-copy-jobs", "--by-state", "COMPLETED", "--max-results", "100"])
        cross_account_copy_count = 0
        copy_jobs: list[dict[str, Any]] = []
        if copy_data and has_property(copy_data, "CopyJobs"):
            for job in cli_array(copy_data.get("CopyJobs")):
                destination_arn = str(property_value(job, ["DestinationBackupVaultArn"]) or "")
                destination_account = _bck_account_id_from_arn(destination_arn)
                is_cross_account = bool(destination_account and destination_account != account_id)
                if is_cross_account:
                    cross_account_copy_count += 1
                copy_jobs.append(
                    {
                        "job_id": str(property_value(job, ["CopyJobId"]) or ""),
                        "destination_arn": destination_arn,
                        "destination_account": destination_account,
                        "cross_account": is_cross_account,
                    }
                )

        evidence = {
            "vault_count": collection_count(vaults or []),
            "cross_account_vault_count": cross_account_vault_count,
            "cross_account_copy_count": cross_account_copy_count,
            "vaults": vault_evidence,
            "copy_jobs": copy_jobs,
        }

        if cross_account_vault_count > 0 or cross_account_copy_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-11",
                "PASS",
                evidence,
                "Cross-account backup copies or vaults detected",
            )
        if collection_count(vaults or []) == 0 and collection_count(copy_jobs) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-11",
                "FAIL",
                evidence,
                "No backup vaults or copy jobs found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-11",
            "FAIL",
            evidence,
            "No cross-account backup copies found",
        )

    checks["BCK-11"] = bck11

    checks["BCK-12"] = workshop(
        "BCK-12",
        "Verify restoration tests are performed periodically. Check frequency, scope, success rate and corrective actions.",
    )
    checks["BCK-13"] = workshop(
        "BCK-13",
        "Verify IAM and SSO component restoration is covered. Check procedures, dependencies and adapted tests.",
    )
    checks["BCK-14"] = workshop(
        "BCK-14",
        "Verify cloud DR scenarios are defined and tested: region loss, compromised account, ransomware, security tooling loss.",
    )
    checks["BCK-15"] = workshop(
        "BCK-15",
        "Verify RTO/RPO are formally documented, RSSI-approved, and aligned with platform mechanisms.",
    )
    checks["BCK-16"] = workshop(
        "BCK-16",
        "Verify failover mechanisms are documented and tested. Confirm scope and any derogations are RSSI-approved.",
    )

    def bck17(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        evidence = _bck_backup_alerting_evidence(ctx)
        has_alerting = (
            collection_count(evidence["matching_rule_names"]) > 0
            or collection_count(evidence["matching_alarm_names"]) > 0
        )
        if has_alerting:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-17",
                "PASS",
                evidence,
                "Backup failure alerting rules or alarms are configured",
            )
        if evidence["recent_failed_job_count"] > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-17",
                "FAIL",
                evidence,
                "Recent failed backup jobs found without matching alerting rules or alarms",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-17",
            "PARTIAL",
            evidence,
            "No backup alerting rules found; verify escalation path and SLA tracking manually",
        )

    checks["BCK-17"] = bck17

    checks["BCK-18"] = workshop(
        "BCK-18",
        "Verify PRA access roles are dedicated, approved, logged and reviewed post-usage.",
    )
    checks["BCK-19"] = workshop(
        "BCK-19",
        "Verify PRA and PCA documentation is maintained with post-change updates, versioning and owners.",
    )
    checks["BCK-20"] = workshop(
        "BCK-20",
        "Verify PRA evidence is exportable for audit: configuration exports, test procedures and restoration reports.",
    )

    if len(checks) != 20:
        raise RuntimeError(f"get_domain expected 20 BCK controls but defined {len(checks)}")

    return DomainModule(code="BCK", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
