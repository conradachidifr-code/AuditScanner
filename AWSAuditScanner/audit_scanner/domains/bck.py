"""BCK domain - backup and recovery controls."""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property, property_value
from audit_scanner.results import AuditResult

SEVERITY = {f"BCK-{index:02d}": "P1" for index in range(1, 21)}


def _bck_backup_plans(ctx: CheckContext, region: str) -> list[dict[str, Any]] | None:
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


def _bck_backup_plan_details(ctx: CheckContext, backup_plan_id: str) -> dict[str, Any] | None:
    return ctx.invoke_aws_cli(["backup", "get-backup-plan", "--backup-plan-id", backup_plan_id])


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
            if re.search(r":ec2:", resource_text, re.IGNORECASE) and "EC2" not in resource_types:
                resource_types.append("EC2")
            if re.search(r":rds:", resource_text, re.IGNORECASE) and "RDS" not in resource_types:
                resource_types.append("RDS")
            if re.search(r":elasticfilesystem:", resource_text, re.IGNORECASE) and "EFS" not in resource_types:
                resource_types.append("EFS")
            if re.search(r":dynamodb:", resource_text, re.IGNORECASE) and "DynamoDB" not in resource_types:
                resource_types.append("DynamoDB")

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


def _bck_bucket_name_critical(bucket_name: str) -> bool:
    return bool(re.search(r"log|backup|critical", bucket_name.lower()))


def _bck_s3_bucket_names(ctx: CheckContext, region: str) -> list[str] | None:
    data = ctx.invoke_aws_cli(["s3api", "list-buckets"])
    if data is None:
        return None

    bucket_names: list[str] = []
    if has_property(data, "Buckets"):
        for bucket in cli_array(data.get("Buckets")):
            if has_property(bucket, "Name"):
                bucket_names.append(str(property_value(bucket, ["Name"]) or ""))
    return bucket_names


def _bck_account_id_from_arn(arn: str) -> str | None:
    match = re.search(r"arn:aws:[^:]*:[^:]*:(\d{12}):", arn)
    if match:
        return match.group(1)
    return None


def get_domain() -> DomainModule:
    checks: OrderedDict[str, object] = OrderedDict()

    def workshop(cid: str, notes: str):
        def _check(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
            return ctx.results.workshop_control(account_id, account_name, region, cid, notes)

        return _check

    checks["BCK-01"] = workshop("BCK-01", "Verify backup policy document exists and is RSSI-approved.")

    def bck02(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        plans = _bck_backup_plans(ctx, region)
        if plans is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-02")
        if collection_count(plans) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-02", "FAIL", {"plan_count": 0}, "No backup plans found"
            )

        plan_evidence: list[dict[str, Any]] = []
        covered_types: list[str] = []
        for plan in plans:
            plan_id = str(property_value(plan, ["BackupPlanId"]) or "")
            plan_name = str(property_value(plan, ["BackupPlanName"]) or "")
            types = _bck_selection_resource_types(ctx, plan_id)

            for resource_type in types:
                if resource_type not in covered_types:
                    covered_types.append(resource_type)

            plan_evidence.append(
                {"plan_id": plan_id, "plan_name": plan_name, "resource_types": list(types)}
            )

        evidence = {
            "plan_count": collection_count(plans),
            "plans": plan_evidence,
            "covered_types": covered_types,
        }
        has_ec2 = "EC2" in covered_types or "TAGGED" in covered_types
        has_rds = "RDS" in covered_types or "TAGGED" in covered_types
        has_efs = "EFS" in covered_types or "TAGGED" in covered_types
        has_dynamo = "DynamoDB" in covered_types or "TAGGED" in covered_types

        if has_ec2 and has_rds and has_efs and has_dynamo:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-02",
                "PASS",
                evidence,
                "Backup plans cover EC2, RDS, EFS, and DynamoDB",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-02",
            "PARTIAL",
            evidence,
            "Backup plans exist but not all required resource types are explicitly covered",
        )

    checks["BCK-02"] = bck02

    def bck03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        plans = _bck_backup_plans(ctx, region)
        if plans is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-03")
        if collection_count(plans) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-03", "FAIL", {"plan_count": 0}, "No backup plans found"
            )

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

        evidence = {
            "schedule_count": collection_count(schedules),
            "infrequent_count": infrequent_count,
            "schedules": schedules,
        }
        if collection_count(schedules) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-03", "FAIL", evidence, "No backup rules found"
            )
        if infrequent_count == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-03",
                "PASS",
                evidence,
                "Backup schedules are daily or more frequent",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-03",
            "FAIL",
            evidence,
            "One or more backup schedules are weekly or less frequent",
        )

    checks["BCK-03"] = bck03

    def bck04(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["backup", "list-backup-vaults"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-04")

        vaults = cli_array(data.get("BackupVaultList")) if has_property(data, "BackupVaultList") else []
        if collection_count(vaults) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-04", "FAIL", {"vault_count": 0}, "No backup vaults found"
            )

        vault_evidence: list[dict[str, Any]] = []
        cross_account_count = 0
        for vault in vaults:
            vault_arn = str(property_value(vault, ["BackupVaultArn"]) or "")
            vault_account = _bck_account_id_from_arn(vault_arn)
            is_cross_account = bool(vault_account and vault_account != account_id)
            if is_cross_account:
                cross_account_count += 1
            vault_evidence.append(
                {
                    "vault_name": str(property_value(vault, ["BackupVaultName"]) or ""),
                    "vault_arn": vault_arn,
                    "account_id": vault_account,
                }
            )

        evidence = {
            "vault_count": collection_count(vaults),
            "cross_account_count": cross_account_count,
            "vaults": vault_evidence,
        }
        if cross_account_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-04",
                "PASS",
                evidence,
                "Backup vault in isolated account detected",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-04",
            "FAIL",
            evidence,
            "Backup vaults only exist in the current account",
        )

    checks["BCK-04"] = bck04

    def bck05(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        list_data = ctx.invoke_aws_cli(["backup", "list-backup-vaults"])
        if list_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-05")

        vaults = cli_array(list_data.get("BackupVaultList")) if has_property(list_data, "BackupVaultList") else []
        if collection_count(vaults) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-05", "FAIL", {"vault_count": 0}, "No backup vaults found"
            )

        vault_evidence: list[dict[str, Any]] = []
        failing_vaults = 0
        for vault in vaults:
            vault_name = str(property_value(vault, ["BackupVaultName"]) or "")
            detail_data = ctx.invoke_aws_cli(
                ["backup", "describe-backup-vault", "--backup-vault-name", vault_name]
            )
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

        evidence = {
            "vault_count": collection_count(vaults),
            "vaults": vault_evidence,
            "failing_vaults": failing_vaults,
        }
        if failing_vaults == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-05",
                "PASS",
                evidence,
                "All backup vaults encrypted with CMK",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-05",
            "FAIL",
            evidence,
            "One or more backup vaults lack CMK encryption",
        )

    checks["BCK-05"] = bck05

    def bck06(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        list_data = ctx.invoke_aws_cli(["backup", "list-backup-vaults"])
        if list_data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-06")

        vaults = cli_array(list_data.get("BackupVaultList")) if has_property(list_data, "BackupVaultList") else []
        if collection_count(vaults) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-06", "FAIL", {"vault_count": 0}, "No backup vaults found"
            )

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

        evidence = {
            "vault_count": collection_count(vaults),
            "vaults": vault_evidence,
            "failing_vaults": failing_vaults,
        }
        if failing_vaults == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-06",
                "PASS",
                evidence,
                "Vault access policies restrict recovery point deletion",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-06",
            "FAIL",
            evidence,
            "Missing vault policy or unrestricted deletion allowed",
        )

    checks["BCK-06"] = bck06

    def bck07(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(
            ["backup", "list-copy-jobs", "--by-state", "COMPLETED", "--max-results", "100"]
        )
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-07")

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
                "BCK-07",
                "PASS",
                evidence,
                "Cross-region backup copies detected",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-07",
            "FAIL",
            evidence,
            "No completed cross-region backup copies found",
        )

    checks["BCK-07"] = bck07

    def bck08(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["rds", "describe-db-instances"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-08")

        instances = cli_array(data.get("DBInstances")) if has_property(data, "DBInstances") else []
        if collection_count(instances) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-08",
                "PARTIAL",
                {"instance_count": 0},
                "No RDS instances found in region",
            )

        failing_instances: list[str] = []
        instance_evidence: list[dict[str, Any]] = []
        for instance in instances:
            retention = int(property_value(instance, ["BackupRetentionPeriod"]) or 0)
            instance_id = str(property_value(instance, ["DBInstanceIdentifier"]) or "")
            instance_evidence.append({"instance_id": instance_id, "retention": retention})
            if retention < 7 and collection_count(failing_instances) < 10:
                failing_instances.append(instance_id)

        evidence = {
            "instance_count": collection_count(instances),
            "instances": instance_evidence,
            "failing_instances": failing_instances,
        }
        if collection_count(failing_instances) > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-08",
                "FAIL",
                evidence,
                "One or more RDS instances have BackupRetentionPeriod below 7 days",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-08",
            "PASS",
            evidence,
            "All RDS instances have automated backups retained for at least 7 days",
        )

    checks["BCK-08"] = bck08

    def bck09(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        bucket_names = _bck_s3_bucket_names(ctx, region)
        if bucket_names is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-09")

        critical_buckets = [bucket_name for bucket_name in bucket_names if _bck_bucket_name_critical(bucket_name)]
        if collection_count(critical_buckets) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-09",
                "PARTIAL",
                {
                    "bucket_count": collection_count(bucket_names),
                    "critical_bucket_count": 0,
                },
                "No critical buckets identified by naming convention (cross-reference DAT-17)",
            )

        versioning_enabled = 0
        versioning_disabled = 0
        bucket_evidence: list[dict[str, Any]] = []
        for bucket_name in critical_buckets:
            version_data = ctx.invoke_aws_cli(["s3api", "get-bucket-versioning", "--bucket", bucket_name])
            enabled = False
            if version_data and has_property(version_data, "Status"):
                enabled = str(property_value(version_data, ["Status"]) or "") == "Enabled"
            if enabled:
                versioning_enabled += 1
            else:
                versioning_disabled += 1
            if collection_count(bucket_evidence) < 10:
                bucket_evidence.append({"bucket_name": bucket_name, "versioning": enabled})

        evidence = {
            "critical_bucket_count": collection_count(critical_buckets),
            "versioning_enabled": versioning_enabled,
            "versioning_disabled": versioning_disabled,
            "buckets": bucket_evidence,
        }
        if versioning_disabled > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-09",
                "FAIL",
                evidence,
                "One or more critical buckets do not have versioning enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-09",
            "PASS",
            evidence,
            "Versioning enabled on critical buckets (aligned with DAT-17)",
        )

    checks["BCK-09"] = bck09

    def bck10(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        data = ctx.invoke_aws_cli(["efs", "describe-file-systems"])
        if data is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-10")

        file_systems = cli_array(data.get("FileSystems")) if has_property(data, "FileSystems") else []
        if collection_count(file_systems) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-10",
                "PARTIAL",
                {"efs_count": 0},
                "No EFS file systems found in region",
            )

        enabled_count = 0
        disabled_count = 0
        efs_evidence: list[dict[str, Any]] = []
        for file_system in file_systems:
            file_system_id = str(property_value(file_system, ["FileSystemId"]) or "")
            policy_data = ctx.invoke_aws_cli(
                ["efs", "describe-backup-policy", "--file-system-id", file_system_id]
            )
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

        evidence = {
            "efs_count": collection_count(file_systems),
            "enabled_count": enabled_count,
            "disabled_count": disabled_count,
            "file_systems": efs_evidence,
        }
        if disabled_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-10",
                "FAIL",
                evidence,
                "One or more EFS file systems do not have backup enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-10",
            "PASS",
            evidence,
            "EFS backup policy enabled on all file systems",
        )

    checks["BCK-10"] = bck10

    def bck11(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        table_names: list[str] = []
        exclusive_start: str | None = None
        while True:
            arguments = ["dynamodb", "list-tables"]
            if exclusive_start:
                arguments.extend(["--exclusive-start-table-name", exclusive_start])
            list_data = ctx.invoke_aws_cli(arguments)
            if list_data is None:
                return ctx.results.null_api_partial(account_id, account_name, region, "BCK-11")
            if has_property(list_data, "TableNames"):
                table_names.extend([str(name) for name in cli_array(list_data.get("TableNames"))])
            exclusive_start = None
            if has_property(list_data, "LastEvaluatedTableName"):
                token = str(property_value(list_data, ["LastEvaluatedTableName"]) or "").strip()
                if token:
                    exclusive_start = token
            if not exclusive_start:
                break

        if collection_count(table_names) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-11",
                "PARTIAL",
                {"table_count": 0},
                "No DynamoDB tables found in region",
            )

        enabled_count = 0
        disabled_count = 0
        table_evidence: list[dict[str, Any]] = []
        for table_name in table_names:
            backup_data = ctx.invoke_aws_cli(
                ["dynamodb", "describe-continuous-backups", "--table-name", table_name]
            )
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

        evidence = {
            "table_count": collection_count(table_names),
            "enabled_count": enabled_count,
            "disabled_count": disabled_count,
            "tables": table_evidence,
        }
        if disabled_count > 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-11",
                "FAIL",
                evidence,
                "One or more DynamoDB tables do not have PITR enabled",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-11",
            "PASS",
            evidence,
            "Point-in-time recovery enabled on all DynamoDB tables",
        )

    checks["BCK-11"] = bck11
    checks["BCK-12"] = workshop(
        "BCK-12", "Verify restoration test performed and documented. Check RFC results from 10/06."
    )
    checks["BCK-13"] = workshop(
        "BCK-13", "Verify restoration procedure exists in DEX or backup documentation."
    )

    def bck14(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        plans = _bck_backup_plans(ctx, region)
        if plans is None:
            return ctx.results.null_api_partial(account_id, account_name, region, "BCK-14")
        if collection_count(plans) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-14", "FAIL", {"plan_count": 0}, "No backup plans found"
            )

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

        evidence = {
            "rule_count": collection_count(rule_evidence),
            "failing_rules": failing_rules,
            "rules": rule_evidence,
        }
        if collection_count(rule_evidence) == 0:
            return ctx.results.audit_result(
                account_id, account_name, region, "BCK-14", "FAIL", evidence, "No backup retention rules found"
            )
        if failing_rules == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-14",
                "PASS",
                evidence,
                "All backup rules retain data for at least 30 days",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-14",
            "FAIL",
            evidence,
            "One or more backup rules have DeleteAfterDays below 30",
        )

    checks["BCK-14"] = bck14
    checks["BCK-15"] = workshop(
        "BCK-15", "Verify PCA in SIPedia was RSSI-approved. Check DIMA 4h / SLA 99.9%."
    )
    checks["BCK-16"] = workshop(
        "BCK-16", "Known: only firewall failover tested. RSSI derogation to confirm formally."
    )
    checks["BCK-17"] = workshop("BCK-17", "Known: DIMA 4h not tested in real conditions.")
    checks["BCK-18"] = workshop(
        "BCK-18", "Known: DR covers only crypto-locking and cyber-attack, not region loss."
    )
    checks["BCK-19"] = workshop("BCK-19", "Verify RSSI formally approved PCA and DR strategy.")

    def bck20(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
        resources: list[dict[str, Any]] = []
        token: str | None = None

        while True:
            arguments = ["backup", "list-protected-resources"]
            if token:
                arguments.extend(["--next-token", token])
            data = ctx.invoke_aws_cli(arguments)
            if data is None:
                return ctx.results.null_api_partial(account_id, account_name, region, "BCK-20")

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
            if resource_type not in type_counts:
                type_counts[resource_type] = 0
            type_counts[resource_type] += 1

        has_ec2 = "EC2" in type_counts or "EBS" in type_counts
        has_rds = "RDS" in type_counts or "Aurora" in type_counts
        has_efs = "EFS" in type_counts
        evidence = {
            "protected_resource_count": collection_count(resources),
            "resource_type_counts": type_counts,
        }
        if has_ec2 and has_rds and has_efs:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-20",
                "PASS",
                evidence,
                "Protected resources include EC2, RDS, and EFS",
            )
        if collection_count(resources) == 0:
            return ctx.results.audit_result(
                account_id,
                account_name,
                region,
                "BCK-20",
                "FAIL",
                evidence,
                "No protected backup resources found",
            )
        return ctx.results.audit_result(
            account_id,
            account_name,
            region,
            "BCK-20",
            "PARTIAL",
            evidence,
            "Backup coverage exists but not all socle critical resource types are protected",
        )

    checks["BCK-20"] = bck20

    return DomainModule(code="BCK", severity=SEVERITY, checks=checks)  # type: ignore[arg-type]
