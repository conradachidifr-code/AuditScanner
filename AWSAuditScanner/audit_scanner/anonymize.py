"""Anonymize audit output for AI sharing — Python port of Protect-AuditOutput.ps1."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class AnonymizationState:
    account_id_to_pseudonym: dict[str, str] = field(default_factory=dict)
    role_arn_to_pseudonym: dict[str, str] = field(default_factory=dict)
    resource_counters: dict[str, int] = field(default_factory=dict)
    next_account_index: int = 1


def _resource_pseudonym(state: AnonymizationState, prefix: str) -> str:
    state.resource_counters[prefix] = state.resource_counters.get(prefix, 0) + 1
    return f"{prefix}-{state.resource_counters[prefix]:04d}"


def _add_account(state: AnonymizationState, account_id: str, role_arn: str | None = None) -> None:
    if not account_id:
        return
    if account_id not in state.account_id_to_pseudonym:
        pseudonym = f"ACCT-{state.next_account_index:03d}"
        state.next_account_index += 1
        state.account_id_to_pseudonym[account_id] = pseudonym
    if role_arn:
        state.role_arn_to_pseudonym[role_arn] = "[REDACTED-ROLE-ARN]"


def initialize_map(source_path: Path, config_path: Path) -> AnonymizationState:
    state = AnonymizationState()
    if config_path.is_file():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        default_role = config.get("default_role_path")
        if default_role:
            state.role_arn_to_pseudonym[str(default_role)] = "[REDACTED-ROLE-ARN]"
        for account in config.get("accounts", []):
            role_arn = account.get("role_arn")
            _add_account(state, str(account.get("id", "")), str(role_arn) if role_arn else None)

    folder_pattern = re.compile(r"^(.+)_(\d{12})$")
    if source_path.is_dir():
        for child in source_path.iterdir():
            if child.is_dir():
                match = folder_pattern.match(child.name)
                if match:
                    _add_account(state, match.group(2))
    return state


def _hyphenated_prefixes() -> list[str]:
    return sorted(
        [
            "tgw-attach", "vpce-svc", "cvpn-endpoint", "ipam-pool", "ipam-scope",
            "vpn-connection", "replicationgroup", "cache-cluster", "eipalloc", "ipalloc",
            "customer-gateway", "fsmt", "fsap", "snap", "subnet", "vpce", "pcx", "rtb",
            "acl", "eni", "vol", "ami", "vpc", "tgw", "igw", "eigw", "nat", "vgw", "vpn",
            "cgw", "dopt", "dhcp", "pl", "lgw", "lpg", "fle", "fl", "sg", "sgr", "sgp",
            "gp", "db", "fs", "esm", "elb", "arn", "cb", "cr", "ls", "ni", "net", "efa", "i",
        ],
        key=len,
        reverse=True,
    )


def _protect_prefixed_ids(text: str, state: AnonymizationState) -> str:
    result = text
    for prefix in _hyphenated_prefixes():
        pattern = re.compile(rf"\b{re.escape(prefix)}-[0-9a-f]{{8,32}}\b")
        while pattern.search(result):
            replacement = _resource_pseudonym(state, prefix)
            result = pattern.sub(replacement, result, count=1)
    return result


def _protect_generic_ids(text: str, state: AnonymizationState) -> str:
    pattern = re.compile(
        r"\b(?!(?:eu|us|ap|sa|ca|me|af|cn|il|mx)-)([a-z][a-z0-9]{1,22})-([0-9a-f]{8,32})\b"
    )
    result = text
    for _ in range(5000):
        match = pattern.search(result)
        if not match:
            break
        prefix = match.group(1)
        if prefix in {"account", "acct", "profile", "redacted", "log", "kms", "hostedzone"} or prefix.isdigit():
            result = pattern.sub("[REDACTED-AWS-ID]", result, count=1)
        else:
            result = pattern.sub(_resource_pseudonym(state, prefix), result, count=1)
    return result


def _replace_fields(text: str, replacements: list[tuple[str, str]]) -> str:
    result = text
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result)
    return result


def protect_audit_text(text: str, state: AnonymizationState) -> str:
    if not text:
        return text

    result = text
    for role_arn, pseudonym in state.role_arn_to_pseudonym.items():
        if role_arn:
            result = result.replace(role_arn, pseudonym)

    for account_id in sorted(state.account_id_to_pseudonym):
        result = result.replace(account_id, state.account_id_to_pseudonym[account_id])

    result = re.sub(r"\b\d{12}\b", "[REDACTED-ACCOUNT-ID]", result)
    result = re.sub(r"arn:aws(?:-[a-z]+)?:[a-z0-9-]+:[a-z0-9-]*:\d{12}:.+", "[REDACTED-ARN]", result)
    result = re.sub(r"arn:aws:iam::\d{12}:role/.+", "[REDACTED-ROLE-ARN]", result)
    result = re.sub(r"Auditor\s*:\s*.+$", "Auditor   : [REDACTED]", result, flags=re.MULTILINE)
    result = re.sub(r'"auditor"\s*:\s*"[^"]*"', '"auditor": "[REDACTED]"', result)
    result = re.sub(r'"sso_profile"\s*:\s*"[^"]*"', '"sso_profile": "[REDACTED]"', result)
    result = re.sub(r'"role_arn"\s*:\s*"[^"]*"', '"role_arn": "[REDACTED]"', result)
    result = re.sub(r"C:\\Users\\[^\\\"\s]+", r"C:\Users\[REDACTED]", result)
    result = re.sub(r"/Users/[^/\"\s]+", "/Users/[REDACTED]", result)
    result = re.sub(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED-EMAIL]", result)

    result = _protect_prefixed_ids(result, state)

    log_path = re.compile(r"/aws/[a-zA-Z0-9_./-]+")
    while log_path.search(result):
        result = log_path.sub(_resource_pseudonym(state, "log-group"), result, count=1)

    result = _replace_fields(
        result,
        [
            (r'"flow_log_id"\s*:\s*"[^"]*"', '"flow_log_id": "[REDACTED-LOG-ID]"'),
            (r'"FlowLogId"\s*:\s*"[^"]*"', '"FlowLogId": "[REDACTED-LOG-ID]"'),
            (r'"log_group"\s*:\s*"[^"]*"', '"log_group": "[REDACTED-LOG-ID]"'),
            (r'"LogGroupName"\s*:\s*"[^"]*"', '"LogGroupName": "[REDACTED-LOG-ID]"'),
            (r'"TrailARN"\s*:\s*"[^"]*"', '"TrailARN": "[REDACTED-LOG-ARN]"'),
            (r'"id"\s*:\s*"fl-[0-9a-f]+"', '"id": "[REDACTED-FLOW-LOG-ID]"'),
        ],
    )

    uuid_pattern = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
    while uuid_pattern.search(result):
        result = uuid_pattern.sub(_resource_pseudonym(state, "kms-key"), result, count=1)

    result = re.sub(
        r"\bmrk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "[REDACTED-MRK-KEY]",
        result,
    )
    alias_pattern = re.compile(r"alias/[a-zA-Z0-9/_-]+")
    while alias_pattern.search(result):
        result = alias_pattern.sub(f"alias/{_resource_pseudonym(state, 'kms-alias')}", result, count=1)

    result = _replace_fields(
        result,
        [
            (r'"key_id"\s*:\s*"[^"]*"', '"key_id": "[REDACTED-KMS-KEY]"'),
            (r'"KeyArn"\s*:\s*"[^"]*"', '"KeyArn": "[REDACTED-KMS-ARN]"'),
            (r"arn:aws:kms:[a-z0-9-]+:[^:]+:key/[0-9a-f-]+", "[REDACTED-KMS-ARN]"),
            (r"s3://[a-z0-9.\-_]+", "s3://[REDACTED-BUCKET]"),
            (r'"bucket"\s*:\s*"[^"]*"', '"bucket": "[REDACTED-BUCKET]"'),
            (r'"BucketName"\s*:\s*"[^"]*"', '"BucketName": "[REDACTED-BUCKET]"'),
            (r'"table_name"\s*:\s*"[^"]*"', '"table_name": "[REDACTED-TABLE]"'),
            (r'"SecretId"\s*:\s*"[^"]*"', '"SecretId": "[REDACTED-SECRET]"'),
            (r'"ParameterName"\s*:\s*"[^"]*"', '"ParameterName": "[REDACTED-PARAMETER]"'),
        ],
    )

    hosted_zone = re.compile(r"\bZ[0-9A-Z]{10,32}\b")
    while hosted_zone.search(result):
        result = hosted_zone.sub(_resource_pseudonym(state, "hostedzone"), result, count=1)

    result = _protect_generic_ids(result, state)
    result = re.sub(
        r"\b(?!(?:0\.0\.0\.0|255\.255\.255\.255)\b)(?:\d{1,3}\.){3}\d{1,3}\b",
        "[REDACTED-IP]",
        result,
    )
    result = re.sub(r"\bAWSReservedSSO_[A-Za-z0-9_-]+\b", "[REDACTED-SSO-ROLE]", result)
    result = re.sub(
        r"aws-reserved/sso\.amazonaws\.com/[a-z0-9-]+/AWSReservedSSO_[A-Za-z0-9_]+",
        "[REDACTED-SSO-PATH]",
        result,
    )
    return result


def anonymized_relative_path(relative_path: str, state: AnonymizationState) -> str:
    parts = re.split(r"[\\/]", relative_path)
    mapped: list[str] = []
    folder_pattern = re.compile(r"^(.+)_(\d{12})$")
    for segment in parts:
        match = folder_pattern.match(segment)
        if match:
            account_name = match.group(1)
            account_id = match.group(2)
            id_pseudonym = state.account_id_to_pseudonym.get(account_id, "[REDACTED-ACCOUNT-ID]")
            mapped.append(f"{account_name}_{id_pseudonym}")
        else:
            mapped.append(protect_audit_text(segment, state))
    return str(Path(*mapped)) if mapped else relative_path


def write_mapping_file(path: Path, config_path: Path, state: AnonymizationState) -> None:
    export: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "warning": "INTERNAL ONLY - maps masked account IDs back to real IDs. Account names are not masked in output.",
        "accounts": [],
    }
    if config_path.is_file():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        for account in config.get("accounts", []):
            account_id = str(account.get("id", ""))
            export["accounts"].append(
                {
                    "account_name": str(account.get("name", "")),
                    "masked_account_id": state.account_id_to_pseudonym.get(account_id, ""),
                    "real_account_id": account_id,
                }
            )
    else:
        for account_id in sorted(state.account_id_to_pseudonym):
            export["accounts"].append(
                {
                    "account_name": "",
                    "masked_account_id": state.account_id_to_pseudonym[account_id],
                    "real_account_id": account_id,
                }
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(export, indent=2, ensure_ascii=False), encoding="utf-8")


def run_anonymization(
    input_path: Path,
    output_path: Path,
    config_file: Path,
    mapping_file: Path,
    force: bool = False,
) -> int:
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input path not found: {input_path}")
    if output_path.exists() and not force:
        raise FileExistsError(f"Output path already exists: {output_path}. Use --force to overwrite.")
    if output_path.exists():
        shutil.rmtree(output_path)

    state = initialize_map(input_path, config_file)
    input_root = input_path.resolve()
    processed = 0

    for file_path in input_root.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in {".json", ".log", ".txt"}:
            continue
        if file_path.name.startswith("anonymization-map"):
            continue
        relative = str(file_path.relative_to(input_root))
        if relative.startswith("anonymized"):
            continue
        target_relative = anonymized_relative_path(relative, state)
        target_path = output_path / target_relative
        target_path.parent.mkdir(parents=True, exist_ok=True)
        raw = file_path.read_text(encoding="utf-8")
        target_path.write_text(protect_audit_text(raw, state), encoding="utf-8")
        processed += 1

    write_mapping_file(mapping_file, config_file, state)
    print("====================================")
    print("Audit output anonymized")
    print(f"Source      : {input_root}")
    print(f"Destination : {output_path}")
    print(f"Files       : {processed}")
    print(f"Accounts    : {len(state.account_id_to_pseudonym)}")
    print(f"Mapping     : {mapping_file}")
    print("")
    print("Share only the anonymized folder with the AI evaluator.")
    print("Keep the mapping file internal - it reverses masked account IDs.")
    print("====================================")
    return processed
