"""Anonymize audit output for AI sharing — Python port of Protect-AuditOutput.ps1.

Masks 12-digit AWS account IDs (names preserved), ARNs, and resource identifiers.
Optional filters limit which account folders and domain artifacts are copied.

CLI: ``python protect_audit_output.py`` — see ``--help`` or README "Anonymize output".
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VALID_DOMAINS = frozenset(
    {"LOG", "IAM", "DET", "DAT", "GOV", "ORG", "NET", "CIC", "BCK", "INC", "WRK"}
)

ACCOUNT_FOLDER_RE = re.compile(r"^(.+)_(\d{12})$")
DOMAIN_FILE_RE = re.compile(
    r"^(?:AuditDiagnostics_)?([A-Z]{3})_\d{8}-\d{4}(?:_evidence)?\.(?:json|log)$",
    re.IGNORECASE,
)
DOMAIN_REPORT_RE = re.compile(r"^AuditReport_([A-Z]{3})_\d{8}-\d{4}\.html$", re.IGNORECASE)


@dataclass
class AccountFilter:
    name: str | None = None
    account_id: str | None = None


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


def parse_filter_tokens(value: str | None) -> list[str]:
    if not value:
        return []
    tokens: list[str] = []
    for part in value.replace(";", ",").split(","):
        token = part.strip()
        if token:
            tokens.append(token)
    return tokens


def normalize_domain_filters(domains: list[str] | None) -> set[str] | None:
    if not domains:
        return None
    normalized = {domain.strip().upper() for domain in domains if domain.strip()}
    unknown = sorted(domain for domain in normalized if domain not in VALID_DOMAINS)
    if unknown:
        raise ValueError(
            f"Unknown domain(s): {', '.join(unknown)}. "
            f"Valid domains: {', '.join(sorted(VALID_DOMAINS))}"
        )
    return normalized or None


def resolve_account_filters(tokens: list[str], config_path: Path) -> list[AccountFilter]:
    if not tokens:
        return []

    by_name: dict[str, tuple[str, str]] = {}
    by_id: dict[str, tuple[str, str]] = {}
    if config_path.is_file():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        for account in config.get("accounts", []):
            name = str(account.get("name", ""))
            account_id = str(account.get("id", ""))
            if name:
                by_name[name.lower()] = (name, account_id)
            if account_id:
                by_id[account_id] = (name, account_id)

    filters: list[AccountFilter] = []
    for token in tokens:
        if re.fullmatch(r"\d{12}", token):
            if token in by_id:
                name, account_id = by_id[token]
                filters.append(AccountFilter(name=name, account_id=account_id))
            else:
                filters.append(AccountFilter(account_id=token))
            continue

        if token.lower() in by_name:
            name, account_id = by_name[token.lower()]
            filters.append(AccountFilter(name=name, account_id=account_id))
        else:
            filters.append(AccountFilter(name=token))
    return filters


def _domain_from_basename(filename: str) -> str | None:
    report_match = DOMAIN_REPORT_RE.match(filename)
    if report_match:
        return report_match.group(1).upper()
    file_match = DOMAIN_FILE_RE.match(filename)
    if file_match:
        return file_match.group(1).upper()
    return None


def _parse_account_folder(folder_name: str) -> tuple[str, str] | None:
    match = ACCOUNT_FOLDER_RE.match(folder_name)
    if not match:
        return None
    return match.group(1), match.group(2)


def _account_folder_matches(folder_name: str, account_filters: list[AccountFilter]) -> bool:
    parsed = _parse_account_folder(folder_name)
    if not parsed:
        return False
    folder_name_value, folder_id = parsed
    for account_filter in account_filters:
        name_ok = (
            account_filter.name is None
            or account_filter.name.lower() == folder_name_value.lower()
        )
        id_ok = account_filter.account_id is None or account_filter.account_id == folder_id
        if name_ok and id_ok:
            return True
    return False


def should_include_file(
    relative_path: str,
    account_filters: list[AccountFilter] | None,
    domain_filters: set[str] | None,
) -> bool:
    relative = relative_path.replace("\\", "/")
    if relative.startswith("anonymized/") or relative == "anonymized":
        return False

    parts = relative.split("/")
    if not parts:
        return False

    basename = parts[-1]

    if len(parts) == 1 and basename.startswith("AuditReport_"):
        domain = _domain_from_basename(basename)
        if domain_filters is None:
            return account_filters is None
        return domain is not None and domain in domain_filters

    if parts[0] == "log":
        return account_filters is None and domain_filters is None

    if not ACCOUNT_FOLDER_RE.match(parts[0]):
        return False

    if account_filters is not None and not _account_folder_matches(parts[0], account_filters):
        return False

    if domain_filters is None:
        return True

    domain = _domain_from_basename(basename)
    return domain is not None and domain in domain_filters


def default_output_path(
    input_path: Path,
    account_filters: list[AccountFilter] | None,
    domain_filters: set[str] | None,
) -> Path:
    if not account_filters and not domain_filters:
        return input_path / "anonymized"

    suffix_parts: list[str] = []
    if account_filters:
        account_labels = sorted(
            {
                (account_filter.name or account_filter.account_id or "account")
                for account_filter in account_filters
            }
        )
        suffix_parts.append("acct-" + "-".join(account_labels))
    if domain_filters:
        suffix_parts.append("dom-" + "-".join(sorted(domain_filters)))
    return input_path / "anonymized" / "-".join(suffix_parts)


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


def write_mapping_file(
    path: Path,
    config_path: Path,
    state: AnonymizationState,
    account_filters: list[AccountFilter] | None = None,
) -> None:
    export: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "warning": "INTERNAL ONLY - maps masked account IDs back to real IDs. Account names are not masked in output.",
        "accounts": [],
    }

    def _include_account(account_name: str, account_id: str) -> bool:
        if not account_filters:
            return True
        return _account_folder_matches(f"{account_name}_{account_id}", account_filters)

    if config_path.is_file():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        for account in config.get("accounts", []):
            account_id = str(account.get("id", ""))
            account_name = str(account.get("name", ""))
            if not _include_account(account_name, account_id):
                continue
            export["accounts"].append(
                {
                    "account_name": account_name,
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
    output_path: Path | None,
    config_file: Path,
    mapping_file: Path,
    force: bool = False,
    accounts: list[str] | None = None,
    domains: list[str] | None = None,
) -> int:
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input path not found: {input_path}")

    account_filters = resolve_account_filters(accounts or [], config_file) or None
    domain_filters = normalize_domain_filters(domains)
    resolved_output = output_path or default_output_path(input_path, account_filters, domain_filters)

    if resolved_output.exists() and not force:
        raise FileExistsError(
            f"Output path already exists: {resolved_output}. Use --force to overwrite."
        )
    if resolved_output.exists():
        shutil.rmtree(resolved_output)

    state = initialize_map(input_path, config_file)
    input_root = input_path.resolve()
    processed = 0
    skipped = 0

    for file_path in input_root.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in {".json", ".log", ".txt", ".html"}:
            continue
        if file_path.name.startswith("anonymization-map"):
            continue

        relative = str(file_path.relative_to(input_root))
        if not should_include_file(relative, account_filters, domain_filters):
            skipped += 1
            continue

        target_relative = anonymized_relative_path(relative, state)
        target_path = resolved_output / target_relative
        target_path.parent.mkdir(parents=True, exist_ok=True)
        raw = file_path.read_text(encoding="utf-8")
        target_path.write_text(protect_audit_text(raw, state), encoding="utf-8")
        processed += 1

    if processed == 0:
        raise FileNotFoundError(
            "No files matched the selected account/domain filters. "
            "Check folder names ({AccountName}_{AccountId}) and scan artifacts."
        )

    write_mapping_file(mapping_file, config_file, state, account_filters)
    print("====================================")
    print("Audit output anonymized")
    print(f"Source      : {input_root}")
    print(f"Destination : {resolved_output}")
    if account_filters:
        labels = [
            account_filter.name or account_filter.account_id or "?"
            for account_filter in account_filters
        ]
        print(f"Accounts    : {', '.join(labels)}")
    else:
        print("Accounts    : all")
    if domain_filters:
        print(f"Domains     : {', '.join(sorted(domain_filters))}")
    else:
        print("Domains     : all")
    print(f"Files       : {processed}")
    print(f"Skipped     : {skipped}")
    print(f"Mapped IDs  : {len(state.account_id_to_pseudonym)}")
    print(f"Mapping     : {mapping_file}")
    print("")
    print("Share only the anonymized folder with the AI evaluator.")
    print("Keep the mapping file internal - it reverses masked account IDs.")
    print("====================================")
    return processed
