"""Write scan JSON, evidence, and session logs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from audit_scanner.config import Account
from audit_scanner.results import AuditResult


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def account_output_paths(
    output_path: Path, account_name: str, account_id: str, domain: str, timestamp: str
) -> dict[str, Path]:
    account_folder = output_path / f"{account_name}_{account_id}"
    evidence_path = account_folder / "evidence"
    errors_path = account_folder / "errors"
    for folder in (account_folder, evidence_path, errors_path):
        folder.mkdir(parents=True, exist_ok=True)
    return {
        "account_folder": account_folder,
        "results_file": account_folder / f"{domain}_{timestamp}.json",
        "evidence_file": evidence_path / f"{domain}_{timestamp}_evidence.json",
        "diagnostic_file": errors_path / f"AuditDiagnostics_{domain}_{timestamp}.log",
    }


def write_results_file(
    path: Path,
    account: Account,
    domain: str,
    timestamp: str,
    auditor: str,
    results: list[AuditResult],
) -> Path:
    payload = {
        "metadata": {
            "account_id": account.id,
            "account_name": account.name,
            "domain": domain,
            "auditor": auditor,
            "timestamp": timestamp,
            "role_arn": account.role_arn,
            "regions": account.regions,
        },
        "results": [result.to_dict() for result in results],
    }
    _write_json(path, payload)
    return path


def write_evidence_file(
    path: Path,
    account: Account,
    domain: str,
    timestamp: str,
    auditor: str,
    evidence_records: list[dict[str, Any]],
) -> Path | None:
    captured = []
    for record in evidence_records:
        has_evidence = record.get("evidence") is not None
        commands = record.get("commands_executed") or []
        if has_evidence or commands:
            captured.append(record)

    if not captured:
        return None

    payload = {
        "metadata": {
            "account_id": account.id,
            "account_name": account.name,
            "domain": domain,
            "auditor": auditor,
            "timestamp": timestamp,
            "role_arn": account.role_arn,
            "sso_profile": account.sso_profile,
            "regions": account.regions,
        },
        "controls": captured,
    }
    _write_json(path, payload)
    return path


def append_session_log(path: Path, message: str, level: str = "INFO") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    from datetime import datetime

    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{level}] {message}\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
