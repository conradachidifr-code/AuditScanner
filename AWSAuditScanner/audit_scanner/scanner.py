"""Core scan orchestration with optional parallel account execution."""

from __future__ import annotations

import os
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - optional dependency
    def tqdm(iterable, **kwargs):  # type: ignore[misc]
        return iterable

from audit_scanner.config import Account, AppConfig
from audit_scanner.diagnostics import DiagnosticWriter
from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.html_report import write_html_report
from audit_scanner.output import (
    account_output_paths,
    append_session_log,
    write_evidence_file,
    write_results_file,
)
from audit_scanner.results import AuditResult
from audit_scanner.session import clear_account_session, set_account_session


@dataclass
class AccountScanResult:
    account_name: str
    account_folder: str | None
    results: list[dict[str, Any]]
    summary: dict[str, Any]
    evidence_records: list[dict[str, Any]]


def _summary_row(account_name: str, results: list[AuditResult]) -> dict[str, Any]:
    counts = {"passed": 0, "failed": 0, "partial": 0, "not_tested": 0}
    for item in results:
        status = item.status
        if status == "PASS":
            counts["passed"] += 1
        elif status == "FAIL":
            counts["failed"] += 1
        elif status == "PARTIAL":
            counts["partial"] += 1
        elif status == "NOT_TESTED":
            counts["not_tested"] += 1
    return {"account": account_name, **counts}


def _evidence_record(result: AuditResult, commands: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "control_id": result.control_id,
        "region": result.region,
        "status": result.status,
        "severity": result.severity,
        "notes": result.notes,
        "timestamp": result.timestamp,
        "evidence": result.evidence,
        "commands_executed": commands,
    }


def scan_account(
    account: Account,
    domain: DomainModule,
    output_path: Path,
    timestamp: str,
    auditor: str,
    auth_mode: str,
    skip_controls: set[str],
    verbose: bool = False,
) -> AccountScanResult:
    paths = account_output_paths(output_path, account.name, account.id, domain.code, timestamp)
    diagnostics = DiagnosticWriter(
        paths["diagnostic_file"], domain.code, account.name, account.id, auditor
    )

    results: list[AuditResult] = []
    evidence_records: list[dict[str, Any]] = []

    profile = account.sso_profile or None
    if not set_account_session(account, auth_mode):
        for region in account.regions:
            for control_id in domain.checks:
                result = AuditResult(
                    account_id=account.id,
                    account_name=account.name,
                    region=region,
                    control_id=control_id,
                    status="NOT_TESTED",
                    evidence=None,
                    notes="Could not assume role for account",
                    severity=domain.severity.get(control_id, "P2"),
                )
                results.append(result)
                evidence_records.append(_evidence_record(result, []))
        clear_account_session()
        write_results_file(paths["results_file"], account, domain.code, timestamp, auditor, results)
        write_evidence_file(
            paths["evidence_file"], account, domain.code, timestamp, auditor, evidence_records
        )
        return AccountScanResult(
            account.name,
            str(paths["account_folder"]),
            [r.to_dict() for r in results],
            _summary_row(account.name, results),
            evidence_records,
        )

    active_profile = os.environ.get("AWS_PROFILE") or profile

    for region in account.regions:
        if verbose:
            print(f"  Region: {region}")

        for control_id, check_fn in domain.checks.items():
            check_ctx = CheckContext.for_region(region, active_profile, domain.severity)

            def on_cli_failure(diag_type: str, entry) -> None:
                diagnostics.write_cli_failure(
                    diag_type,
                    entry.output,
                    [{
                        "command": entry.command,
                        "success": entry.success,
                        "exit_code": entry.exit_code,
                        "output": entry.output,
                    }],
                )

            check_ctx.aws.on_cli_failure = on_cli_failure

            if control_id in skip_controls:
                result = check_ctx.results.audit_result(
                    account.id, account.name, region, control_id, "NOT_TESTED", None, "Skipped by parameter"
                )
            else:
                try:
                    result = check_fn(account.id, account.name, region, check_ctx)
                except Exception as exc:  # noqa: BLE001
                    diagnostics.set_check_cli_log(check_ctx.aws.cli_log)
                    diagnostics.write_exception(
                        domain.code,
                        account.name,
                        account.id,
                        region,
                        control_id,
                        str(exc),
                        type(exc).__name__,
                        traceback.format_exc(),
                    )
                    result = check_ctx.results.audit_result(
                        account.id,
                        account.name,
                        region,
                        control_id,
                        "PARTIAL",
                        None,
                        f"Exception: {exc}",
                    )

                if result is None:
                    result = check_ctx.results.audit_result(
                        account.id,
                        account.name,
                        region,
                        control_id,
                        "PARTIAL",
                        None,
                        "Check returned no result",
                    )

            if verbose:
                print(f"    {control_id}: {result.status}")

            results.append(result)
            evidence_records.append(_evidence_record(result, check_ctx.aws.snapshot_log()))

    clear_account_session()
    write_results_file(paths["results_file"], account, domain.code, timestamp, auditor, results)
    write_evidence_file(paths["evidence_file"], account, domain.code, timestamp, auditor, evidence_records)

    return AccountScanResult(
        account.name,
        str(paths["account_folder"]),
        [r.to_dict() for r in results],
        _summary_row(account.name, results),
        evidence_records,
    )


def _scan_account_worker(payload: dict[str, Any]) -> AccountScanResult:
    from audit_scanner.domains.registry import load_domain_by_code

    account = Account(**payload["account"])
    domain = load_domain_by_code(payload["domain_code"])
    return scan_account(
        account=account,
        domain=domain,
        output_path=Path(payload["output_path"]),
        timestamp=payload["timestamp"],
        auditor=payload["auditor"],
        auth_mode=payload["auth_mode"],
        skip_controls=set(payload["skip_controls"]),
        verbose=payload["verbose"],
    )


def run_scan(
    config: AppConfig,
    domain: DomainModule,
    output_path: Path,
    auditor: str,
    auth_mode: str,
    skip_controls: set[str],
    parallel: bool = True,
    max_workers: int | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    output_path.mkdir(parents=True, exist_ok=True)
    log_dir = output_path / "log"
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    session_log = log_dir / f"AuditSession_{timestamp}.log"

    append_session_log(
        session_log,
        f"Session started. Domain={domain.code} Accounts={len(config.accounts)} Parallel={parallel}",
    )

    active_accounts = [account for account in config.accounts if not account.skip]
    summaries: list[dict[str, Any]] = []
    all_results: dict[str, list[dict[str, Any]]] = {}
    written_folders: list[str] = []

    if parallel and len(active_accounts) > 1:
        payloads = [
            {
                "account": {
                    "id": account.id,
                    "name": account.name,
                    "role_arn": account.role_arn,
                    "sso_profile": account.sso_profile,
                    "regions": account.regions,
                    "skip": account.skip,
                    "skip_reason": account.skip_reason,
                },
                "domain_code": domain.code,
                "output_path": str(output_path),
                "timestamp": timestamp,
                "auditor": auditor,
                "auth_mode": auth_mode,
                "skip_controls": sorted(skip_controls),
                "verbose": False,
            }
            for account in active_accounts
        ]

        workers = max_workers or min(len(active_accounts), os.cpu_count() or 4)
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_scan_account_worker, payload): payload for payload in payloads}
            for future in tqdm(as_completed(futures), total=len(futures), desc="Accounts", unit="acct"):
                payload = futures[future]
                account_name = payload["account"]["name"]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    append_session_log(session_log, f"Account {account_name} failed: {exc}", "ERROR")
                    continue
                summaries.append(result.summary)
                all_results[result.account_name] = result.results
                if result.account_folder:
                    written_folders.append(result.account_folder)
                append_session_log(session_log, f"Completed account {result.account_name}")
    else:
        progress = tqdm(active_accounts, desc="Accounts", unit="acct")
        for account in progress:
            progress.set_postfix(account=account.name)
            if verbose:
                print(f"--- Account: {account.name} ({account.id}) ---")
            result = scan_account(
                account, domain, output_path, timestamp, auditor, auth_mode, skip_controls, verbose
            )
            summaries.append(result.summary)
            all_results[result.account_name] = result.results
            if result.account_folder:
                written_folders.append(result.account_folder)
            append_session_log(session_log, f"Completed account {result.account_name}")

    report_path = output_path / f"AuditReport_{domain.code}_{timestamp}.html"
    write_html_report(report_path, domain.code, auditor, timestamp, summaries, all_results)

    return {
        "timestamp": timestamp,
        "session_log": str(session_log),
        "html_report": str(report_path),
        "summaries": summaries,
        "written_folders": written_folders,
        "all_results": all_results,
    }
