#!/usr/bin/env python3
"""AWS Audit Scanner — Python entry point."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import datetime
from pathlib import Path

from audit_scanner.config import (
    fallback_config_from_profiles,
    filter_accounts,
    load_config,
    parse_account_filter_tokens,
)
from audit_scanner.domains.registry import VALID_DOMAINS, load_domain_by_code
from audit_scanner.output import append_session_log
from audit_scanner.scanner import run_scan
from audit_scanner.session import test_account_connectivity


def _default_auditor() -> str:
    return os.environ.get("USERNAME") or os.environ.get("USER") or getpass.getuser()


def _print_banner(domain: str, account_count: int, regions: str, auditor: str, dry_run: bool) -> None:
    print("====================================")
    print("AWS Audit Scanner (Python)")
    print(f"Domain  : {domain}")
    print(f"Accounts: {account_count}")
    print(f"Regions : {regions}")
    print(f"Auditor : {auditor}")
    print(f"DryRun  : {dry_run}")
    print("====================================")


def _print_summary(summaries: list[dict]) -> None:
    print("")
    print("Summary")
    header = f"{'Account':<20} {'Passed':>8} {'Failed':>8} {'Partial':>8} {'Not Tested':>12}"
    print(header)
    print("-" * len(header))
    for row in summaries:
        print(
            f"{row['account']:<20} {row['passed']:>8} {row['failed']:>8} "
            f"{row['partial']:>8} {row['not_tested']:>12}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AWS Audit Scanner")
    parser.add_argument("--domain", "-Domain", required=True, choices=list(VALID_DOMAINS))
    parser.add_argument("--auditor", "-Auditor", default=_default_auditor())
    parser.add_argument("--config-file", "-ConfigFile", default=None)
    parser.add_argument("--output-path", "-OutputPath", default=None)
    parser.add_argument("--dry-run", "-DryRun", action="store_true")
    parser.add_argument("--skip-controls", "-SkipControls", default="")
    parser.add_argument("--verbose", "-Verbose", action="store_true")
    parser.add_argument("--sequential", action="store_true", help="Disable parallel account scanning")
    parser.add_argument("--workers", type=int, default=None, help="Max parallel account workers")
    parser.add_argument(
        "--account",
        action="append",
        default=[],
        help="Account name or 12-digit ID to scan (repeatable or comma-separated). Default: all accounts.",
    )
    args = parser.parse_args(argv)

    script_root = Path(__file__).resolve().parent
    config_file = Path(args.config_file) if args.config_file else script_root / "accounts.json"
    output_path = Path(args.output_path) if args.output_path else script_root / "output"
    domain = args.domain.upper()

    account_tokens = parse_account_filter_tokens(args.account)

    try:
        config = load_config(config_file)
    except (FileNotFoundError, ValueError) as exc:
        log_path = output_path / "log"
        log_path.mkdir(parents=True, exist_ok=True)
        session_log = log_path / f"AuditSession_{datetime.now().strftime('%Y%m%d-%H%M')}.log"
        append_session_log(session_log, str(exc), "WARN")
        append_session_log(session_log, "Falling back to AWS profile discovery from ~/.aws/config", "WARN")
        config = fallback_config_from_profiles()

    try:
        config = filter_accounts(config, account_tokens)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    region_banner = ", ".join(config.default_regions)
    all_regions = sorted({region for account in config.accounts for region in account.regions})
    if all_regions:
        region_banner = ", ".join(all_regions)

    _print_banner(domain, len(config.accounts), region_banner, args.auditor, args.dry_run)

    if args.dry_run:
        rows = []
        for account in config.accounts:
            if account.skip:
                rows.append((account.name, account.id, "SKIPPED", None, account.skip_reason))
                continue
            connectivity = test_account_connectivity(account, config.auth_mode)
            rows.append(
                (connectivity.account_name, connectivity.account_id, connectivity.status, connectivity.identity, connectivity.error)
            )
        print(f"{'Name':<20} {'AccountId':<14} {'Status':<8} Identity / Error")
        for name, account_id, status, identity, error in rows:
            detail = identity or error or ""
            print(f"{name:<20} {account_id:<14} {status:<8} {detail}")
        return 0

    try:
        domain_module = load_domain_by_code(domain)
    except NotImplementedError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    skip_controls = {item.strip() for item in args.skip_controls.split(",") if item.strip()}
    started = datetime.now()
    outcome = run_scan(
        config=config,
        domain=domain_module,
        output_path=output_path,
        auditor=args.auditor,
        auth_mode=config.auth_mode,
        skip_controls=skip_controls,
        parallel=not args.sequential,
        max_workers=args.workers,
        verbose=args.verbose,
    )

    _print_summary(outcome["summaries"])
    elapsed = datetime.now() - started
    print(f"Total elapsed time: {elapsed}")
    print("")
    print(f"Output folder : {output_path}")
    print(f"Session log   : {outcome['session_log']}")
    print(f"HTML report   : {outcome['html_report']}")
    if outcome["written_folders"]:
        print("Account output:")
        for folder in outcome["written_folders"]:
            print(f"  {folder}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
