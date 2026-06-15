#!/usr/bin/env python3
"""Anonymize AWS Audit Scanner output for sharing with an AI audit evaluator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from audit_scanner.anonymize import parse_filter_tokens, run_anonymization


def main(argv: list[str] | None = None) -> int:
    script_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Anonymize audit scanner output for AI review",
        epilog=(
            "Examples:\n"
            "  python protect_audit_output.py --force\n"
            "  python protect_audit_output.py --account PROD-SEC --domain NET --force\n"
            "  python protect_audit_output.py --account PROD-SEC,PROD-SHARED --domain IAM,INC --force"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input-path", default=str(script_root / "output"))
    parser.add_argument(
        "--output-path",
        default=None,
        help="Destination folder (default: output/anonymized, or output/anonymized/acct-...-dom-... when filtered)",
    )
    parser.add_argument("--config-file", default=str(script_root / "accounts.json"))
    parser.add_argument("--mapping-file", default=None)
    parser.add_argument(
        "--account",
        action="append",
        default=[],
        help="Account name or 12-digit ID to include (repeatable or comma-separated). Default: all accounts.",
    )
    parser.add_argument(
        "--domain",
        action="append",
        default=[],
        help="Domain code to include (repeatable or comma-separated). Default: all domains.",
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    input_path = Path(args.input_path)
    output_path = Path(args.output_path) if args.output_path else None
    mapping_file = Path(args.mapping_file) if args.mapping_file else input_path / "anonymization-map.local.json"

    account_tokens: list[str] = []
    for value in args.account:
        account_tokens.extend(parse_filter_tokens(value))

    domain_tokens: list[str] = []
    for value in args.domain:
        domain_tokens.extend(parse_filter_tokens(value))

    try:
        run_anonymization(
            input_path=input_path,
            output_path=output_path,
            config_file=Path(args.config_file),
            mapping_file=mapping_file,
            force=args.force,
            accounts=account_tokens or None,
            domains=domain_tokens or None,
        )
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
