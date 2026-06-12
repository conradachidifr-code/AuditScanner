#!/usr/bin/env python3
"""Anonymize AWS Audit Scanner output for sharing with an AI audit evaluator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from audit_scanner.anonymize import run_anonymization


def main(argv: list[str] | None = None) -> int:
    script_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Anonymize audit scanner output")
    parser.add_argument("--input-path", default=str(script_root / "output"))
    parser.add_argument("--output-path", default=None)
    parser.add_argument("--config-file", default=str(script_root / "accounts.json"))
    parser.add_argument("--mapping-file", default=None)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    input_path = Path(args.input_path)
    output_path = Path(args.output_path) if args.output_path else input_path / "anonymized"
    mapping_file = Path(args.mapping_file) if args.mapping_file else input_path / "anonymization-map.local.json"

    try:
        run_anonymization(input_path, output_path, Path(args.config_file), mapping_file, force=args.force)
    except (FileNotFoundError, FileExistsError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
