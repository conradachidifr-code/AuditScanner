"""Per-account diagnostic log writers."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from audit_scanner.aws_cli import CliLogEntry


class DiagnosticWriter:
    def __init__(self, path: Path, domain: str, account_name: str, account_id: str, auditor: str) -> None:
        self.path = path
        self._check_cli_log: list[CliLogEntry] = []
        header = "\n".join(
            [
                "AWS Audit Scanner - account diagnostic log",
                f"Domain    : {domain}",
                f"Account   : {account_name} ({account_id})",
                f"Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Auditor   : {auditor}",
                "Python exceptions and failed AWS CLI commands are recorded below.",
                "",
            ]
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(header, encoding="utf-8")

    def set_check_cli_log(self, entries: list[CliLogEntry]) -> None:
        self._check_cli_log = list(entries)

    def write_exception(
        self,
        domain: str,
        account_name: str,
        account_id: str,
        region: str,
        control_id: str,
        message: str,
        exception_type: str,
        stack_trace: str,
    ) -> None:
        lines = [
            "=" * 80,
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] PYTHON_EXCEPTION",
            f"Domain      : {domain}",
            f"Account     : {account_name} ({account_id})",
            f"Region      : {region}",
            f"Control     : {control_id}",
            f"Message     : {message}",
            f"ExceptionType: {exception_type}",
            "Stack trace :",
            stack_trace,
            "All CLI commands during this check:",
        ]
        for entry in self._check_cli_log:
            status = "OK" if entry.success else "FAIL"
            code = entry.exit_code if entry.exit_code is not None else "?"
            lines.append(f"  [{status} exit={code}] {entry.command}")
        lines.append("=" * 80)
        lines.append("")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))

    def write_cli_failure(self, diag_type: str, message: str, failed_commands: list[dict[str, Any]]) -> None:
        lines = [
            "=" * 80,
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {diag_type.upper()}",
            f"Message     : {message}",
            "Failed commands:",
        ]
        for entry in failed_commands:
            code = entry.get("exit_code", "?")
            lines.append(f"  [FAIL exit={code}] {entry.get('command', '')}")
        lines.append("=" * 80)
        lines.append("")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
