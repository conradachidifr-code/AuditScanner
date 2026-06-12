"""AWS CLI subprocess wrapper (auth mode A — same as PowerShell scanner)."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class CliLogEntry:
    command: str
    success: bool
    exit_code: int | None
    output: str


@dataclass
class AwsCliContext:
    region: str
    profile: str | None = None
    cli_log: list[CliLogEntry] = field(default_factory=list)
    on_cli_failure: Callable[[str, CliLogEntry], None] | None = None

    def command_string(self, arguments: list[str]) -> str:
        parts = ["aws", *arguments, "--output", "json", "--region", self.region]
        if not os.environ.get("AWS_ACCESS_KEY_ID"):
            profile = self.profile or os.environ.get("AWS_PROFILE")
            if profile:
                parts.extend(["--profile", profile])
        return " ".join(parts)

    def invoke(self, arguments: list[str]) -> Any | None:
        cli_args = list(arguments) + ["--output", "json", "--region", self.region]
        env = os.environ.copy()

        if not env.get("AWS_ACCESS_KEY_ID"):
            profile = self.profile or env.get("AWS_PROFILE")
            if not profile:
                message = "No AWS credentials or profile in environment"
                entry = CliLogEntry(self.command_string(arguments), False, None, message)
                self.cli_log.append(entry)
                if self.on_cli_failure:
                    self.on_cli_failure("cli_no_credentials", entry)
                return None
            cli_args.extend(["--profile", profile])

        command_string = self.command_string(arguments)
        try:
            completed = subprocess.run(
                ["aws", *cli_args],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
        except OSError as exc:
            entry = CliLogEntry(command_string, False, None, str(exc))
            self.cli_log.append(entry)
            if self.on_cli_failure:
                self.on_cli_failure("cli_execution_error", entry)
            return None

        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        output_text = stdout or stderr

        if completed.returncode != 0:
            entry = CliLogEntry(command_string, False, completed.returncode, output_text)
            self.cli_log.append(entry)
            if self.on_cli_failure:
                self.on_cli_failure("cli_error", entry)
            return None

        if not stdout:
            entry = CliLogEntry(command_string, True, completed.returncode, "")
            self.cli_log.append(entry)
            return None

        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as exc:
            entry = CliLogEntry(
                command_string,
                False,
                completed.returncode,
                f"JSON parse failed: {exc} | output: {stdout[:500]}",
            )
            self.cli_log.append(entry)
            if self.on_cli_failure:
                self.on_cli_failure("cli_json_error", entry)
            return None

        entry = CliLogEntry(command_string, True, completed.returncode, stdout[:4000])
        self.cli_log.append(entry)
        return parsed

    def snapshot_log(self) -> list[dict[str, Any]]:
        return [
            {
                "command": entry.command,
                "success": entry.success,
                "exit_code": entry.exit_code,
                "output": entry.output,
            }
            for entry in self.cli_log
        ]

    def clear_log(self) -> None:
        self.cli_log.clear()
