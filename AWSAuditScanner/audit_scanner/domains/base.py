"""Base types for domain modules."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable

from audit_scanner.aws_cli import AwsCliContext
from audit_scanner.results import AuditResult, ResultFactory


CheckFn = Callable[[str, str, str, "CheckContext"], AuditResult]


@dataclass
class CheckContext:
    aws: AwsCliContext
    results: ResultFactory
    invoke_aws_cli: Callable[[list[str]], Any | None]
    _credential_report_cache: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def for_region(cls, region: str, profile: str | None, severity: dict[str, str]) -> "CheckContext":
        aws = AwsCliContext(region=region, profile=profile)
        factory = ResultFactory(severity)

        def invoke(arguments: list[str]) -> Any | None:
            return aws.invoke(arguments)

        return cls(aws=aws, results=factory, invoke_aws_cli=invoke)


@dataclass
class DomainModule:
    code: str
    severity: dict[str, str]
    checks: "OrderedDict[str, CheckFn]"
