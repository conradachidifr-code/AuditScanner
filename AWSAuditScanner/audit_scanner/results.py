"""Audit result builders — JSON field names match PowerShell ConvertTo-Json output."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _iso_timestamp() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


@dataclass
class AuditResult:
    account_id: str
    account_name: str
    region: str
    control_id: str
    status: str
    evidence: Any = None
    notes: str = ""
    severity: str = "P2"
    timestamp: str = field(default_factory=_iso_timestamp)

    def to_dict(self) -> dict[str, Any]:
        return {
            "Timestamp": self.timestamp,
            "AccountId": self.account_id,
            "AccountName": self.account_name,
            "Region": self.region,
            "ControlId": self.control_id,
            "Status": self.status,
            "Evidence": self.evidence,
            "Notes": self.notes,
            "Severity": self.severity,
        }


class ResultFactory:
    def __init__(self, severity_map: dict[str, str]) -> None:
        self._severity = severity_map

    def _severity_for(self, control_id: str) -> str:
        return self._severity.get(control_id, "P2")

    def audit_result(
        self,
        account_id: str,
        account_name: str,
        region: str,
        control_id: str,
        status: str,
        evidence: Any = None,
        notes: str = "",
    ) -> AuditResult:
        return AuditResult(
            account_id=account_id,
            account_name=account_name,
            region=region,
            control_id=control_id,
            status=status,
            evidence=evidence,
            notes=notes,
            severity=self._severity_for(control_id),
        )

    def global_control_gate(
        self, account_id: str, account_name: str, region: str, control_id: str
    ) -> AuditResult | None:
        if region == "eu-west-1":
            return None
        return self.audit_result(
            account_id,
            account_name,
            region,
            control_id,
            "NOT_TESTED",
            None,
            "Global control - checked in eu-west-1 only",
        )

    def workshop_control(
        self, account_id: str, account_name: str, region: str, control_id: str, notes: str
    ) -> AuditResult:
        return self.audit_result(account_id, account_name, region, control_id, "NOT_TESTED", None, notes)

    def null_api_partial(
        self, account_id: str, account_name: str, region: str, control_id: str
    ) -> AuditResult:
        return self.audit_result(
            account_id,
            account_name,
            region,
            control_id,
            "PARTIAL",
            None,
            "API call returned null - possible permission issue",
        )
