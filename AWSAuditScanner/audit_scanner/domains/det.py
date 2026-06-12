"""DET domain — detection (GuardDuty, Security Hub)."""

from __future__ import annotations

from collections import OrderedDict

from audit_scanner.domains.base import CheckContext, DomainModule
from audit_scanner.helpers import cli_array, collection_count, has_property
from audit_scanner.results import AuditResult

SEVERITY = {
    "DET-01": "P0",
    "DET-02": "P1",
    "DET-03": "P1",
    "DET-04": "P2",
}


def _det01(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
    data = ctx.invoke_aws_cli(["guardduty", "list-detectors"])
    if data is None:
        return ctx.results.null_api_partial(account_id, account_name, region, "DET-01")
    detector_count = collection_count(data.get("DetectorIds")) if has_property(data, "DetectorIds") else 0
    if detector_count > 0:
        return ctx.results.audit_result(
            account_id, account_name, region, "DET-01", "PASS",
            {"detector_count": detector_count}, "GuardDuty detector is enabled",
        )
    return ctx.results.audit_result(
        account_id, account_name, region, "DET-01", "FAIL",
        {"detector_count": 0}, "No GuardDuty detector found in region",
    )


def _det02(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
    data = ctx.invoke_aws_cli(["securityhub", "describe-hub"])
    if data is None:
        return ctx.results.null_api_partial(account_id, account_name, region, "DET-02")
    hub_arn = str(data.get("HubArn", "")) if has_property(data, "HubArn") else ""
    if hub_arn:
        return ctx.results.audit_result(
            account_id, account_name, region, "DET-02", "PASS",
            {"hub_arn": hub_arn}, "Security Hub is enabled in region",
        )
    return ctx.results.audit_result(
        account_id, account_name, region, "DET-02", "FAIL",
        None, "Security Hub is not enabled in region",
    )


def _det03(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
    gate = ctx.results.global_control_gate(account_id, account_name, region, "DET-03")
    if gate:
        return gate
    data = ctx.invoke_aws_cli(["securityhub", "get-enabled-standards"])
    if data is None:
        return ctx.results.null_api_partial(account_id, account_name, region, "DET-03")
    standard_count = 0
    if has_property(data, "StandardsSubscriptions"):
        standard_count = collection_count(cli_array(data.get("StandardsSubscriptions")))
    if standard_count > 0:
        return ctx.results.audit_result(
            account_id, account_name, region, "DET-03", "PASS",
            {"enabled_standards_count": standard_count}, "Security Hub standards are subscribed",
        )
    return ctx.results.audit_result(
        account_id, account_name, region, "DET-03", "FAIL",
        {"enabled_standards_count": 0}, "No Security Hub standards subscribed",
    )


def _det04(account_id: str, account_name: str, region: str, ctx: CheckContext) -> AuditResult:
    return ctx.results.workshop_control(
        account_id, account_name, region, "DET-04",
        "Workshop control: verify Detective or third-party SIEM integration and alert routing manually",
    )


def get_domain() -> DomainModule:
    return DomainModule(
        code="DET",
        severity=SEVERITY,
        checks=OrderedDict(
            [
                ("DET-01", _det01),
                ("DET-02", _det02),
                ("DET-03", _det03),
                ("DET-04", _det04),
            ]
        ),
    )
