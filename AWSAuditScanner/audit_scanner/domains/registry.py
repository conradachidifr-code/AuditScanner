"""Domain module registry."""

from __future__ import annotations

from audit_scanner.domains.base import DomainModule

VALID_DOMAINS = ("LOG", "IAM", "DET", "DAT", "GOV", "ORG", "NET", "CIC", "BCK", "INC", "WRK")

_PHASE_ONE = ("DET", "INC", "NET", "IAM", "CIC", "WRK")


def load_domain_by_code(code: str) -> DomainModule:
    code = code.upper()
    if code not in VALID_DOMAINS:
        raise ValueError(f"Invalid domain '{code}'. Must be one of: {', '.join(VALID_DOMAINS)}")
    if code not in _PHASE_ONE:
        raise NotImplementedError(
            f"Domain '{code}' is not yet ported to Python. "
            f"Available: {', '.join(_PHASE_ONE)}. Use Invoke-AWSScanner.ps1 for other domains."
        )

    if code == "DET":
        from audit_scanner.domains import det

        return det.get_domain()
    if code == "INC":
        from audit_scanner.domains import inc

        return inc.get_domain()
    if code == "NET":
        from audit_scanner.domains import net

        return net.get_domain()
    if code == "IAM":
        from audit_scanner.domains import iam

        return iam.get_domain()
    if code == "CIC":
        from audit_scanner.domains import cic

        return cic.get_domain()
    if code == "WRK":
        from audit_scanner.domains import wrk

        return wrk.get_domain()

    raise NotImplementedError(f"Domain '{code}' loader missing")
