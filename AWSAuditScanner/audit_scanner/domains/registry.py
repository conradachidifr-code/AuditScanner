"""Domain module registry."""

from __future__ import annotations

from audit_scanner.domains.base import DomainModule

VALID_DOMAINS = ("LOG", "IAM", "DET", "DAT", "GOV", "ORG", "NET", "CIC", "BCK", "INC", "WRK")

_PYTHON_DOMAINS = VALID_DOMAINS

_LOADERS = {
    "BCK": "bck",
    "CIC": "cic",
    "DAT": "dat",
    "DET": "det",
    "GOV": "gov",
    "IAM": "iam",
    "INC": "inc",
    "LOG": "log",
    "NET": "net",
    "ORG": "org",
    "WRK": "wrk",
}


def load_domain_by_code(code: str) -> DomainModule:
    code = code.upper()
    if code not in VALID_DOMAINS:
        raise ValueError(f"Invalid domain '{code}'. Must be one of: {', '.join(VALID_DOMAINS)}")
    if code not in _PYTHON_DOMAINS:
        raise NotImplementedError(
            f"Domain '{code}' is not yet ported to Python. "
            f"Available: {', '.join(_PYTHON_DOMAINS)}."
        )

    module_name = _LOADERS.get(code)
    if not module_name:
        raise NotImplementedError(f"Domain '{code}' loader missing")

    import importlib

    module = importlib.import_module(f"audit_scanner.domains.{module_name}")
    return module.get_domain()
