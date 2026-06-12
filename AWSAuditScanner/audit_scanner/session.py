"""Per-account AWS session (SSO profile or assume-role)."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass

from audit_scanner.config import Account, load_profiles_from_aws_config


@dataclass
class ConnectivityResult:
    account_id: str
    account_name: str
    status: str
    identity: str | None = None
    error: str | None = None


def clear_account_session() -> None:
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        os.environ.pop(key, None)


def resolve_sso_profile(account: Account) -> str | None:
    if account.sso_profile:
        return account.sso_profile
    try:
        profiles = load_profiles_from_aws_config()
    except OSError:
        return None
    for profile in profiles:
        if profile["AccountId"] == account.id:
            return profile["Name"]
    for profile in profiles:
        if profile["Name"] == account.name:
            return profile["Name"]
    return None


def test_sso_profile_session(profile_name: str, account_id: str) -> bool:
    try:
        completed = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--output", "json", "--profile", profile_name],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    if completed.returncode != 0:
        return False
    if not completed.stdout.strip():
        return False
    identity = json.loads(completed.stdout)
    return str(identity.get("Account")) == account_id


def set_account_session(account: Account, auth_mode: str = "sso_profile") -> bool:
    source_profile = os.environ.get("AWS_PROFILE")
    clear_account_session()

    if auth_mode in ("sso_profile", "auto"):
        profile = resolve_sso_profile(account)
        if not profile and source_profile:
            if test_sso_profile_session(source_profile, account.id):
                profile = source_profile
        if profile and test_sso_profile_session(profile, account.id):
            os.environ["AWS_PROFILE"] = profile
            return True
        if auth_mode == "sso_profile":
            return False

    session_name = f"AuditScan-{account.id}"
    assume_args = [
        "aws",
        "sts",
        "assume-role",
        "--role-arn",
        account.role_arn,
        "--role-session-name",
        session_name,
        "--output",
        "json",
    ]
    if source_profile:
        assume_args.extend(["--profile", source_profile])

    completed = subprocess.run(assume_args, capture_output=True, text=True, check=False)
    if completed.returncode != 0 or not completed.stdout.strip():
        return False

    payload = json.loads(completed.stdout)
    credentials = payload.get("Credentials")
    if not credentials:
        return False

    os.environ["AWS_ACCESS_KEY_ID"] = credentials["AccessKeyId"]
    os.environ["AWS_SECRET_ACCESS_KEY"] = credentials["SecretAccessKey"]
    os.environ["AWS_SESSION_TOKEN"] = credentials["SessionToken"]
    return True


def test_account_connectivity(account: Account, auth_mode: str = "sso_profile") -> ConnectivityResult:
    result = ConnectivityResult(account.id, account.name, "FAILED")
    try:
        if not set_account_session(account, auth_mode):
            result.error = "Failed to assume role"
            return result
        completed = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            result.error = (completed.stderr or completed.stdout).strip()
            return result
        if not completed.stdout.strip():
            result.error = "Empty response from get-caller-identity"
            return result
        identity = json.loads(completed.stdout)
        result.status = "OK"
        result.identity = identity.get("Arn")
    except Exception as exc:  # noqa: BLE001 — mirror PS catch-all
        result.error = str(exc)
    finally:
        clear_account_session()
    return result
