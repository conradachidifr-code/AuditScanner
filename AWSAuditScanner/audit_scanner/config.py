"""Load accounts.json and AWS config profiles."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Account:
    id: str
    name: str
    role_arn: str
    sso_profile: str
    regions: list[str]
    skip: bool = False
    skip_reason: str = ""

    def to_metadata_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "role_arn": self.role_arn,
            "sso_profile": self.sso_profile,
            "regions": self.regions,
            "skip": self.skip,
            "skip_reason": self.skip_reason,
        }


@dataclass
class AppConfig:
    default_role_name: str
    default_regions: list[str]
    auth_mode: str
    accounts: list[Account]


def _build_role_arn(entry: dict[str, Any], raw_config: dict[str, Any], account_id: str) -> str:
    role_arn = entry.get("role_arn")
    if role_arn:
        return str(role_arn)
    default_role_path = raw_config.get("default_role_path")
    if default_role_path:
        return f"arn:aws:iam::{account_id}:role/{default_role_path}"
    role_name = raw_config.get("default_role_name")
    if not role_name:
        raise ValueError("Config missing required field: default_role_name or default_role_path")
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw = json.loads(config_path.read_text(encoding="utf-8"))
    if not raw.get("default_regions"):
        raise ValueError("Config missing required field: default_regions")
    if not raw.get("accounts"):
        raise ValueError("Config missing required field: accounts")
    if not raw.get("default_role_name") and not raw.get("default_role_path"):
        raise ValueError("Config missing required field: default_role_name or default_role_path")

    accounts: list[Account] = []
    for entry in raw["accounts"]:
        if not entry.get("id"):
            raise ValueError("Account entry missing required field: id")
        if not entry.get("name"):
            raise ValueError("Account entry missing required field: name")

        regions = entry.get("regions") or list(raw["default_regions"])
        profile = entry.get("profile") or entry.get("sso_profile") or ""

        accounts.append(
            Account(
                id=str(entry["id"]),
                name=str(entry["name"]),
                role_arn=_build_role_arn(entry, raw, str(entry["id"])),
                sso_profile=str(profile) if profile else "",
                regions=[str(r) for r in regions],
                skip=bool(entry.get("skip", False)),
                skip_reason=str(entry.get("skip_reason") or ""),
            )
        )

    return AppConfig(
        default_role_name=str(raw.get("default_role_name") or ""),
        default_regions=[str(r) for r in raw["default_regions"]],
        auth_mode=str(raw.get("auth_mode") or "sso_profile"),
        accounts=accounts,
    )


def load_profiles_from_aws_config() -> list[dict[str, str]]:
    if os.environ.get("AWS_CONFIG_FILE"):
        config_path = Path(os.environ["AWS_CONFIG_FILE"])
    elif os.name == "nt" and os.environ.get("USERPROFILE"):
        config_path = Path(os.environ["USERPROFILE"]) / ".aws" / "config"
    else:
        config_path = Path.home() / ".aws" / "config"

    if not config_path.is_file():
        raise FileNotFoundError(f"AWS config file not found: {config_path}")

    profiles: list[dict[str, str]] = []
    current_profile: str | None = None
    section_re = re.compile(r"^\[(.+)\]$")
    account_re = re.compile(r"^sso_account_id\s*=\s*(.+)$")

    for line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        section_match = section_re.match(stripped)
        if section_match:
            section_name = section_match.group(1)
            if section_name.startswith("profile "):
                current_profile = section_name[8:]
            else:
                current_profile = None
            continue

        if current_profile:
            account_match = account_re.match(stripped)
            if account_match:
                profiles.append({"Name": current_profile, "AccountId": account_match.group(1).strip()})

    return profiles


def fallback_config_from_profiles() -> AppConfig:
    profiles = load_profiles_from_aws_config()
    default_regions = ["eu-west-1", "eu-west-2", "eu-west-3"]
    fallback_role = "CCOE_DataRead"
    accounts = [
        Account(
            id=p["AccountId"],
            name=p["Name"],
            role_arn=f"arn:aws:iam::{p['AccountId']}:role/{fallback_role}",
            sso_profile=p["Name"],
            regions=list(default_regions),
        )
        for p in profiles
    ]
    return AppConfig(
        default_role_name=fallback_role,
        default_regions=default_regions,
        auth_mode="sso_profile",
        accounts=accounts,
    )
