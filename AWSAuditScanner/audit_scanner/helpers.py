"""Shared helpers mirroring Invoke-AWSScanner.ps1 audit utilities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def cli_array(items: Any) -> list[Any]:
    if items is None:
        return []
    if isinstance(items, str):
        return [items]
    if isinstance(items, Mapping):
        return [items]
    if isinstance(items, Sequence):
        return list(items)
    return [items]


def collection_count(items: Any) -> int:
    if items is None:
        return 0
    if isinstance(items, str):
        return 1
    if isinstance(items, Mapping):
        return 1
    if isinstance(items, Sequence):
        return len(items)
    return 1


def has_property(obj: Any, property_name: str) -> bool:
    if obj is None:
        return False
    if isinstance(obj, Mapping):
        return any(str(key).lower() == property_name.lower() for key in obj.keys())
    if hasattr(obj, property_name):
        return True
    if isinstance(obj, dict):
        return property_name in obj
    getter = getattr(obj, "get", None)
    if callable(getter):
        return getter(property_name) is not None
    return False


def property_value(obj: Any, property_names: Sequence[str]) -> Any:
    if obj is None:
        return None
    if isinstance(obj, Mapping):
        for name in property_names:
            for key, value in obj.items():
                if str(key).lower() == name.lower():
                    return value
        return None
    for name in property_names:
        if hasattr(obj, name):
            return getattr(obj, name)
        getter = getattr(obj, "get", None)
        if callable(getter):
            value = getter(name)
            if value is not None:
                return value
    return None
