"""Configurable privacy transformations for reports returned to analysts."""
from __future__ import annotations

import copy
import re
from typing import Any

from app import config

_SENSITIVE_KEYS = {"from", "to", "reply_to", "return_path", "sender", "recipient", "from_address", "to_address"}


def _mask_email(value: Any) -> Any:
    if not isinstance(value, str) or "@" not in value:
        return value
    return re.sub(r"([\w.+-])[^@\s]*(@[^\s>]+)", r"\1***\2", value)


def mask_report(report: dict[str, Any]) -> dict[str, Any]:
    if not config.MASK_SENSITIVE_FIELDS:
        return report

    masked = copy.deepcopy(report)

    def visit(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: (_mask_email(item) if key in _SENSITIVE_KEYS else visit(item)) for key, item in value.items()}
        if isinstance(value, list):
            return [visit(item) for item in value]
        return value

    return visit(masked)