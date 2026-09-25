"""Evidence integrity and upload-safety helpers."""
from __future__ import annotations

import hashlib
from pathlib import PurePath
from typing import Optional


class InvalidEvidenceError(ValueError):
    pass


def safe_filename(filename: Optional[str]) -> str:
    """Return a basename-only filename and reject empty or non-email evidence."""
    name = PurePath(filename or "").name.strip()
    if not name or name in {".", ".."}:
        raise InvalidEvidenceError("A filename is required for uploaded evidence")
    if not name.lower().endswith(".eml"):
        raise InvalidEvidenceError("Only .eml evidence files are accepted")
    return name


def sha256_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
