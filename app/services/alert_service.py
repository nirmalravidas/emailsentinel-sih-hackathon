"""Alert abstraction with database recording as the initial delivery provider."""
from __future__ import annotations

from app.database import database


ALERT_LEVELS = {"HIGH", "CRITICAL"}


def maybe_create_risk_alert(analysis_id: str, risk_level: str, risk_score: int) -> dict | None:
    normalized_level = risk_level.upper()
    if normalized_level not in ALERT_LEVELS:
        return None
    return database.create_alert(
        analysis_id=analysis_id,
        alert_type="HIGH_RISK_ANALYSIS",
        severity=normalized_level,
        message=f"Email analysis {analysis_id} reached {normalized_level} risk ({risk_score}/100).",
    )
