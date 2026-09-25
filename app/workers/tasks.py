"""Background analysis tasks."""
import base64

from app.workers.celery_app import celery_app
from app.services import analysis_service
from app import config
from app.database import database
from app.services import alert_service


@celery_app.task(bind=True, name="emailsentinel.health_check")
def health_check(self) -> dict[str, str]:
    """Return a worker health marker without touching analysis data."""
    return {"status": "ok", "task_id": self.request.id or "local"}


@celery_app.task(bind=True, name="emailsentinel.analyze_email")
def analyze_email_task(self, analysis_id: str, raw_email_b64: str, evidence_hash: str) -> dict:
    """Run the reusable forensic pipeline in a Celery worker."""
    raw = base64.b64decode(raw_email_b64.encode("ascii"), validate=True)
    database.save_case({"analysis_id": analysis_id, "status": "PROCESSING"})
    try:
        result = analysis_service.analyze_raw_email(raw, evidence_hash=evidence_hash, analysis_id=analysis_id)
        assessment = result["threat_assessment"]
        database.save_case({
            "analysis_id": analysis_id,
            "status": "COMPLETED",
            "classification": assessment["classification"],
            "risk_score": assessment["risk_score"],
            "risk_level": assessment["risk_level"],
            "probable_origin_ip": result["relay_analysis"]["probable_origin_ip"],
            "forensic_report": result,
            "indicators_of_compromise": result["indicators_of_compromise"],
        })
        alert_service.maybe_create_risk_alert(
            analysis_id, assessment["risk_level"], assessment["risk_score"]
        )
        return result
    except Exception:
        database.save_case({"analysis_id": analysis_id, "status": "FAILED"})
        raise
