"""SQLAlchemy database engine and a compatibility repository for case metadata."""
from contextlib import contextmanager
from typing import Any, Dict, List

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from app import config
from app.database.base import Base
from app.database.models import Alert, AnalysisCase, AuditLog, Campaign, CampaignIndicator, CaseIOC, EmailEvidence, EvidenceEvent, IOC


connect_args = {"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(
    config.DATABASE_URL,
    echo=config.DATABASE_ECHO,
    connect_args=connect_args,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@contextmanager
def session_scope():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create local SQLite tables for development; PostgreSQL uses Alembic."""
    if config.DATABASE_URL.startswith("sqlite"):
        config.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        Base.metadata.create_all(engine)


def purge_expired_cases() -> int:
    if not config.RETENTION_ENABLED:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.RETENTION_DAYS)
    with session_scope() as session:
        expired = session.scalars(select(AnalysisCase).where(AnalysisCase.created_at < cutoff)).all()
        count = len(expired)
        for case in expired:
            session.delete(case)
        return count


def save_case(record: Dict[str, Any]) -> None:
    with session_scope() as session:
        case = session.scalar(select(AnalysisCase).where(AnalysisCase.analysis_id == record["analysis_id"]))
        if case is None:
            case = AnalysisCase(
                analysis_id=record["analysis_id"],
                case_number=record.get("case_number", f"ES-{record['analysis_id'][:8].upper()}"),
            )
            session.add(case)
            session.flush()
        for field in ("created_at", "subject", "sender", "recipient", "classification", "risk_score", "risk_level", "probable_origin_ip", "status", "forensic_report"):
            if field in record and field != "created_at":
                setattr(case, field, record[field])
        if record.get("raw_email_hash"):
            evidence = EmailEvidence(
                case_id=case.id,
                original_filename=record.get("original_filename"),
                raw_email_hash=record["raw_email_hash"],
                content_hash=record.get("content_hash"),
                raw_email_size=record.get("raw_email_size", 0),
                storage_reference=record.get("storage_reference"),
            )
            session.add(evidence)
            session.flush()
            session.add(EvidenceEvent(
                evidence_id=evidence.id,
                event_type="INGESTED",
                hash=record["raw_email_hash"],
                description="Email evidence accepted and hashed at ingestion",
            ))
        if record.get("indicators_of_compromise"):
            _save_case_iocs(session, case, record["indicators_of_compromise"])


def list_cases(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    with session_scope() as session:
        rows = session.scalars(
            select(AnalysisCase).order_by(AnalysisCase.created_at.desc()).limit(limit).offset(offset)
        ).all()
        return [_case_dict(case) for case in rows]


def count_cases() -> int:
    with session_scope() as session:
        return int(session.scalar(select(func.count()).select_from(AnalysisCase)) or 0)


def get_case(analysis_id: str) -> Dict[str, Any] | None:
    with session_scope() as session:
        case = session.scalar(select(AnalysisCase).where(AnalysisCase.analysis_id == analysis_id))
        return _case_dict(case) if case else None


def get_case_iocs(analysis_id: str) -> List[Dict[str, Any]] | None:
    with session_scope() as session:
        case = session.scalar(select(AnalysisCase).where(AnalysisCase.analysis_id == analysis_id))
        if case is None:
            return None
        rows = session.scalars(select(CaseIOC).where(CaseIOC.case_id == case.id)).all()
        return [{"type": link.ioc.ioc_type, "value": link.ioc.value, "source": link.source} for link in rows]


def correlate_case_iocs(analysis_id: str) -> Dict[str, Any] | None:
    with session_scope() as session:
        case = session.scalar(select(AnalysisCase).where(AnalysisCase.analysis_id == analysis_id))
        if case is None:
            return None
        links = session.scalars(select(CaseIOC).where(CaseIOC.case_id == case.id)).all()
        shared: Dict[str, List[Dict[str, Any]]] = {}
        for link in links:
            other_links = session.scalars(
                select(CaseIOC).where(CaseIOC.ioc_id == link.ioc_id, CaseIOC.case_id != case.id)
            ).all()
            for other in other_links:
                shared.setdefault(link.ioc.value, []).append({
                    "case_id": other.case.analysis_id,
                    "ioc_type": link.ioc.ioc_type,
                })
        return {
            "case_id": analysis_id,
            "shared_indicators": shared,
            "similarity_score": round(min(1.0, sum(len(items) for items in shared.values()) / 5), 2),
            "disclaimer": "Shared indicators support campaign investigation; they do not prove common attacker identity.",
        }


def update_case_status(analysis_id: str, status: str, analyst_notes: str | None = None) -> Dict[str, Any] | None:
    with session_scope() as session:
        case = session.scalar(select(AnalysisCase).where(AnalysisCase.analysis_id == analysis_id))
        if case is None:
            return None
        case.status = status
        if analyst_notes is not None:
            case.analyst_notes = analyst_notes
        session.add(AuditLog(
            actor="analyst",
            action="CASE_STATUS_UPDATED",
            resource_type="analysis_case",
            resource_id=analysis_id,
            metadata_json={"status": status, "has_notes": analyst_notes is not None},
        ))
        session.flush()
        return _case_dict(case)


def case_timeline(analysis_id: str) -> List[Dict[str, Any]] | None:
    with session_scope() as session:
        case = session.scalar(select(AnalysisCase).where(AnalysisCase.analysis_id == analysis_id))
        if case is None:
            return None
        events: List[Dict[str, Any]] = [{
            "event_type": "CASE_CREATED",
            "timestamp": case.created_at.isoformat() if case.created_at else None,
            "description": "Analysis case created",
        }]
        evidence = session.scalars(select(EmailEvidence).where(EmailEvidence.case_id == case.id)).all()
        for item in evidence:
            for event in item.events:
                events.append({
                    "event_type": event.event_type,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "hash": event.hash,
                    "description": event.description,
                })
        if case.status == "COMPLETED":
            events.append({
                "event_type": "ANALYZED",
                "timestamp": case.updated_at.isoformat() if case.updated_at else None,
                "description": "Forensic analysis completed",
            })
        audits = session.scalars(
            select(AuditLog).where(
                AuditLog.resource_type == "analysis_case",
                AuditLog.resource_id == analysis_id,
            )
        ).all()
        for audit in audits:
            events.append({
                "event_type": audit.action,
                "timestamp": audit.timestamp.isoformat() if audit.timestamp else None,
                "description": f"Audit action by {audit.actor or 'system'}",
                "metadata": audit.metadata_json,
            })
        return sorted(events, key=lambda event: event["timestamp"] or "")


def record_audit_event(action: str, resource_type: str, resource_id: str, actor: str = "system") -> None:
    with session_scope() as session:
        session.add(AuditLog(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
        ))


def create_alert(analysis_id: str, alert_type: str, severity: str, message: str) -> Dict[str, Any] | None:
    with session_scope() as session:
        case = session.scalar(select(AnalysisCase).where(AnalysisCase.analysis_id == analysis_id))
        if case is None:
            return None
        alert = session.scalar(select(Alert).where(Alert.case_id == case.id, Alert.alert_type == alert_type))
        if alert is None:
            alert = Alert(
                case_id=case.id,
                alert_type=alert_type,
                severity=severity,
                message=message,
                delivery_status="RECORDED",
            )
            session.add(alert)
            session.flush()
        return _alert_dict(alert)


def list_alerts(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    with session_scope() as session:
        alerts = session.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(limit).offset(offset)).all()
        return [_alert_dict(alert) for alert in alerts]


def get_alert(alert_id: int) -> Dict[str, Any] | None:
    with session_scope() as session:
        alert = session.get(Alert, alert_id)
        return _alert_dict(alert) if alert else None


def create_campaign(name: str, description: str | None = None, risk_level: str | None = None) -> Dict[str, Any]:
    import uuid

    with session_scope() as session:
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            campaign_name=name,
            description=description,
            risk_level=risk_level,
            email_count=0,
        )
        session.add(campaign)
        session.flush()
        return _campaign_dict(campaign)


def list_campaigns(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    with session_scope() as session:
        campaigns = session.scalars(
            select(Campaign).order_by(Campaign.last_seen.desc().nullslast(), Campaign.first_seen.desc().nullslast()).limit(limit).offset(offset)
        ).all()
        return [_campaign_dict(campaign) for campaign in campaigns]


def get_campaign(campaign_id: str) -> Dict[str, Any] | None:
    with session_scope() as session:
        campaign = session.scalar(select(Campaign).where(Campaign.campaign_id == campaign_id))
        if campaign is None:
            return None
        result = _campaign_dict(campaign)
        result["cases"] = [
            {"case_id": link.case.analysis_id, "similarity_score": link.similarity_score}
            for link in campaign.indicators
        ]
        result["indicators"] = [
            {"type": link.ioc.ioc_type, "value": link.ioc.value}
            for link in campaign.indicators
        ]
        return result


def attach_case_to_campaign(campaign_id: str, analysis_id: str, similarity_score: float | None = None) -> Dict[str, Any] | None:
    with session_scope() as session:
        campaign = session.scalar(select(Campaign).where(Campaign.campaign_id == campaign_id))
        case = session.scalar(select(AnalysisCase).where(AnalysisCase.analysis_id == analysis_id))
        if campaign is None or case is None:
            return None
        for link in case.ioc_links:
            existing = session.scalar(select(CampaignIndicator).where(
                CampaignIndicator.campaign_id == campaign.id,
                CampaignIndicator.ioc_id == link.ioc_id,
                CampaignIndicator.case_id == case.id,
            ))
            if existing is None:
                campaign.indicators.append(CampaignIndicator(
                    ioc=link.ioc,
                    case=case,
                    similarity_score=similarity_score,
                ))
        campaign.email_count = len({link.case_id for link in campaign.indicators})
        now = case.updated_at or case.created_at
        campaign.first_seen = min(filter(None, [campaign.first_seen, case.created_at]), default=case.created_at)
        campaign.last_seen = max(filter(None, [campaign.last_seen, now]), default=now)
        session.add(AuditLog(
            actor="analyst",
            action="CASE_ATTACHED_TO_CAMPAIGN",
            resource_type="campaign",
            resource_id=campaign_id,
            metadata_json={"analysis_id": analysis_id, "similarity_score": similarity_score},
        ))
        session.flush()
        return _campaign_dict(campaign)


def _case_dict(case: AnalysisCase) -> Dict[str, Any]:
    return {
        "analysis_id": case.analysis_id,
        "case_number": case.case_number,
        "status": case.status,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "subject": case.subject,
        "sender": case.sender,
        "recipient": case.recipient,
        "classification": case.classification,
        "risk_score": case.risk_score,
        "risk_level": case.risk_level,
        "probable_origin_ip": case.probable_origin_ip,
        "forensic_report": case.forensic_report,
    }


def _alert_dict(alert: Alert) -> Dict[str, Any]:
    return {
        "id": alert.id,
        "case_id": alert.case.analysis_id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "message": alert.message,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "delivery_status": alert.delivery_status,
    }


def _campaign_dict(campaign: Campaign) -> Dict[str, Any]:
    return {
        "campaign_id": campaign.campaign_id,
        "name": campaign.campaign_name,
        "description": campaign.description,
        "risk_level": campaign.risk_level,
        "first_seen": campaign.first_seen.isoformat() if campaign.first_seen else None,
        "last_seen": campaign.last_seen.isoformat() if campaign.last_seen else None,
        "email_count": campaign.email_count,
    }


def _save_case_iocs(session, case: AnalysisCase, indicators: Dict[str, Any]) -> None:
    values_by_type = {
        "IP": indicators.get("ips", []),
        "DOMAIN": indicators.get("domains", []),
        "URL": indicators.get("urls", []),
        "HASH": indicators.get("attachment_sha256", []),
    }
    for ioc_type, values in values_by_type.items():
        for value in dict.fromkeys(str(item).strip() for item in values if str(item).strip()):
            normalized = value.lower() if ioc_type in {"DOMAIN", "URL", "EMAIL"} else value
            ioc = session.scalar(select(IOC).where(IOC.ioc_type == ioc_type, IOC.value == normalized))
            if ioc is None:
                ioc = IOC(ioc_type=ioc_type, value=normalized, source="email_analysis", confidence=1.0)
                session.add(ioc)
                session.flush()
            exists = session.scalar(select(CaseIOC).where(CaseIOC.case_id == case.id, CaseIOC.ioc_id == ioc.id))
            if exists is None:
                session.add(CaseIOC(case=case, ioc=ioc, source="forensic_report"))
