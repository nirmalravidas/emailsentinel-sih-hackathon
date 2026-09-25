"""API routes. The analysis pipeline is orchestrated in analyze_email()."""
import logging
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import JSONResponse, Response

from app import config
from app.database import database
from app.models.schemas import AnalysisResponse, AnalysisStatusResponse, CampaignCaseAttach, CampaignCreate, CaseStatusUpdate, CasesResponse, NLPRequest, NLPResponse
from app.services import analysis_service
from app.services import alert_service
from app.services import report_service
from app.services import privacy_service
from app.workers.tasks import analyze_email_task
from app.services import (
    dns_service,
    domain_analyzer,
    email_parser,
    evidence_service,
    header_analyzer,
    ip_intelligence,
    nlp_service,
    risk_engine,
    url_analyzer,
)

logger = logging.getLogger("emailsentinel.api")
router = APIRouter()


def _add_role(store: Dict[str, List[str]], domain: Optional[str], role: str) -> None:
    if domain:
        store.setdefault(domain.lower(), []).append(role)


@router.post(
    "/analyze-email",
    response_model=None,
    tags=["Analysis"],
    summary="Analyze a raw email (.eml upload or pasted raw text)",
)
def analyze_email(
    file: Optional[UploadFile] = File(None, description="A .eml file to analyze"),
    raw_email: Optional[str] = Form(None, description="OR paste the full raw email (headers + body) here"),
):
    """Run the shared EmailSentinel pipeline and persist one forensic result.

    Provide **either** an `.eml` file **or** `raw_email` text. If both are given the file wins.
    URLs are never opened; only DNS and IP-geolocation lookups leave the server.
    """
    raw: Optional[bytes] = None
    original_filename: Optional[str] = None
    if file is not None and file.filename:
        try:
            original_filename = evidence_service.safe_filename(file.filename)
        except evidence_service.InvalidEvidenceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        raw = file.file.read(config.MAX_EMAIL_BYTES + 1)
    elif raw_email and raw_email.strip():
        raw = raw_email.encode("utf-8", errors="replace")

    if not raw:
        raise HTTPException(status_code=400, detail="Provide an .eml file or raw_email text.")
    if len(raw) > config.MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail=f"Email larger than {config.MAX_EMAIL_BYTES} bytes.")
    evidence_hash = evidence_service.sha256_digest(raw)

    analysis_id = str(uuid.uuid4())
    if config.ASYNC_ANALYSIS_ENABLED:
        database.save_case({
            "analysis_id": analysis_id,
            "status": "QUEUED",
            "subject": None,
            "sender": None,
            "raw_email_hash": evidence_hash,
            "original_filename": original_filename,
            "raw_email_size": len(raw),
        })
        task = analyze_email_task.delay(
            analysis_id,
            base64.b64encode(raw).decode("ascii"),
            evidence_hash,
            original_filename,
        )
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "case_id": analysis_id,
                "analysis_id": analysis_id,
                "task_id": task.id,
                "status": "QUEUED",
            },
        )

    try:
        response = analysis_service.analyze_raw_email(
            raw,
            evidence_hash=evidence_hash,
            analysis_id=analysis_id,
            original_filename=original_filename,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    assessment = response["threat_assessment"]
    email_summary = response["email_summary"]
    stored_response = privacy_service.mask_report(response)
    database.save_case({
        "analysis_id": analysis_id,
        "status": "COMPLETED",
        "subject": email_summary["subject"],
        "sender": email_summary["from"],
        "classification": assessment["classification"],
        "risk_score": assessment["risk_score"],
        "risk_level": assessment["risk_level"],
        "probable_origin_ip": response["relay_analysis"]["probable_origin_ip"],
        "raw_email_hash": evidence_hash,
        "original_filename": original_filename,
        "raw_email_size": len(raw),
        "forensic_report": stored_response,
        "indicators_of_compromise": response["indicators_of_compromise"],
    })
    alert_service.maybe_create_risk_alert(analysis_id, assessment["risk_level"], assessment["risk_score"])
    return stored_response

    # 1. parse -------------------------------------------------------------
    parsed = email_parser.parse_email(raw)
    warnings: List[str] = []
    if not parsed["headers_present"]:
        warnings.append("No email headers found; identity, relay and authentication analysis are limited.")
    elif not parsed["received"]:
        warnings.append("No Received headers found; relay chain and origin IP are unavailable.")
    if not parsed["body_text"] and not parsed["subject"]:
        raise HTTPException(status_code=422, detail="Could not extract any subject or body from the input.")

    # 2. NLP ---------------------------------------------------------------
    nlp = nlp_service.analyze_text(f"{parsed['subject'] or ''}\n{parsed['body_text']}")

    # 3. headers -----------------------------------------------------------
    identity = header_analyzer.analyze_identity(parsed)
    relay = header_analyzer.analyze_received(parsed)
    auth = header_analyzer.analyze_authentication(raw=raw, parsed=parsed, origin_ip=relay["probable_origin_ip"])

    # 4. URLs --------------------------------------------------------------
    urls = url_analyzer.analyze_urls(parsed["urls"])

    # 5. domains / lookalikes ---------------------------------------------
    sender_domains: Dict[str, List[str]] = {}
    _add_role(sender_domains, identity["from_domain"], "sender")
    _add_role(sender_domains, identity["reply_to_domain"], "reply_to")
    _add_role(sender_domains, identity["return_path_domain"], "return_path")

    lookalike_input: Dict[str, List[str]] = {d: list(r) for d, r in sender_domains.items()}
    dns_input: Dict[str, List[str]] = {d: list(r) for d, r in sender_domains.items()}
    for u in urls:
        if u["domain"] and not u["ip_based"]:
            _add_role(lookalike_input, u["domain"], "url")
            if len(dns_input) < 6:
                _add_role(dns_input, u["domain"], "url")
    lookalikes = domain_analyzer.analyze_lookalikes(lookalike_input)

    # 6. network lookups (run in parallel; both fail gracefully) ------------
    with ThreadPoolExecutor(max_workers=2) as pool:
        geo_future = pool.submit(ip_intelligence.geolocate_relay, relay, parsed["body_ips"])
        dns_future = pool.submit(dns_service.lookup_domains, dns_input)
        geolocation = geo_future.result()
        domain_intel = dns_future.result()

    # 7. risk --------------------------------------------------------------
    risk = risk_engine.compute_risk(nlp, urls, identity, auth, lookalikes)
    classification = nlp["classification"]
    if classification == "legitimate" and risk["risk_level"] in ("High", "Critical"):
        classification = "suspicious"  # rules disagree with the ML model

    # 8. indicators of compromise ------------------------------------------
    ips: List[str] = []
    for ip in [h["from_ip"] for h in relay["relay_chain"]] + parsed["body_ips"]:
        if ip and ip_intelligence.is_public_ip(ip) and ip not in ips:
            ips.append(ip)
    domains: List[str] = []
    for d in list(sender_domains) + [u["domain"] for u in urls if u["domain"] and not u["ip_based"]]:
        if d not in domains:
            domains.append(d)
    iocs = {
        "ips": ips,
        "domains": domains,
        "urls": [u["url"] for u in urls],
        "attachment_sha256": [a["sha256"] for a in parsed["attachments"]],
    }

    response = {
        "analysis_id": analysis_id,
        "evidence": {
            "sha256": evidence_hash,
            "size_bytes": len(raw),
            "original_filename": original_filename,
            "raw_content_stored": False,
        },
        "email_summary": {
            "subject": parsed["subject"],
            "from": parsed["from"],
            "to": parsed["to"],
            "reply_to": parsed["reply_to"],
            "return_path": parsed["return_path"],
            "date": parsed["date"],
            "message_id": parsed["message_id"],
            "mime_info": parsed["mime_info"],
            "attachments": parsed["attachments"],
        },
        "threat_assessment": {
            "classification": classification,
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "reasons": risk["reasons"],
            "score_breakdown": risk["score_breakdown"],
            "disclaimer": risk["disclaimer"],
        },
        "nlp_analysis": {
            "confidence": nlp["confidence"],
            "keywords": nlp["keywords"],
            "social_engineering_indicators": nlp["social_engineering_indicators"],
            "class_probabilities": nlp["class_probabilities"],
            "heuristic_flags": nlp["heuristic_flags"],
            "heuristic_matches": nlp["heuristic_matches"],
        },
        "identity_analysis": {
            "identity_mismatch": identity["identity_mismatch"],
            "lookalike_domain": bool(lookalikes),
            "matched_brand": lookalikes[0]["brand_name"] if lookalikes else None,
            "display_name": identity["display_name"],
            "indicators": identity["indicators"],
            "lookalike_details": lookalikes,
        },
        "authentication": auth,
        "url_analysis": urls,
        "relay_analysis": {
            "probable_origin_ip": relay["probable_origin_ip"],
            "probable_origin_note": relay["probable_origin_note"],
            "hop_count": relay["hop_count"],
            "chain_order": relay["chain_order"],
            "path_summary": relay["path_summary"],
            "relay_chain": relay["relay_chain"],
        },
        "geolocation": geolocation,
        "domain_intelligence": domain_intel,
        "indicators_of_compromise": iocs,
        "explanation": risk["explanation"],
        "warnings": warnings,
    }

    database.save_case(
        {
            "analysis_id": analysis_id,
            "status": "COMPLETED",
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "subject": parsed["subject"],
            "sender": parsed["from"],
            "classification": classification,
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "probable_origin_ip": relay["probable_origin_ip"],
            "raw_email_hash": evidence_hash,
            "original_filename": original_filename,
            "raw_email_size": len(raw),
            "forensic_report": response,
            "indicators_of_compromise": iocs,
        }
    )
    alert_service.maybe_create_risk_alert(analysis_id, risk["risk_level"], risk["risk_score"])
    return response


@router.get(
    "/analysis/{analysis_id}",
    response_model=AnalysisStatusResponse,
    tags=["Analysis"],
    summary="Get queued analysis status and completed result metadata",
)
def analysis_status(analysis_id: str):
    case = database.get_case(analysis_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return {
        "analysis_id": analysis_id,
        "case_id": analysis_id,
        "status": case["status"],
        "result": case.get("forensic_report") if case["status"] == "COMPLETED" else None,
    }


@router.get("/cases/{case_id}", tags=["Cases"], summary="Get one analysis case")
def get_case(case_id: str):
    case = database.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.get("/cases/{case_id}/timeline", tags=["Cases"], summary="Get case forensic timeline")
def get_case_timeline(case_id: str):
    timeline = database.case_timeline(case_id)
    if timeline is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case_id": case_id, "events": timeline}


@router.get("/cases/{case_id}/iocs", tags=["Cases"], summary="Get indicators associated with a case")
def get_case_iocs(case_id: str):
    indicators = database.get_case_iocs(case_id)
    if indicators is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case_id": case_id, "iocs": indicators, "source": "database"}


@router.get("/cases/{case_id}/correlation", tags=["Cases"], summary="Correlate shared indicators with other cases")
def get_case_correlation(case_id: str):
    correlation = database.correlate_case_iocs(case_id)
    if correlation is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return correlation


@router.get("/cases/{case_id}/report", tags=["Cases"], summary="Get the complete forensic report")
def get_case_report(case_id: str):
    case = database.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if not case.get("forensic_report"):
        raise HTTPException(status_code=409, detail="Forensic report is not available yet")
    database.record_audit_event("REPORT_EXPORTED", "analysis_case", case_id)
    return case["forensic_report"]


@router.get("/cases/{case_id}/report.pdf", tags=["Cases"], summary="Download the forensic report as PDF")
def download_case_report_pdf(case_id: str):
    case = database.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    report = case.get("forensic_report")
    if not report:
        raise HTTPException(status_code=409, detail="Forensic report is not available yet")
    database.record_audit_event("REPORT_PDF_EXPORTED", "analysis_case", case_id)
    filename = f"emailsentinel-report-{case_id}.pdf"
    return Response(
        content=report_service.build_pdf(report),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.patch("/cases/{case_id}/status", tags=["Cases"], summary="Update case workflow status")
def update_case_status(case_id: str, update: CaseStatusUpdate):
    case = database.update_case_status(case_id, update.status, update.analyst_notes)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.get("/alerts", tags=["Alerts"], summary="List recorded risk alerts")
def list_alerts(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return {"limit": limit, "offset": offset, "alerts": database.list_alerts(limit, offset)}


@router.get("/alerts/{alert_id}", tags=["Alerts"], summary="Get one recorded alert")
def get_alert(alert_id: int):
    alert = database.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/campaigns", tags=["Campaigns"], summary="Create an investigation campaign")
def create_campaign(body: CampaignCreate):
    return database.create_campaign(body.name, body.description, body.risk_level)


@router.get("/campaigns", tags=["Campaigns"], summary="List investigation campaigns")
def list_campaigns(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return {"limit": limit, "offset": offset, "campaigns": database.list_campaigns(limit, offset)}


@router.get("/campaigns/{campaign_id}", tags=["Campaigns"], summary="Get campaign cases and indicators")
def get_campaign(campaign_id: str):
    campaign = database.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.post("/campaigns/{campaign_id}/cases/{case_id}", tags=["Campaigns"], summary="Attach a case to a campaign")
def attach_campaign_case(campaign_id: str, case_id: str, body: CampaignCaseAttach | None = None):
    campaign = database.attach_case_to_campaign(campaign_id, case_id, body.similarity_score if body else None)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign or case not found")
    return campaign


@router.post("/nlp/analyze", response_model=NLPResponse, tags=["NLP"], summary="Classify a piece of text")
def nlp_analyze(body: NLPRequest):
    """Test the NLP module on its own (TF-IDF + Logistic Regression, plus heuristic indicators)."""
    r = nlp_service.analyze_text(body.text)
    return {
        "classification": r["classification"],
        "confidence": r["confidence"],
        "indicators": r["social_engineering_indicators"],
        "keywords": r["keywords"],
        "class_probabilities": r["class_probabilities"],
    }


@router.get("/cases", response_model=CasesResponse, tags=["Cases"], summary="List stored analysis cases")
def list_cases(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    """Basic metadata for previous analyses (newest first). Full emails are not stored."""
    return {
        "total": database.count_cases(),
        "limit": limit,
        "offset": offset,
        "cases": database.list_cases(limit, offset),
    }
