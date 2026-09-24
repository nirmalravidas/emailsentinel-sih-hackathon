"""API routes. The analysis pipeline is orchestrated in analyze_email()."""
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile

from app import config
from app.database import database
from app.models.schemas import AnalysisResponse, CasesResponse, NLPRequest, NLPResponse
from app.services import (
    dns_service,
    domain_analyzer,
    email_parser,
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
    response_model=AnalysisResponse,
    tags=["Analysis"],
    summary="Analyze a raw email (.eml upload or pasted raw text)",
)
def analyze_email(
    file: Optional[UploadFile] = File(None, description="A .eml file to analyze"),
    raw_email: Optional[str] = Form(None, description="OR paste the full raw email (headers + body) here"),
):
    """Run the full EmailSentinel pipeline and return one JSON forensic result.

    Provide **either** an `.eml` file **or** `raw_email` text. If both are given the file wins.
    URLs are never opened; only DNS and IP-geolocation lookups leave the server.
    """
    raw: Optional[bytes] = None
    if file is not None and file.filename:
        raw = file.file.read(config.MAX_EMAIL_BYTES + 1)
    elif raw_email and raw_email.strip():
        raw = raw_email.encode("utf-8", errors="replace")

    if not raw:
        raise HTTPException(status_code=400, detail="Provide an .eml file or raw_email text.")
    if len(raw) > config.MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail=f"Email larger than {config.MAX_EMAIL_BYTES} bytes.")

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
    auth = header_analyzer.analyze_authentication(parsed)

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

    analysis_id = str(uuid.uuid4())
    response = {
        "analysis_id": analysis_id,
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
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "subject": parsed["subject"],
            "sender": parsed["from"],
            "classification": classification,
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "probable_origin_ip": relay["probable_origin_ip"],
        }
    )
    return response


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
