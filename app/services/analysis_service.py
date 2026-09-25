"""Reusable orchestration boundary for the existing forensic analysis pipeline."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from app import config
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


def _add_role(store: Dict[str, List[str]], domain: Optional[str], role: str) -> None:
    if domain:
        store.setdefault(domain.lower(), []).append(role)


def analyze_raw_email(raw: bytes, *, evidence_hash: Optional[str] = None, analysis_id: Optional[str] = None) -> Dict[str, Any]:
    """Run all existing analysis stages and return the forensic response.

    Network lookups are bounded by their service timeouts and URLs are never fetched.
    """
    parsed = email_parser.parse_email(raw)
    warnings: List[str] = []
    if not parsed["headers_present"]:
        warnings.append("No email headers found; identity, relay and authentication analysis are limited.")
    elif not parsed["received"]:
        warnings.append("No Received headers found; relay chain and origin IP are unavailable.")
    if not parsed["body_text"] and not parsed["subject"]:
        raise ValueError("Could not extract any subject or body from the input.")

    nlp = nlp_service.analyze_text(f"{parsed['subject'] or ''}\n{parsed['body_text']}")
    identity = header_analyzer.analyze_identity(parsed)
    relay = header_analyzer.analyze_received(parsed)
    auth = header_analyzer.analyze_authentication(parsed)
    urls = url_analyzer.analyze_urls(parsed["urls"])

    sender_domains: Dict[str, List[str]] = {}
    _add_role(sender_domains, identity["from_domain"], "sender")
    _add_role(sender_domains, identity["reply_to_domain"], "reply_to")
    _add_role(sender_domains, identity["return_path_domain"], "return_path")
    lookalike_input = {domain: list(roles) for domain, roles in sender_domains.items()}
    dns_input = {domain: list(roles) for domain, roles in sender_domains.items()}
    for url in urls:
        if url["domain"] and not url["ip_based"]:
            _add_role(lookalike_input, url["domain"], "url")
            if len(dns_input) < 6:
                _add_role(dns_input, url["domain"], "url")
    lookalikes = domain_analyzer.analyze_lookalikes(lookalike_input)

    with ThreadPoolExecutor(max_workers=2) as pool:
        geo_future = pool.submit(ip_intelligence.geolocate_relay, relay, parsed["body_ips"])
        dns_future = pool.submit(dns_service.lookup_domains, dns_input)
        geolocation = geo_future.result()
        domain_intel = dns_future.result()

    risk = risk_engine.compute_risk(nlp, urls, identity, auth, lookalikes)
    classification = nlp["classification"]
    if classification == "legitimate" and risk["risk_level"] in ("High", "Critical"):
        classification = "suspicious"

    ips: List[str] = []
    for ip in [hop["from_ip"] for hop in relay["relay_chain"]] + parsed["body_ips"]:
        if ip and ip_intelligence.is_public_ip(ip) and ip not in ips:
            ips.append(ip)
    domains: List[str] = []
    for domain in list(sender_domains) + [url["domain"] for url in urls if url["domain"] and not url["ip_based"]]:
        if domain not in domains:
            domains.append(domain)

    return {
        "analysis_id": analysis_id or str(uuid.uuid4()),
        "evidence": {"sha256": evidence_hash, "size_bytes": len(raw), "raw_content_stored": False},
        "email_summary": {
            "subject": parsed["subject"], "from": parsed["from"], "to": parsed["to"],
            "reply_to": parsed["reply_to"], "return_path": parsed["return_path"],
            "date": parsed["date"], "message_id": parsed["message_id"],
            "mime_info": parsed["mime_info"], "attachments": parsed["attachments"],
        },
        "threat_assessment": {
            "classification": classification, "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"], "reasons": risk["reasons"],
            "score_breakdown": risk["score_breakdown"], "disclaimer": risk["disclaimer"],
        },
        "nlp_analysis": {
            "confidence": nlp["confidence"], "keywords": nlp["keywords"],
            "social_engineering_indicators": nlp["social_engineering_indicators"],
            "class_probabilities": nlp["class_probabilities"],
            "heuristic_flags": nlp["heuristic_flags"], "heuristic_matches": nlp["heuristic_matches"],
        },
        "identity_analysis": {
            "identity_mismatch": identity["identity_mismatch"], "lookalike_domain": bool(lookalikes),
            "matched_brand": lookalikes[0]["brand_name"] if lookalikes else None,
            "display_name": identity["display_name"], "indicators": identity["indicators"],
            "lookalike_details": lookalikes,
        },
        "authentication": auth,
        "url_analysis": urls,
        "relay_analysis": {
            "probable_origin_ip": relay["probable_origin_ip"],
            "probable_origin_note": relay["probable_origin_note"], "hop_count": relay["hop_count"],
            "chain_order": relay["chain_order"], "path_summary": relay["path_summary"],
            "relay_chain": relay["relay_chain"],
        },
        "geolocation": geolocation,
        "domain_intelligence": domain_intel,
        "indicators_of_compromise": {
            "ips": ips, "domains": domains, "urls": [url["url"] for url in urls],
            "attachment_sha256": [attachment["sha256"] for attachment in parsed["attachments"]],
        },
        "explanation": risk["explanation"], "warnings": warnings,
    }
