"""Explainable additive risk scoring (0-100).

Each signal adds a fixed number of points; the maximum for every group is listed below and the groups
add up to exactly 100:

    NLP model threat probability ........ 30  (30 x P(not legitimate))
    NLP heuristic indicators ............ 15  (urgency 4, credential 4, financial 3, suspension 2, impersonation 1, CTA 1)
    URL indicators ...................... 15  (insecure HTTP 3, suspicious keywords 6, IP/obfuscation/shortener 6)
    Identity mismatch ................... 15  (Reply-To 7, brand in display name 5, Return-Path 3)
    Authentication ...................... 15  (SPF fail 6 / softfail 3, DKIM fail 4, DMARC fail 5)
    Lookalike domain .................... 10

The weights are hand-picked for demonstration. The score is NOT a scientifically validated probability.
"""
from __future__ import annotations

from typing import Any, Dict, List

DISCLAIMER = (
    "Risk score is a heuristic, hand-weighted sum of explainable signals. It is not a scientifically "
    "validated probability and should support, not replace, analyst judgement."
)

HEURISTIC_WEIGHTS = {
    "urgency": (4, "Urgent / time-pressure language detected"),
    "credential_request": (4, "Request for credentials or personal verification detected"),
    "financial_request": (3, "Financial or payment request language detected"),
    "account_suspension": (2, "Account suspension / lock threat detected"),
    "impersonation_language": (1, "Impersonation-style wording (e.g. 'Security Team') detected"),
    "suspicious_cta": (1, "Suspicious call-to-action (e.g. 'click here') detected"),
}


def risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def compute_risk(
    nlp: Dict[str, Any],
    urls: List[Dict[str, Any]],
    identity: Dict[str, Any],
    auth: Dict[str, Any],
    lookalikes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    breakdown: List[Dict[str, Any]] = []
    reasons: List[str] = []
    explanation: List[str] = []

    def add(signal: str, points: int, maximum: int, reason: str, short: str) -> None:
        breakdown.append({"signal": signal, "points": points, "max_points": maximum, "reason": reason})
        if points > 0:
            reasons.append(reason)
            if short not in explanation:
                explanation.append(short)

    # ---- 1. NLP model
    probs = nlp.get("class_probabilities") or {}
    threat_p = 1.0 - probs.get("legitimate", 1.0) if probs else 0.0
    nlp_points = round(30 * threat_p)
    label = nlp.get("classification", "unknown")
    reason = (
        f"NLP model detected {label} language (threat probability {threat_p:.2f})"
        if threat_p >= 0.5
        else f"NLP model found weak threat signal (threat probability {threat_p:.2f})"
    )
    add("nlp_model", nlp_points, 30, reason, "Phishing-like language detected" if threat_p >= 0.5 else "Weak language signals")
    if threat_p < 0.5 and explanation and explanation[-1] == "Weak language signals":
        explanation.pop()  # a weak signal is not worth an explanation line

    # ---- 2. NLP heuristics
    flags = nlp.get("heuristic_flags") or {}
    h_points = 0
    for key, (pts, text) in HEURISTIC_WEIGHTS.items():
        if flags.get(key):
            h_points += pts
            add(f"heuristic_{key}", pts, pts, text, "Social-engineering language detected")
    if h_points == 0:
        add("heuristics", 0, 15, "No social-engineering phrases detected", "")

    # ---- 3. URLs
    suspicious = [u for u in urls if u["suspicious"]]
    if urls:
        if any(not u["uses_https"] for u in urls):
            add("url_http", 3, 3, "URL uses insecure HTTP", "Suspicious URL detected")
        kw_urls = [u for u in urls if u["keywords_found"]]
        if kw_urls:
            kws = sorted({k for u in kw_urls for k in u["keywords_found"]})
            add("url_keywords", 6, 6, f"Suspicious URL detected (keywords: {', '.join(kws)})", "Suspicious URL detected")
        evasive = [u for u in urls if u["ip_based"] or u["obfuscation_detected"]
                   or any(i in ("URL shortener",) or i.startswith("Suspicious TLD") for i in u["risk_indicators"])]
        if evasive:
            add("url_evasion", 6, 6, "URL uses IP address, obfuscation, shortener or risky TLD", "Obfuscated URL detected")
    if not suspicious:
        breakdown.append({"signal": "urls", "points": 0, "max_points": 15, "reason": "No suspicious URLs"})

    # ---- 4. Identity
    iflags = identity.get("flags", {})
    if iflags.get("reply_to_mismatch"):
        add("reply_to_mismatch", 7, 7, "Reply-To domain differs from sender", "Sender identity mismatch detected")
    if iflags.get("display_name_impersonation"):
        brand = identity.get("impersonated_brand")
        txt = f"Display name impersonates {brand}" if brand else "Display name contains a conflicting email address"
        add("display_name_impersonation", 5, 5, txt, "Sender identity mismatch detected")
    if iflags.get("return_path_mismatch"):
        add("return_path_mismatch", 3, 3, "Return-Path domain differs from sender", "Sender identity mismatch detected")

    # ---- 5. Authentication
    independent = auth.get("independent_validation") or {}
    spf = (independent.get("spf") or {}).get("status", auth.get("spf"))
    dkim = (independent.get("dkim") or {}).get("status", auth.get("dkim"))
    dmarc = (independent.get("dmarc") or {}).get("status", auth.get("dmarc"))
    if spf == "fail":
        add("spf_fail", 6, 6, "SPF authentication failed", "Email authentication failed")
    elif spf == "softfail":
        add("spf_softfail", 3, 3, "SPF soft-failed", "Email authentication failed")
    if dkim == "fail":
        add("dkim_fail", 4, 4, "DKIM authentication failed", "Email authentication failed")
    if dmarc == "fail":
        add("dmarc_fail", 5, 5, "DMARC authentication failed", "Email authentication failed")

    # ---- 6. Lookalike domain
    if lookalikes:
        top = lookalikes[0]
        add(
            "lookalike_domain", 10, 10,
            f"Domain {top['domain']} resembles {top['brand_name']} ({top['matched_brand']}), similarity {top['similarity']}",
            "Suspicious domain detected",
        )

    score = max(0, min(100, sum(b["points"] for b in breakdown)))
    return {
        "risk_score": score,
        "risk_level": risk_level(score),
        "reasons": reasons or ["No significant threat indicators detected"],
        "explanation": [e for e in explanation if e] or ["No significant threat indicators detected"],
        "score_breakdown": [b for b in breakdown if b["points"] > 0],
        "disclaimer": DISCLAIMER,
        "nlp_threat_probability": round(threat_p, 3),
    }
