"""Header forensics: sender identity checks, Received-chain parsing, SPF/DKIM/DMARC extraction."""
from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any, Dict, List, Optional

import dkim
import spf
import dns.resolver

from app.services.domain_analyzer import BRAND_INFO, domain_of, registrable_domain

ORIGIN_NOTE = (
    "The earliest public IP found in the Received headers. Received headers can be forged by the sender "
    "and only reflect mail infrastructure, so this is NOT proof of the attacker's location or identity."
)
AUTH_NOTE = (
    "Values are read from the Authentication-Results / Received-SPF headers added by the receiving mail "
    "server. These header values are retained as receiver evidence and can be forged if the message did not "
    "pass through a trusted receiver; independent_validation contains fresh DNS, SPF, DMARC, and DKIM checks."
)


# --------------------------------------------------------------------------- identity
def analyze_identity(parsed: Dict[str, Any]) -> Dict[str, Any]:
    display, from_addr = parseaddr(parsed.get("from") or "")
    _, reply_addr = parseaddr(parsed.get("reply_to") or "")
    _, return_addr = parseaddr(parsed.get("return_path") or "")

    from_domain = domain_of(from_addr)
    reply_domain = domain_of(reply_addr)
    return_domain = domain_of(return_addr)
    from_reg = registrable_domain(from_domain)

    indicators: List[str] = []
    flags = {"reply_to_mismatch": False, "return_path_mismatch": False, "display_name_impersonation": False}

    if reply_domain and registrable_domain(reply_domain) != from_reg:
        flags["reply_to_mismatch"] = True
        indicators.append("Reply-To differs from sender domain")

    if return_domain and registrable_domain(return_domain) != from_reg:
        flags["return_path_mismatch"] = True
        indicators.append("Return-Path differs from sender domain (can be normal for bulk mail providers)")

    # display name claims to be a well-known brand but the domain is not that brand's
    impersonated: Optional[str] = None
    display_l = (display or "").lower()
    for info in BRAND_INFO.values():
        if any(re.search(rf"\b{re.escape(k)}\b", display_l) for k in info["keywords"]):
            if from_reg and from_reg not in info["legit"]:
                impersonated = info["name"]
                flags["display_name_impersonation"] = True
                indicators.append(
                    f"Display name references {info['name']} but sender domain is {from_domain}"
                )
                indicators.append("Possible impersonation")
                break

    # display name contains an email address for a different domain (classic spoof)
    m = re.search(r"[\w.+-]+@([\w.-]+\.\w+)", display or "")
    if m and registrable_domain(m.group(1).lower()) != from_reg:
        indicators.append("Display name contains an email address from a different domain")
        flags["display_name_impersonation"] = True

    if not from_addr:
        indicators.append("Missing or unparseable From address")

    return {
        "display_name": display or None,
        "from": from_addr or None,
        "reply_to": reply_addr or None,
        "return_path": return_addr or None,
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_domain,
        "impersonated_brand": impersonated,
        "identity_mismatch": any(flags.values()),
        "flags": flags,
        "indicators": indicators,
    }


# --------------------------------------------------------------------------- received chain
_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_PLAIN_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _valid_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _extract_ip(clause: str) -> Optional[str]:
    for m in _BRACKET_IP.finditer(clause):
        ip = _valid_ip(m.group(1))
        if ip:
            return ip
    for m in _PLAIN_IPV4.finditer(clause):
        ip = _valid_ip(m.group(0))
        if ip:
            return ip
    return None


def _is_public(ip: Optional[str]) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _parse_received(raw: str) -> Dict[str, Any]:
    text = re.sub(r"\s+", " ", raw).strip()
    body, _, date_part = text.rpartition(";")
    if not body:
        body, date_part = text, ""

    ts_iso, ts_raw = None, date_part.strip() or None
    if ts_raw:
        try:
            ts_iso = parsedate_to_datetime(ts_raw).isoformat()
        except (TypeError, ValueError):
            ts_iso = None

    from_m = re.search(r"\bfrom\s+(\S+)", body, re.I)
    by_m = re.search(r"\bby\s+(\S+)", body, re.I)
    with_m = re.search(r"\bwith\s+(\S+)", body, re.I)

    from_clause = ""
    if from_m:
        end = by_m.start() if by_m and by_m.start() > from_m.start() else len(body)
        from_clause = body[from_m.start():end]

    from_host = from_m.group(1).strip("[]();") if from_m else None
    from_ip = _extract_ip(from_clause)
    return {
        "from_host": from_host,
        "from_ip": from_ip,
        "from_ip_is_public": _is_public(from_ip),
        "by_host": by_m.group(1).strip("[]();") if by_m else None,
        "protocol": with_m.group(1) if with_m else None,
        "timestamp": ts_iso,
        "timestamp_raw": ts_raw,
    }


def analyze_received(parsed: Dict[str, Any]) -> Dict[str, Any]:
    headers = parsed.get("received") or []
    # Received headers are prepended by each server, so the LAST one in the file is the OLDEST hop.
    hops = [_parse_received(h) for h in reversed(headers)]
    for i, hop in enumerate(hops, 1):
        hop["hop"] = i
    chain = [
        {k: hop[k] for k in ("hop", "from_host", "from_ip", "from_ip_is_public", "by_host",
                             "protocol", "timestamp", "timestamp_raw")}
        for hop in hops
    ]

    origin = next((h["from_ip"] for h in chain if h["from_ip"] and h["from_ip_is_public"]), None)
    origin_public = origin is not None
    if origin is None:
        origin = next((h["from_ip"] for h in chain if h["from_ip"]), None)
    if origin is None and parsed.get("x_originating_ip"):
        cand = _valid_ip(parsed["x_originating_ip"].strip("[] "))
        origin = cand
        origin_public = _is_public(cand)

    # human readable path, oldest -> newest
    path: List[str] = []
    if chain:
        first = chain[0]
        host, ip = first["from_host"] or "unknown", first["from_ip"]
        path.append(host if not ip or host == ip else f"{host} [{ip}]")
        path.extend(h["by_host"] or "unknown" for h in chain)

    return {
        "probable_origin_ip": origin,
        "probable_origin_ip_is_public": origin_public if origin else None,
        "probable_origin_note": ORIGIN_NOTE,
        "hop_count": len(chain),
        "chain_order": "oldest_first",
        "relay_chain": chain,
        "path_summary": " -> ".join(path) if path else None,
    }


# --------------------------------------------------------------------------- SPF / DKIM / DMARC
def _domain_from_address(value: Optional[str]) -> Optional[str]:
    _, address = parseaddr(value or "")
    return address.rsplit("@", 1)[-1].lower().strip() if "@" in address else None


def _organizational_domain(domain: Optional[str]) -> Optional[str]:
    return registrable_domain(domain)


def _parse_dmarc_policy(domain: Optional[str]) -> Dict[str, Any]:
    if not domain:
        return {"status": "unknown", "reason": "From domain is unavailable"}
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=3.0)
        records = [b"".join(item.strings).decode("utf-8", errors="replace") for item in answers]
    except dns.resolver.NXDOMAIN:
        records = []
    except Exception as exc:
        return {"status": "temperror", "reason": f"DMARC DNS lookup failed: {type(exc).__name__}"}
    record = next((item for item in records if re.search(r"(?:^|;)\s*v=DMARC1", item, re.I)), None)
    if not record:
        return {"status": "none", "policy": "none", "record": None}
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            tags[key.lower()] = value.strip()
    return {
        "status": "found",
        "policy": tags.get("p", "none").lower(),
        "subdomain_policy": tags.get("sp", tags.get("p", "none")).lower(),
        "alignment_dkim": tags.get("adkim", "r").lower(),
        "alignment_spf": tags.get("aspf", "r").lower(),
        "percentage": tags.get("pct", "100"),
        "record": record,
    }


def _validate_spf(parsed: Dict[str, Any], from_domain: Optional[str], origin_ip: Optional[str]) -> Dict[str, Any]:
    envelope_domain = _domain_from_address(parsed.get("return_path")) or from_domain
    if not envelope_domain or not origin_ip:
        return {"status": "unknown", "domain": envelope_domain, "ip": origin_ip, "reason": "Envelope domain or public origin IP unavailable"}
    try:
        result, code, explanation = spf.check2(origin_ip, envelope_domain, "emailsentinel.local")
        return {"status": result.lower(), "domain": envelope_domain, "ip": origin_ip, "dns_code": code, "explanation": explanation}
    except Exception as exc:
        return {"status": "temperror", "domain": envelope_domain, "ip": origin_ip, "reason": f"SPF evaluation failed: {type(exc).__name__}"}


def _validate_dkim(raw: Optional[bytes], parsed: Dict[str, Any]) -> Dict[str, Any]:
    signatures = parsed.get("dkim_signature") or []
    domains = []
    for signature in signatures:
        match = re.search(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", signature, re.I)
        if match:
            domains.append(match.group(1).strip().lower())
    if not signatures:
        return {"status": "none", "signature_domains": []}
    if not raw:
        return {"status": "unknown", "signature_domains": domains, "reason": "Raw message unavailable for verification"}
    try:
        verified = bool(dkim.verify(raw))
        return {"status": "pass" if verified else "fail", "signature_domains": domains, "verified_cryptographically": verified}
    except Exception as exc:
        return {"status": "temperror", "signature_domains": domains, "reason": f"DKIM verification failed: {type(exc).__name__}"}


def analyze_authentication(parsed: Dict[str, Any], raw: Optional[bytes] = None, origin_ip: Optional[str] = None) -> Dict[str, Any]:
    seen: Dict[str, List[str]] = {"spf": [], "dkim": [], "dmarc": []}
    for header in parsed.get("authentication_results") or []:
        for mech, value in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", header, re.I):
            seen[mech.lower()].append(value.lower())

    source = "Authentication-Results" if any(seen.values()) else None
    result = {m: "unknown" for m in seen}
    for mech, values in seen.items():
        if values:
            # several DKIM signatures may exist: one pass is enough to call it pass
            result[mech] = "pass" if "pass" in values else values[0]

    if result["spf"] == "unknown" and parsed.get("received_spf"):
        m = re.match(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)", parsed["received_spf"], re.I)
        if m:
            result["spf"] = m.group(1).lower()
            source = source or "Received-SPF"

    from_domain = _domain_from_address(parsed.get("from"))
    spf_validation = _validate_spf(parsed, from_domain, origin_ip)
    dkim_validation = _validate_dkim(raw, parsed)
    dmarc_policy = _parse_dmarc_policy(from_domain)
    envelope_domain = spf_validation.get("domain")
    spf_aligned = (
        spf_validation.get("status") == "pass"
        and envelope_domain
        and from_domain
        and (_organizational_domain(envelope_domain) == _organizational_domain(from_domain)
             if dmarc_policy.get("alignment_spf", "r") == "r"
             else envelope_domain == from_domain)
    )
    dkim_aligned = any(
        dkim_validation.get("status") == "pass"
        and domain
        and from_domain
        and (_organizational_domain(domain) == _organizational_domain(from_domain)
             if dmarc_policy.get("alignment_dkim", "r") == "r"
             else domain == from_domain)
        for domain in dkim_validation.get("signature_domains", [])
    )
    dmarc_status = "pass" if dmarc_policy.get("status") == "found" and (spf_aligned or dkim_aligned) else (
        "fail" if dmarc_policy.get("status") == "found" else "none"
    )

    return {
        **result,
        "source": source or "none",
        "dkim_signature_present": bool(parsed.get("dkim_signature")),
        "note": AUTH_NOTE,
        "independent_validation": {
            "spf": spf_validation,
            "dkim": dkim_validation,
            "dmarc": {
                **dmarc_policy,
                "status": dmarc_status,
                "from_domain": from_domain,
                "spf_aligned": bool(spf_aligned),
                "dkim_aligned": bool(dkim_aligned),
            },
        },
        "validation_note": "Independent checks use DNS and DKIM cryptographic verification; results can fail when DNS, keys, or the original message are unavailable.",
    }
