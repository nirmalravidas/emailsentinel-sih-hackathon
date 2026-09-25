"""Basic DNS intelligence (A / MX / TXT) using dnspython, plus optional WHOIS.

DNS records are context, not a maliciousness verdict, and are never used in the risk score.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List

import dns.exception
import dns.resolver

from app import config
from app.services import cache_service

logger = logging.getLogger("emailsentinel.dns")
RECORD_TYPES = ("A", "MX", "TXT")


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = config.DNS_TIMEOUT
    r.lifetime = config.DNS_TIMEOUT
    return r


def _query(domain: str, rtype: str) -> Dict[str, Any]:
    cache_key = f"domain:dns:{rtype}:{domain.lower()}"
    cached = cache_service.get_json(cache_key)
    if isinstance(cached, dict):
        return cached
    try:
        answers = _resolver().resolve(domain, rtype)
        values: List[str] = []
        for rdata in answers:
            if rtype == "MX":
                values.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
            elif rtype == "TXT":
                values.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
            else:
                values.append(rdata.to_text())
        result = {"values": values}
        cache_service.set_json(cache_key, result, config.REDIS_DNS_TTL)
        return result
    except dns.resolver.NXDOMAIN:
        result = {"values": [], "error": "NXDOMAIN (domain does not exist)"}
        cache_service.set_json(cache_key, result, config.REDIS_DNS_TTL)
        return result
    except dns.resolver.NoAnswer:
        result = {"values": []}
        cache_service.set_json(cache_key, result, config.REDIS_DNS_TTL)
        return result
    except dns.exception.Timeout:
        return {"values": [], "error": "timeout"}
    except dns.resolver.NoNameservers:
        return {"values": [], "error": "no nameservers available"}
    except Exception as exc:  # e.g. no resolver configuration in a sandbox
        return {"values": [], "error": f"{type(exc).__name__}: {exc}"}


def _whois(domain: str) -> Dict[str, Any]:
    try:
        import whois  # python-whois, imported lazily because it is optional

        data = whois.whois(domain)
        created = data.creation_date
        if isinstance(created, list):
            created = created[0]
        info: Dict[str, Any] = {"registrar": data.registrar, "creation_date": str(created) if created else None}
        if isinstance(created, datetime):
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            info["domain_age_days"] = (datetime.now(timezone.utc) - created).days
        return info
    except Exception as exc:
        return {"error": f"whois unavailable: {type(exc).__name__}"}


def lookup_domains(domain_roles: Dict[str, List[str]]) -> Dict[str, Any]:
    """domain_roles maps a domain to the roles it played in the email (sender, reply_to, url, ...)."""
    note = ("DNS/WHOIS data is contextual information only and is not used as a maliciousness verdict.")
    if not domain_roles:
        return {"note": note, "domains": []}
    if not config.ENABLE_DNS:
        return {"note": note, "status": "disabled", "domains": [
            {"domain": d, "roles": sorted(set(r))} for d, r in domain_roles.items()]}

    domains = list(domain_roles)
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {(d, t): pool.submit(_query, d, t) for d in domains for t in RECORD_TYPES}
        whois_futures = {d: pool.submit(_whois, d) for d in domains} if config.ENABLE_WHOIS else {}

        out = []
        for d in domains:
            dns_records: Dict[str, List[str]] = {}
            errors: Dict[str, str] = {}
            for t in RECORD_TYPES:
                res = futures[(d, t)].result()
                dns_records[t] = res["values"]
                if "error" in res:
                    errors[t] = res["error"]
            entry: Dict[str, Any] = {"domain": d, "roles": sorted(set(domain_roles[d])), "dns": dns_records}
            if errors:
                entry["dns_errors"] = errors
            if d in whois_futures:
                entry["whois"] = whois_futures[d].result()
            out.append(entry)
    return {"note": note, "domains": out}
