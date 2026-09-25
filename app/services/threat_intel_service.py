"""Optional reputation and infrastructure correlation providers.

All providers are best-effort. They never become the source of truth and never block core analysis.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List
import dns.exception
import dns.resolver
import httpx

from app import config
from app.services import cache_service

logger = logging.getLogger("emailsentinel.threat_intel")
_tor_cache: set[str] | None = None


def _disabled() -> Dict[str, Any]:
    return {"status": "disabled", "message": "Threat-intelligence providers are disabled"}


def _tor_exits() -> set[str]:
    global _tor_cache
    if _tor_cache is not None:
        return _tor_cache
    cached = cache_service.get_json("threat-intel:tor-exits")
    if isinstance(cached, list):
        _tor_cache = {str(item) for item in cached}
        return _tor_cache
    try:
        response = httpx.get(config.TOR_EXIT_LIST_URL, timeout=config.THREAT_INTEL_TIMEOUT)
        response.raise_for_status()
        _tor_cache = {line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")}
        cache_service.set_json("threat-intel:tor-exits", sorted(_tor_cache), 3600)
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Tor exit-list lookup failed: %s", exc)
        _tor_cache = set()
    return _tor_cache


def _dnsbl(ip: str) -> Dict[str, Any]:
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        answers = dns.resolver.resolve(f"{reversed_ip}.{config.THREAT_INTEL_DNSBL}", "A", lifetime=config.DNS_TIMEOUT)
        return {"listed": True, "dnsbl": config.THREAT_INTEL_DNSBL, "codes": [answer.to_text() for answer in answers]}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"listed": False, "dnsbl": config.THREAT_INTEL_DNSBL}
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return {"status": "lookup_failed", "dnsbl": config.THREAT_INTEL_DNSBL}
    except Exception as exc:
        return {"status": "lookup_failed", "reason": type(exc).__name__}


def _abuseipdb(ip: str) -> Dict[str, Any]:
    if not config.ABUSEIPDB_API_KEY:
        return {"status": "not_configured"}
    try:
        response = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Accept": "application/json", "Key": config.ABUSEIPDB_API_KEY},
            timeout=config.THREAT_INTEL_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "status": "ok",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "is_tor": data.get("isTor"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_hosting_or_proxy": data.get("usageType") in {"Data Center/Web Hosting/Transit", "Search Engine Spider", "Content Server"},
            "source": "AbuseIPDB",
        }
    except (httpx.HTTPError, ValueError) as exc:
        return {"status": "lookup_failed", "source": "AbuseIPDB", "reason": type(exc).__name__}


def lookup_ip(ip: str) -> Dict[str, Any]:
    if not config.THREAT_INTEL_ENABLED:
        return {"ip": ip, **_disabled()}
    try:
        if not ipaddress.ip_address(ip).is_global:
            return {"ip": ip, "status": "not_public"}
    except ValueError:
        return {"ip": ip, "status": "invalid"}
    abuse = _abuseipdb(ip)
    dnsbl = _dnsbl(ip)
    tor = ip in _tor_exits()
    return {
        "ip": ip,
        "status": "listed" if tor or dnsbl.get("listed") else "not_listed",
        "tor_exit_node": tor,
        "open_relay_or_abuse_dnsbl": dnsbl,
        "reputation": abuse,
        "botnet_or_malware": _threatfox(ip),
    }


def _threatfox(value: str) -> Dict[str, Any]:
    try:
        response = httpx.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": value},
            timeout=config.THREAT_INTEL_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        indicators = payload.get("data") or []
        return {
            "status": "listed" if indicators else "not_listed",
            "source": "ThreatFox",
            "indicators": indicators[:10],
        }
    except (httpx.HTTPError, ValueError) as exc:
        return {"status": "lookup_failed", "source": "ThreatFox", "reason": type(exc).__name__}


def _urlhaus(value: str, kind: str) -> Dict[str, Any]:
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/" if kind == "url" else "https://urlhaus-api.abuse.ch/v1/host/"
    field = "url" if kind == "url" else "host"
    try:
        response = httpx.post(endpoint, data={field: value}, timeout=config.THREAT_INTEL_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        return {"status": "malicious" if payload.get("query_status") == "ok" else "not_found", "source": "URLhaus", "details": payload}
    except (httpx.HTTPError, ValueError) as exc:
        return {"status": "lookup_failed", "source": "URLhaus", "reason": type(exc).__name__}


def lookup_indicators(ips: List[str], domains: List[str], urls: List[str]) -> Dict[str, Any]:
    if not config.THREAT_INTEL_ENABLED:
        return {"status": "disabled", "message": "Enable THREAT_INTEL_ENABLED for reputation and infrastructure correlation", "ips": [], "domains": [], "urls": []}
    ip_results = [lookup_ip(ip) for ip in dict.fromkeys(ips)]
    domain_results = [{"domain": domain, "reputation": _urlhaus(domain, "domain"), "botnet_or_malware": _threatfox(domain)} for domain in dict.fromkeys(domains)]
    url_results = [{"url": url, "reputation": _urlhaus(url, "url"), "botnet_or_malware": _threatfox(url)} for url in dict.fromkeys(urls)]
    return {
        "status": "completed",
        "providers": ["Tor bulk exit list", config.THREAT_INTEL_DNSBL, "URLhaus", "ThreatFox"] + (["AbuseIPDB"] if config.ABUSEIPDB_API_KEY else []),
        "ips": ip_results,
        "domains": domain_results,
        "urls": url_results,
        "disclaimer": "Reputation feeds are external indicators, may be incomplete or stale, and do not prove attribution.",
    }