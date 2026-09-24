"""IP geolocation via a free public service (ip-api.com by default).

Geolocation describes where an IP address is registered/hosted (infrastructure). It does NOT tell you
where the attacker is or who they are. Private/reserved IPs are never sent to the service.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional

import httpx

from app import config

logger = logging.getLogger("emailsentinel.ip")

DISCLAIMER = (
    "IP geolocation indicates the approximate location of network infrastructure (mail servers, VPNs, "
    "hosting providers), not the physical location or identity of the attacker."
)
_cache: Dict[str, Dict[str, Any]] = {}


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def geolocate(ip: str) -> Dict[str, Any]:
    if not is_public_ip(ip):
        return {"ip": ip, "status": "private_ip", "message": "Geolocation unavailable for private IP"}
    if not config.ENABLE_GEOLOCATION:
        return {"ip": ip, "status": "disabled", "message": "Geolocation disabled via ENABLE_GEOLOCATION"}
    if ip in _cache:
        return _cache[ip]

    url = f"{config.GEO_API_URL.rstrip('/')}/{ip}"
    params = {"fields": "status,message,country,regionName,city,isp,org,as,query"}
    try:
        resp = httpx.get(url, params=params, timeout=config.HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Geolocation lookup failed for %s: %s", ip, exc)
        detail = f"HTTP {exc.response.status_code}" if isinstance(exc, httpx.HTTPStatusError) else type(exc).__name__
        return {"ip": ip, "status": "lookup_failed", "message": f"Geolocation service unavailable ({detail})"}

    if data.get("status") != "success":
        return {"ip": ip, "status": "lookup_failed", "message": data.get("message", "unknown error")}

    result = {
        "ip": data.get("query", ip),
        "status": "ok",
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "organization": data.get("org"),
        "asn": data.get("as"),
        "source": "ip-api.com",
    }
    _cache[ip] = result
    return result


def geolocate_relay(relay: Dict[str, Any], extra_ips: Optional[List[str]] = None) -> Dict[str, Any]:
    origin = relay.get("probable_origin_ip")
    others: List[str] = []
    for hop in relay.get("relay_chain", []):
        ip = hop.get("from_ip")
        if ip and ip != origin and is_public_ip(ip) and ip not in others:
            others.append(ip)
    for ip in extra_ips or []:
        if ip != origin and is_public_ip(ip) and ip not in others:
            others.append(ip)

    if not origin and not others:
        return {
            "status": "no_ip_found",
            "message": "No IP address found in Received headers",
            "disclaimer": DISCLAIMER,
        }

    return {
        "probable_origin_ip": geolocate(origin) if origin else None,
        "other_public_ips": [geolocate(ip) for ip in others[:3]],
        "disclaimer": DISCLAIMER,
    }
