"""URL analysis. URLs are only parsed as strings; they are NEVER opened or fetched."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlparse

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "password", "update", "payment", "confirm", "banking", "wallet", "suspend",
]
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at",
}
RISKY_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "country", "kim"}
LONG_URL = 75


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def analyze_url(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    indicators: List[str] = []
    obfuscation: List[str] = []

    if scheme == "http":
        indicators.append("HTTP (no TLS)")

    ip_based = _is_ip_host(host)
    if ip_based:
        indicators.append("IP-based URL")
    elif re.fullmatch(r"\d+|0x[0-9a-f]+", host):
        ip_based = True
        indicators.append("IP-based URL (encoded as number)")
        obfuscation.append("numeric/hex encoded IP")

    haystack = f"{host}{parsed.path}?{parsed.query}".lower()
    keywords = [w for w in SUSPICIOUS_WORDS if w in haystack]
    for w in keywords:
        indicators.append(f"{w} keyword")

    if len(url) > LONG_URL:
        indicators.append(f"Long URL ({len(url)} chars)")

    if host in SHORTENERS:
        indicators.append("URL shortener")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        indicators.append(f"Suspicious TLD (.{tld})")

    # ---- obfuscation checks
    if parsed.netloc and "@" in parsed.netloc:
        obfuscation.append("credentials/@ in authority section")
    if "xn--" in host:
        obfuscation.append("punycode (possible homograph)")
    if len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 3:
        obfuscation.append("heavy percent-encoding")
    if host and not ip_based and host.count(".") >= 4:
        obfuscation.append("excessive subdomains")
    if host.count("-") >= 3:
        obfuscation.append("many hyphens in hostname")
    if re.search(r"https?(?::|%3a)//", (parsed.path + "?" + parsed.query), re.I):
        obfuscation.append("embedded redirect URL")
    if parsed.port and parsed.port not in (80, 443):
        obfuscation.append(f"non-standard port {parsed.port}")
    for o in obfuscation:
        indicators.append(f"Obfuscation: {o}")

    query_params = len(parse_qsl(parsed.query, keep_blank_values=True))
    benign_only = {"HTTP (no TLS)"}
    suspicious = any(i not in benign_only and not i.startswith("Long URL") for i in indicators)

    return {
        "url": url,
        "domain": host,
        "scheme": scheme,
        "uses_https": scheme == "https",
        "ip_based": ip_based,
        "length": len(url),
        "query_param_count": query_params,
        "keywords_found": keywords,
        "obfuscation_detected": bool(obfuscation),
        "risk_indicators": indicators,
        "suspicious": suspicious,
    }


def analyze_urls(urls: List[str]) -> List[Dict[str, Any]]:
    return [analyze_url(u) for u in urls]
