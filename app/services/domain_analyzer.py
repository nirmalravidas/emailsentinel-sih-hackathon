"""Domain helpers and lookalike (typosquatting / brand impersonation) detection.

Everything here is a HEURISTIC indicator. A lookalike match is not proof of impersonation.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

KNOWN_BRANDS = [
    "microsoft.com",
    "google.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
    "sbi.co.in",
]

# Display names, keywords and legitimate alternative domains for each brand.
BRAND_INFO: Dict[str, Dict[str, Any]] = {
    "microsoft.com": {
        "name": "Microsoft",
        "keywords": ["microsoft"],
        "legit": {"microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com"},
    },
    "google.com": {
        "name": "Google",
        "keywords": ["google"],
        "legit": {"google.com", "gmail.com", "googlemail.com", "google.co.in", "google.co.uk", "google.de",
                  "google.fr", "google.ca", "google.com.au", "google.co.jp"},
    },
    "paypal.com": {
        "name": "PayPal",
        "keywords": ["paypal"],
        "legit": {"paypal.com", "paypal.me", "paypal.co.uk", "paypal.in"},
    },
    "amazon.com": {
        "name": "Amazon",
        "keywords": ["amazon"],
        "legit": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp",
                  "amazon.com.au", "amazonaws.com"},
    },
    "apple.com": {
        "name": "Apple",
        "keywords": ["apple", "apple id"],
        "legit": {"apple.com", "icloud.com"},
    },
    "sbi.co.in": {
        "name": "SBI",
        "keywords": ["sbi", "state bank of india"],
        "legit": {"sbi.co.in", "onlinesbi.com", "onlinesbi.sbi", "sbi.bank.in"},
    },
}

SIMILARITY_THRESHOLD = 0.80
HEURISTIC_NOTE = "Heuristic indicator based on string similarity, not proof of impersonation."

_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "nic"}
_LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


# --------------------------------------------------------------------------- basic helpers
def domain_of(address: Optional[str]) -> Optional[str]:
    if not address or "@" not in address:
        return None
    d = address.rsplit("@", 1)[-1].strip().strip("<>.,; ").lower()
    return d or None


def registrable_domain(domain: Optional[str]) -> Optional[str]:
    """Approximate registrable domain without needing the public suffix list (e.g. a.b.co.in -> b.co.in)."""
    if not domain:
        return None
    labels = domain.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return 1.0 - levenshtein(a, b) / max(len(a), len(b))


def _variants(text: str) -> List[str]:
    """Undo common character substitutions (0->o, 1->l or i, rn->m, vv->w ...)."""
    base = text.lower().translate(_LEET)
    out = set()
    for one in ("l", "i"):
        v = base.replace("1", one).replace("rn", "m").replace("vv", "w")
        out.add(v)
    return list(out)


def _best_similarity(candidate: str, target: str) -> float:
    return max(similarity(v, target) for v in _variants(candidate))


# --------------------------------------------------------------------------- lookalike detection
def detect_lookalike(domain: str) -> Optional[Dict[str, Any]]:
    """Compare one domain against KNOWN_BRANDS. Returns the best match or None."""
    domain = (domain or "").lower().strip(".")
    reg = registrable_domain(domain)
    if not reg:
        return None

    best: Optional[Dict[str, Any]] = None

    for brand in KNOWN_BRANDS:
        info = BRAND_INFO[brand]
        if reg in info["legit"]:
            continue  # the genuine brand (or a known alias) - not a lookalike
        brand_label = brand.split(".")[0]
        label = reg.split(".")[0]
        candidates: List[tuple] = []

        # 1) brand domain used as a subdomain of someone else's domain: microsoft.com.evil.net
        if f".{brand}." in f".{domain}." and reg != brand:
            candidates.append((0.95, "brand domain used as subdomain of another domain"))

        # 2) whole-domain edit distance (handles micros0ft.com, paypa1.com, rnicrosoft.com ...)
        dom_sim = _best_similarity(reg, brand)
        if dom_sim >= SIMILARITY_THRESHOLD:
            raw_sim = similarity(reg, brand)
            kind = "character substitution" if dom_sim > raw_sim else "small edit distance"
            candidates.append((dom_sim, kind))

        # 3) same brand name, different TLD: paypal.co, amazon.xyz
        if label == brand_label:
            candidates.append((0.90, "same brand name, different TLD"))

        # 4) brand name embedded as a token: micros0ft-security.com, sbi-kyc-update.com
        for token in re.split(r"[-_.]", label):
            if len(token) < 3 or token == label:
                continue
            if token == brand_label:
                candidates.append((0.90, "brand name embedded in domain"))
            elif len(brand_label) >= 5 and len(token) >= 4:
                t_sim = _best_similarity(token, brand_label)
                if t_sim >= 0.85:
                    kind = "brand name with character substitution embedded in domain"
                    candidates.append((round(0.9 * t_sim, 2), kind))

        if not candidates:
            continue
        sim, kind = max(candidates)
        if best is None or sim > best["similarity"]:
            best = {
                "lookalike_detected": True,
                "matched_brand": brand,
                "brand_name": info["name"],
                "domain": domain,
                "similarity": round(sim, 2),
                "match_type": kind,
                "note": HEURISTIC_NOTE,
            }
    return best


def analyze_lookalikes(domain_roles: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """domain_roles maps domain -> roles (sender, reply_to, return_path, url). Returns detections only."""
    results = []
    for domain, roles in domain_roles.items():
        hit = detect_lookalike(domain)
        if hit:
            hit["found_in"] = sorted(set(roles))
            results.append(hit)
    results.sort(key=lambda r: r["similarity"], reverse=True)
    return results
