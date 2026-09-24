"""Parse a raw RFC 5322 / .eml message into a plain dict of forensic fields.

Handles common .eml structures (plain, HTML, multipart/alternative, attachments). It does not try
to repair every possible malformed message.
"""
from __future__ import annotations

import hashlib
import html as html_lib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Union

URL_RE = re.compile(r"https?://[^\s<>\"'\\]+", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TRAILING_PUNCT = ".,;:!?)]}>'\""
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".vbs", ".jar", ".msi", ".lnk", ".iso", ".img",
    ".docm", ".xlsm", ".pptm", ".hta", ".ps1", ".html", ".htm", ".svg", ".zip", ".rar", ".7z",
}


class _HTMLText(HTMLParser):
    """Minimal HTML -> text converter that also collects link targets."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.links: List[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.links.append(v)
        if tag in ("br", "p", "div", "tr", "li"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _clean_ws(value: Any) -> Optional[str]:
    if value is None:
        return None
    return re.sub(r"\s+", " ", str(value)).strip()


def _hdr(msg, name: str) -> Optional[str]:
    try:
        return _clean_ws(msg.get(name))
    except Exception:  # malformed header - do not crash the whole analysis
        return None


def _hdr_all(msg, name: str) -> List[str]:
    try:
        return [_clean_ws(v) or "" for v in msg.get_all(name, [])]
    except Exception:
        return []


def _decode_part(part, payload: bytes) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def extract_urls(*texts: str) -> List[str]:
    seen: Dict[str, None] = {}
    for text in texts:
        for m in URL_RE.finditer(html_lib.unescape(text or "")):
            url = m.group(0).rstrip(_TRAILING_PUNCT)
            if url:
                seen.setdefault(url, None)
    return list(seen)[:50]


def extract_ips(text: str) -> List[str]:
    found: Dict[str, None] = {}
    for m in IPV4_RE.finditer(text or ""):
        try:
            ipaddress.ip_address(m.group(0))
            found.setdefault(m.group(0), None)
        except ValueError:
            continue
    return list(found)


def parse_email(raw: Union[bytes, str]) -> Dict[str, Any]:
    raw_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []
    parts_info: List[Dict[str, Any]] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        parts_info.append(
            {
                "content_type": ctype,
                "charset": part.get_content_charset(),
                "disposition": disposition,
                "filename": filename,
                "size_bytes": len(payload),
            }
        )
        if filename or disposition == "attachment":
            ext = ("." + filename.rsplit(".", 1)[-1].lower()) if filename and "." in filename else ""
            attachments.append(
                {
                    "filename": filename,
                    "content_type": ctype,
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "suspicious_extension": ext in SUSPICIOUS_EXTENSIONS,
                }
            )
        elif ctype == "text/plain":
            plain_parts.append(_decode_part(part, payload))
        elif ctype == "text/html":
            html_parts.append(_decode_part(part, payload))

    html_text = ""
    html_links: List[str] = []
    for h in html_parts:
        conv = _HTMLText()
        try:
            conv.feed(h)
        except Exception:
            pass
        html_text += "".join(conv.parts) + "\n"
        html_links.extend(conv.links)

    plain_text = "\n".join(plain_parts).strip()
    body_text = plain_text or re.sub(r"[ \t]+", " ", html_text).strip()

    urls = extract_urls(plain_text, *html_parts, *html_links)

    received = _hdr_all(msg, "Received")
    from_h = _hdr(msg, "From")
    headers_present = any([from_h, _hdr(msg, "Subject"), received])

    return {
        "headers_present": headers_present,
        "subject": _hdr(msg, "Subject"),
        "from": from_h,
        "to": _hdr(msg, "To"),
        "reply_to": _hdr(msg, "Reply-To"),
        "return_path": _hdr(msg, "Return-Path"),
        "date": _hdr(msg, "Date"),
        "message_id": _hdr(msg, "Message-ID"),
        "received": received,
        "authentication_results": _hdr_all(msg, "Authentication-Results"),
        "received_spf": _hdr(msg, "Received-SPF"),
        "dkim_signature": _hdr_all(msg, "DKIM-Signature"),
        "x_originating_ip": _hdr(msg, "X-Originating-IP"),
        "body_text": body_text,
        "has_html_body": bool(html_parts),
        "urls": urls,
        "body_ips": extract_ips(body_text),
        "attachments": attachments,
        "mime_info": {
            "content_type": msg.get_content_type(),
            "is_multipart": msg.is_multipart(),
            "mime_version": _hdr(msg, "MIME-Version"),
            "parts": parts_info,
        },
    }
