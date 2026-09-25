"""PDF export for persisted EmailSentinel forensic reports."""
from __future__ import annotations

import io
import json
from typing import Any, Dict, Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _text(value: Any) -> str:
    if value is None or value == "":
        return "Not available"
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, default=str)
    return str(value)


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    escaped = _text(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(escaped.replace("\n", "<br/>"), style)


def _json_block(value: Any, style: ParagraphStyle) -> Preformatted:
    return Preformatted(json.dumps(value, indent=2, default=str), style)


def _facts(items: Iterable[tuple[str, Any]], styles: Dict[str, ParagraphStyle]) -> Table:
    rows = [[_paragraph(key, styles["label"]), _paragraph(value, styles["body"])] for key, value in items]
    table = Table(rows, colWidths=[38 * mm, 132 * mm], repeatRows=0)
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#d6d7cf")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def build_pdf(report: Dict[str, Any]) -> bytes:
    """Build a self-contained PDF from the JSON forensic report."""
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="EmailSentinel Forensic Report",
        author="EmailSentinel",
    )
    palette = colors.HexColor("#17211f")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, leading=27, textColor=palette, spaceAfter=5))
    styles.add(ParagraphStyle(name="Subtitle", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#6f7770"), spaceAfter=12))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=colors.HexColor("#b44d43"), spaceBefore=13, spaceAfter=7))
    styles.add(ParagraphStyle(name="label", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.HexColor("#6f7770")))
    styles.add(ParagraphStyle(name="body", parent=styles["Normal"], fontSize=9, leading=12, textColor=palette))
    styles.add(ParagraphStyle(name="small", parent=styles["Normal"], fontSize=8, leading=10, textColor=colors.HexColor("#6f7770")))
    styles.add(ParagraphStyle(name="code", parent=styles["Code"], fontName="Courier", fontSize=6.5, leading=8, textColor=colors.HexColor("#17211f"), leftIndent=4, rightIndent=4))

    threat = report.get("threat_assessment", {})
    email = report.get("email_summary", {})
    identity = report.get("identity_analysis", {})
    authentication = report.get("authentication", {})
    relay = report.get("relay_analysis", {})
    geolocation = report.get("geolocation", {})
    iocs = report.get("indicators_of_compromise", {})
    story = [
        Paragraph("EmailSentinel Forensic Report", styles["ReportTitle"]),
        _paragraph(f"Analysis ID: {report.get('analysis_id')}  |  Subject: {email.get('subject') or 'Untitled message'}", styles["Subtitle"]),
        Paragraph("THREAT ASSESSMENT", styles["Section"]),
        _facts([("Classification", threat.get("classification")), ("Risk score", threat.get("risk_score")), ("Risk level", threat.get("risk_level")), ("Evidence SHA-256", report.get("evidence", {}).get("sha256"))], styles),
        Paragraph("MESSAGE IDENTITY", styles["Section"]),
        _facts([("From", email.get("from")), ("To", email.get("to")), ("Reply-To", email.get("reply_to")), ("Return-Path", email.get("return_path")), ("Message ID", email.get("message_id"))], styles),
        Paragraph("INFRASTRUCTURE GEOLOCATION", styles["Section"]),
        _paragraph("Approximate location of the probable origin network infrastructure. This is not the attacker's physical location or identity.", styles["small"]),
    ]
    origin = geolocation.get("probable_origin_ip") or {}
    story.append(_facts([("IP", origin.get("ip")), ("City", origin.get("city")), ("Region", origin.get("region")), ("Country", origin.get("country")), ("ISP", origin.get("isp")), ("Organization", origin.get("organization")), ("ASN", origin.get("asn")), ("Status", origin.get("status") or geolocation.get("status"))], styles))
    story.extend([
        Paragraph("AUTHENTICATION AND IDENTITY", styles["Section"]),
        _facts([("SPF", authentication.get("spf")), ("DKIM", authentication.get("dkim")), ("DMARC", authentication.get("dmarc")), ("Identity mismatch", identity.get("identity_mismatch")), ("Lookalike brand", identity.get("matched_brand"))], styles),
        Paragraph("RELAY ANALYSIS", styles["Section"]),
        _facts([("Probable origin IP", relay.get("probable_origin_ip")), ("Hop count", relay.get("hop_count")), ("Chain order", relay.get("chain_order")), ("Path summary", relay.get("path_summary"))], styles),
        Paragraph("INDICATORS OF COMPROMISE", styles["Section"]),
        _facts([("IP addresses", iocs.get("ips")), ("Domains", iocs.get("domains")), ("URLs", iocs.get("urls")), ("Attachment SHA-256", iocs.get("attachment_sha256"))], styles),
        Paragraph("RISK REASONS", styles["Section"]),
        _paragraph("\n".join(f"- {reason}" for reason in threat.get("reasons", [])) or "No reasons recorded", styles["body"]),
        Paragraph("COMPLETE REPORT DATA", styles["Section"]),
        _json_block(report, styles["code"]),
    ])
    document.build(story)
    return buffer.getvalue()
