from __future__ import annotations

from app import config
from app.services import evidence_service, privacy_service
from app.services.header_analyzer import analyze_authentication


def test_evidence_filenames_are_restricted_and_hashed() -> None:
    assert evidence_service.safe_filename("nested/message.eml") == "message.eml"
    assert len(evidence_service.sha256_digest(b"evidence")) == 64

    try:
        evidence_service.safe_filename("payload.exe")
    except evidence_service.InvalidEvidenceError:
        pass
    else:
        raise AssertionError("non-eml evidence should be rejected")


def test_authentication_report_contains_independent_validation() -> None:
    raw = b"From: sender@example.com\nReturn-Path: <sender@example.com>\n\nhello\n"
    parsed = {
        "from": "sender@example.com",
        "return_path": "<sender@example.com>",
        "authentication_results": [],
        "received_spf": None,
        "dkim_signature": [],
    }
    result = analyze_authentication(parsed, raw=raw, origin_ip=None)
    assert set(result["independent_validation"]) == {"spf", "dkim", "dmarc"}
    assert result["independent_validation"]["dkim"]["status"] == "none"


def test_privacy_masking_is_configurable() -> None:
    original = config.MASK_SENSITIVE_FIELDS
    config.MASK_SENSITIVE_FIELDS = True
    try:
        report = {"email_summary": {"from": "Analyst <analyst@example.com>"}}
        masked = privacy_service.mask_report(report)
        assert "***" in masked["email_summary"]["from"]
        assert report["email_summary"]["from"] == "Analyst <analyst@example.com>"
    finally:
        config.MASK_SENSITIVE_FIELDS = original