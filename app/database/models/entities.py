"""SQLAlchemy 2.x models for cases, evidence, intelligence, and audit data."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class AnalysisCase(TimestampMixin, Base):
    __tablename__ = "analysis_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    case_number: Mapped[str] = mapped_column(String(40), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="NEW")
    classification: Mapped[Optional[str]] = mapped_column(String(64))
    risk_score: Mapped[Optional[int]] = mapped_column(Integer)
    risk_level: Mapped[Optional[str]] = mapped_column(String(16))
    subject: Mapped[Optional[str]] = mapped_column(Text)
    sender: Mapped[Optional[str]] = mapped_column(Text)
    recipient: Mapped[Optional[str]] = mapped_column(Text)
    probable_origin_ip: Mapped[Optional[str]] = mapped_column(String(64))
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text)
    forensic_report: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON)

    evidence = relationship("EmailEvidence", back_populates="case", cascade="all, delete-orphan")
    metadata_record = relationship("EmailMetadata", back_populates="case", uselist=False, cascade="all, delete-orphan")
    header_analysis = relationship("HeaderAnalysis", back_populates="case", uselist=False, cascade="all, delete-orphan")
    authentication = relationship("AuthenticationResult", back_populates="case", uselist=False, cascade="all, delete-orphan")
    urls = relationship("URLIndicator", back_populates="case", cascade="all, delete-orphan")
    domains = relationship("DomainIndicator", back_populates="case", cascade="all, delete-orphan")
    ips = relationship("IPIndicator", back_populates="case", cascade="all, delete-orphan")
    tasks = relationship("AnalysisTask", back_populates="case", cascade="all, delete-orphan")
    campaign_links = relationship("CampaignIndicator", back_populates="case", cascade="all, delete-orphan")
    ioc_links = relationship("CaseIOC", back_populates="case", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="case", cascade="all, delete-orphan")


class EmailEvidence(Base):
    __tablename__ = "email_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), index=True, nullable=False)
    original_filename: Mapped[Optional[str]] = mapped_column(String(255))
    raw_email_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    content_hash: Mapped[Optional[str]] = mapped_column(String(64))
    raw_email_size: Mapped[int] = mapped_column(Integer, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    storage_reference: Mapped[Optional[str]] = mapped_column(Text)
    retention_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    case = relationship("AnalysisCase", back_populates="evidence")
    events = relationship("EvidenceEvent", back_populates="evidence", cascade="all, delete-orphan")


class EmailMetadata(Base):
    __tablename__ = "email_metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), unique=True, nullable=False)
    message_id: Mapped[Optional[str]] = mapped_column(Text)
    subject: Mapped[Optional[str]] = mapped_column(Text)
    from_address: Mapped[Optional[str]] = mapped_column(Text)
    to_address: Mapped[Optional[str]] = mapped_column(Text)
    cc: Mapped[Optional[str]] = mapped_column(Text)
    reply_to: Mapped[Optional[str]] = mapped_column(Text)
    return_path: Mapped[Optional[str]] = mapped_column(Text)
    date_header: Mapped[Optional[str]] = mapped_column(Text)
    mime_info: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    case = relationship("AnalysisCase", back_populates="metadata_record")


class HeaderAnalysis(Base):
    __tablename__ = "header_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), unique=True, nullable=False)
    identity_mismatch: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(Text)
    sender_domain: Mapped[Optional[str]] = mapped_column(String(255))
    reply_to_domain: Mapped[Optional[str]] = mapped_column(String(255))
    return_path_domain: Mapped[Optional[str]] = mapped_column(String(255))
    received_headers: Mapped[list[Any]] = mapped_column(JSON, default=list)
    relay_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    probable_origin_ip: Mapped[Optional[str]] = mapped_column(String(64))
    authentication_results: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    case = relationship("AnalysisCase", back_populates="header_analysis")


class AuthenticationResult(Base):
    __tablename__ = "authentication_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), unique=True, nullable=False)
    spf: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    dkim: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    dmarc: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    alignment: Mapped[Optional[str]] = mapped_column(String(32))
    source: Mapped[Optional[str]] = mapped_column(String(64))
    note: Mapped[Optional[str]] = mapped_column(Text)

    case = relationship("AnalysisCase", back_populates="authentication")


class URLIndicator(Base):
    __tablename__ = "url_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), index=True, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[Optional[str]] = mapped_column(Text)
    domain: Mapped[Optional[str]] = mapped_column(String(255))
    scheme: Mapped[Optional[str]] = mapped_column(String(16))
    suspicious_keywords: Mapped[list[Any]] = mapped_column(JSON, default=list)
    ip_based: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    obfuscation_indicators: Mapped[list[Any]] = mapped_column(JSON, default=list)
    shortener: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer)

    case = relationship("AnalysisCase", back_populates="urls")


class DomainIndicator(Base):
    __tablename__ = "domain_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), index=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    registrar: Mapped[Optional[str]] = mapped_column(String(255))
    registration_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    age_days: Mapped[Optional[int]] = mapped_column(Integer)
    dns_records: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    mx_records: Mapped[list[Any]] = mapped_column(JSON, default=list)
    hosting_information: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    lookalike: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    matched_brand: Mapped[Optional[str]] = mapped_column(String(128))

    case = relationship("AnalysisCase", back_populates="domains")


class IPIndicator(Base):
    __tablename__ = "ip_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), index=True, nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    country: Mapped[Optional[str]] = mapped_column(String(128))
    region: Mapped[Optional[str]] = mapped_column(String(128))
    city: Mapped[Optional[str]] = mapped_column(String(128))
    isp: Mapped[Optional[str]] = mapped_column(String(255))
    organization: Mapped[Optional[str]] = mapped_column(String(255))
    asn: Mapped[Optional[str]] = mapped_column(String(64))
    reverse_dns: Mapped[Optional[str]] = mapped_column(String(255))
    reputation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    case = relationship("AnalysisCase", back_populates="ips")


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(128))
    confidence: Mapped[Optional[float]] = mapped_column(Float)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    campaign_links = relationship("CampaignIndicator", back_populates="ioc", cascade="all, delete-orphan")
    case_links = relationship("CaseIOC", back_populates="ioc", cascade="all, delete-orphan")


class CaseIOC(Base):
    __tablename__ = "case_iocs"
    __table_args__ = (UniqueConstraint("case_id", "ioc_id", name="uq_case_ioc"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), index=True, nullable=False)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), index=True, nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(128))
    case = relationship("AnalysisCase", back_populates="ioc_links")
    ioc = relationship("IOC", back_populates="case_links")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("case_id", "alert_type", name="uq_alert_case_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), index=True, nullable=False)
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    delivery_status: Mapped[str] = mapped_column(String(32), default="RECORDED", nullable=False)
    case = relationship("AnalysisCase", back_populates="alerts")


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    campaign_name: Mapped[Optional[str]] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text)
    risk_level: Mapped[Optional[str]] = mapped_column(String(16))
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    email_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    indicators = relationship("CampaignIndicator", back_populates="campaign", cascade="all, delete-orphan")


class CampaignIndicator(Base):
    __tablename__ = "campaign_indicators"
    __table_args__ = (UniqueConstraint("campaign_id", "ioc_id", "case_id", name="uq_campaign_ioc_case"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), nullable=False)
    similarity_score: Mapped[Optional[float]] = mapped_column(Float)
    campaign = relationship("Campaign", back_populates="indicators")
    ioc = relationship("IOC", back_populates="campaign_links")
    case = relationship("AnalysisCase", back_populates="campaign_links")


class AnalysisTask(Base):
    __tablename__ = "analysis_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    case_id: Mapped[int] = mapped_column(ForeignKey("analysis_cases.id", ondelete="CASCADE"), nullable=False)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="QUEUED")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    error: Mapped[Optional[str]] = mapped_column(Text)
    case = relationship("AnalysisCase", back_populates="tasks")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[Optional[str]] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(128))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class EvidenceEvent(Base):
    __tablename__ = "evidence_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("email_evidence.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    hash: Mapped[Optional[str]] = mapped_column(String(64))
    description: Mapped[Optional[str]] = mapped_column(Text)
    evidence = relationship("EmailEvidence", back_populates="events")
