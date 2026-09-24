"""Pydantic request/response models (these drive the Swagger documentation)."""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "EmailSentinel"


class NLPRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        examples=["Your account will be suspended. Verify immediately."],
    )


class NLPResponse(BaseModel):
    classification: str
    confidence: float
    indicators: List[str]
    keywords: List[str] = []
    class_probabilities: Dict[str, float] = {}


class EmailSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    subject: Optional[str] = None
    from_: Optional[str] = Field(None, alias="from")
    to: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    mime_info: Dict[str, Any] = {}
    attachments: List[Dict[str, Any]] = []


class ThreatAssessment(BaseModel):
    model_config = ConfigDict(extra="allow")
    classification: str
    risk_score: int
    risk_level: str
    reasons: List[str] = []
    score_breakdown: List[Dict[str, Any]] = []
    disclaimer: str = ""


class NLPAnalysis(BaseModel):
    model_config = ConfigDict(extra="allow")
    confidence: float
    keywords: List[str]
    social_engineering_indicators: List[str]
    class_probabilities: Dict[str, float] = {}
    heuristic_flags: Dict[str, bool] = {}
    heuristic_matches: Dict[str, List[str]] = {}


class IdentityAnalysis(BaseModel):
    model_config = ConfigDict(extra="allow")
    identity_mismatch: bool
    lookalike_domain: bool
    matched_brand: Optional[str] = None
    indicators: List[str] = []
    lookalike_details: List[Dict[str, Any]] = []


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    analysis_id: str
    email_summary: EmailSummary
    threat_assessment: ThreatAssessment
    nlp_analysis: NLPAnalysis
    identity_analysis: IdentityAnalysis
    authentication: Dict[str, Any]
    url_analysis: List[Dict[str, Any]]
    relay_analysis: Dict[str, Any]
    geolocation: Dict[str, Any]
    domain_intelligence: Dict[str, Any]
    indicators_of_compromise: Dict[str, List[str]]
    explanation: List[str]
    warnings: List[str] = []


class CaseRecord(BaseModel):
    analysis_id: str
    created_at: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    classification: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    probable_origin_ip: Optional[str] = None


class CasesResponse(BaseModel):
    total: int
    limit: int
    offset: int
    cases: List[CaseRecord]
