from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, validator
from enum import Enum
from datetime import datetime

# Enums
class InputType(str, Enum):
    EMAIL = "email"
    SMS = "sms"
    CHAT = "chat"
    URL = "url"
    RAW_TEXT = "raw_text"
class Classification(str, Enum):
    PHISHING = "phishing"
    IMPERSONATION = "impersonation"
    SCAM = "scam"
    BENIGN = "benign"
class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
class PredictedImpact(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
class RecommendedAction(str, Enum):
    IGNORE = "ignore"
    VERIFY = "verify"
    BLOCK = "block"

# Input Models
class EmailHeaders(BaseModel):
    from_address: Optional[str] = None
    reply_to: Optional[str] = None
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    x_mailer: Optional[str] = None
    received_from: Optional[List[str]] = Field(default_factory=list)
class AttachmentMetadata(BaseModel):
    filename: str
    file_type: str
    file_size_bytes: int
    has_macros: Optional[bool] = None
    is_executable: Optional[bool] = None
    sha256: Optional[str] = None
class RawInput(BaseModel):
    input_type: InputType
    body: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    timestamp: Optional[datetime] = None
    urls: Optional[List[str]] = Field(default_factory=list)
    email_headers: Optional[EmailHeaders] = None
    attachments: Optional[List[AttachmentMetadata]] = Field(default_factory=list)
    user_id: Optional[str] = None
    session_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    @validator("body", "urls", pre=True, always=True)
    def at_least_one_input(cls, v, values):
        return v
class NormalizedInput(BaseModel):
    input_type: InputType
    body: str = ""
    subject: str = ""
    sender: str = ""
    recipient: str = ""
    timestamp: datetime
    extracted_urls: List[str] = Field(default_factory=list)
    email_headers: Optional[EmailHeaders] = None
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    user_id: Optional[str] = None
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)

# Feature Models
class TextFeatures(BaseModel):
    urgency_score: float = 0.0
    authority_score: float = 0.0
    emotional_manipulation_score: float = 0.0
    perplexity_score: float = 0.0
    named_entities: List[Dict[str, str]] = Field(default_factory=list)
    urgency_phrases: List[str] = Field(default_factory=list)
    authority_cues: List[str] = Field(default_factory=list)
    obfuscation_indicators: List[str] = Field(default_factory=list)
    language_inconsistencies: List[str] = Field(default_factory=list)
    aggregate_text_risk: float = 0.0
class URLFeatures(BaseModel):
    url: str
    is_shortened: bool = False
    expanded_url: Optional[str] = None
    domain: str = ""
    domain_age_days: Optional[int] = None
    entropy: float = 0.0
    url_length: int = 0
    suspicious_tld: bool = False
    has_ip_address: bool = False
    redirect_chain: List[str] = Field(default_factory=list)
    redirect_depth: int = 0
    virustotal_score: Optional[float] = None
    threat_intel_flags: List[str] = Field(default_factory=list)
    predicted_outcome: Optional[str] = None
    impact_severity: float = 0.0
    url_risk_score: float = 0.0
class SenderFeatures(BaseModel):
    sender: str = ""
    domain: str = ""
    spf_valid: Optional[bool] = None
    dkim_valid: Optional[bool] = None
    dmarc_valid: Optional[bool] = None
    domain_age_days: Optional[int] = None
    is_free_email_provider: bool = False
    display_name_mismatch: bool = False
    lookalike_domain_detected: bool = False
    lookalike_target: Optional[str] = None
    reputation_score: float = 0.5
    sender_risk_score: float = 0.0
class BehavioralFeatures(BaseModel):
    user_id: Optional[str] = None
    is_known_sender: bool = False
    sender_frequency_anomaly: bool = False
    unusual_send_time: bool = False
    message_style_deviation: float = 0.0
    request_type_unusual: bool = False
    behavioral_risk_score: float = 0.0
class FeatureBundle(BaseModel):
    text: TextFeatures
    urls: List[URLFeatures] = Field(default_factory=list)
    sender: SenderFeatures
    behavioral: BehavioralFeatures

# Intelligence Layer Models
class ClassificationResult(BaseModel):
    phishing: float = 0.0
    impersonation: float = 0.0
    scam: float = 0.0
    benign: float = 0.0
    top_class: Classification = Classification.BENIGN
    confidence: float = 0.0
    method: str = "heuristic"
class PatternMatch(BaseModel):
    rule_id: str
    rule_name: str
    matched_text: Optional[str] = None
    severity: float = 0.0
    category: str = ""
class IntelligenceResult(BaseModel):
    nlp_classification: ClassificationResult
    pattern_matches: List[PatternMatch] = Field(default_factory=list)
    graph_clusters: List[str] = Field(default_factory=list)

# Risk Score + Final Output
class ScoreBreakdown(BaseModel):
    text_risk: float = 0.0
    url_risk: float = 0.0
    sender_risk: float = 0.0
    behavioral_risk: float = 0.0
    pattern_risk: float = 0.0
    nlp_risk: float = 0.0
    weights: Dict[str, float] = Field(default_factory=dict)
class ThreatAnalysisResponse(BaseModel):
    threat_score: float = Field(..., ge=0, le=100, description="0–100 risk score")
    risk_level: RiskLevel
    classification: Classification
    confidence: float = Field(..., ge=0.0, le=1.0)
    predicted_impact: PredictedImpact
    explanation: str
    recommended_action: RecommendedAction
    score_breakdown: ScoreBreakdown
    triggered_indicators: List[str] = Field(default_factory=list)
    url_analysis: List[URLFeatures] = Field(default_factory=list)
    pattern_matches: List[PatternMatch] = Field(default_factory=list)
    processing_time_ms: float = 0.0
    analysis_id: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
class HealthResponse(BaseModel):
    status: str
    version: str
    modules_loaded: Dict[str, bool]