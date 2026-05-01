from dataclasses import dataclass, field
from typing import Dict, List, Optional
import os

@dataclass
class RiskWeights:
    text: float = 0.25
    url: float = 0.30
    sender: float = 0.20
    behavioral: float = 0.10
    nlp: float = 0.10
    pattern: float = 0.05

    def validate(self) -> None:
        total = self.text + self.url + self.sender + self.behavioral + self.nlp + self.pattern
        assert abs(total - 1.0) < 0.001, f"Weights must sum to 1.0, got {total:.4f}"

@dataclass
class RiskThresholds:
    safe_max: int = 30
    suspicious_max: int = 70

@dataclass
class NLPConfig:
    transformer_model: str = "facebook/bart-large-mnli"
    fallback_model: str = "cross-encoder/nli-MiniLM2-L6-H768"
    use_transformer: bool = os.getenv("USE_TRANSFORMER", "false").lower() == "true"
    max_tokens: int = 512
    candidate_labels: List[str] = field(default_factory=lambda: [
        "phishing attack",
        "impersonation fraud",
        "financial scam",
        "legitimate communication",
    ])

@dataclass
class URLConfig:
    shortener_domains: List[str] = field(default_factory=lambda: [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "tiny.cc",
        "is.gd",
        "v.gd",
    ])
    suspicious_tlds: List[str] = field(default_factory=lambda: [
        ".xyz",
        ".top",
        ".click",
        ".loan",
        ".work",
        ".gq",
        ".ml",
        ".cf",
        ".tk",
        ".pw",
        ".cc",
        ".biz",
        ".info",
        ".buzz",
        ".vip",
    ])
    high_entropy_threshold: float = 3.5
    max_redirect_depth: int = 10
    virustotal_api_key: Optional[str] = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY"))
    request_timeout_seconds: int = 5

@dataclass
class SenderConfig:
    free_email_providers: List[str] = field(default_factory=lambda: [
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "protonmail.com",
        "tutanota.com",
        "guerrillamail.com",
        "mailinator.com",
        "temp-mail.org",
        "10minutemail.com",
    ])
    impersonation_targets: Dict[str, List[str]] = field(default_factory=lambda: {
        "paypal": ["paypa1.com", "paypal-secure.com", "paypal-support.net", "paypai.com"],
        "amazon": ["amazon-security.com", "amazon-verify.net", "amaz0n.com"],
        "microsoft": ["microsoft-support.net", "microsoftsecurity.com", "micros0ft.com"],
        "apple": ["apple-id.co", "apple-verify.net", "applesupport.co"],
        "google": ["google-security.net", "googIe.com", "g00gle.com"],
        "bank": ["bankofamerica-secure.com", "chase-verify.net", "wellsfargo-alert.com"],
        "irs": ["irs-refund.com", "irs-gov.net", "internal-revenue.net"],
        "fedex": ["fedex-delivery.com", "fedextrack.net"],
        "dhl": ["dhl-delivery.net", "dhl-tracking.co"],
    })

@dataclass
class Settings:
    app_name: str = "CASEDS"
    version: str = "1.0.0"
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    database_url: Optional[str] = field(default_factory=lambda: os.getenv("DATABASE_URL"))

    weights: RiskWeights = field(default_factory=RiskWeights)
    thresholds: RiskThresholds = field(default_factory=RiskThresholds)
    nlp: NLPConfig = field(default_factory=NLPConfig)
    url: URLConfig = field(default_factory=URLConfig)
    sender: SenderConfig = field(default_factory=SenderConfig)

settings = Settings()
settings.weights.validate()