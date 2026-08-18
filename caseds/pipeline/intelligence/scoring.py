from datetime import datetime, timezone

from caseds.config import settings
from caseds.models.schemas import (
    Classification,
    IntelligenceResult,
    PredictedImpact,
    RecommendedAction,
    RiskLevel,
    ScoreBreakdown,
    ThreatAnalysisResponse,
)
from caseds.models.schemas import FeatureBundle, NormalizedInput


def _risk_level(score: float) -> RiskLevel:
    if score <= settings.thresholds.safe_max:
        return RiskLevel.SAFE
    if score <= settings.thresholds.suspicious_max:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.HIGH_RISK


def _impact(level: RiskLevel) -> PredictedImpact:
    if level == RiskLevel.HIGH_RISK:
        return PredictedImpact.HIGH
    if level == RiskLevel.SUSPICIOUS:
        return PredictedImpact.MEDIUM
    return PredictedImpact.LOW


def _action(level: RiskLevel) -> RecommendedAction:
    if level == RiskLevel.HIGH_RISK:
        return RecommendedAction.BLOCK
    if level == RiskLevel.SUSPICIOUS:
        return RecommendedAction.VERIFY
    return RecommendedAction.IGNORE


def score_threat(
    normalized: NormalizedInput,
    features: FeatureBundle,
    intelligence: IntelligenceResult,
    processing_time_ms: float,
) -> ThreatAnalysisResponse:
    weights = settings.weights

    text_risk = max(0.0, min(1.0, features.text.aggregate_text_risk))
    url_risk = max((u.url_risk_score for u in features.urls), default=0.0)
    sender_risk = max(0.0, min(1.0, features.sender.sender_risk_score))
    behavioral_risk = max(0.0, min(1.0, features.behavioral.behavioral_risk_score))
    pattern_risk = max((p.severity for p in intelligence.pattern_matches), default=0.0)

    nlp_result = intelligence.nlp_classification
    if nlp_result.top_class == Classification.BENIGN:
        nlp_risk = 1.0 - nlp_result.benign
    else:
        nlp_risk = nlp_result.confidence
    nlp_risk = max(0.0, min(1.0, nlp_risk))

    weighted = (
        (text_risk * weights.text)
        + (url_risk * weights.url)
        + (sender_risk * weights.sender)
        + (behavioral_risk * weights.behavioral)
        + (nlp_risk * weights.nlp)
        + (pattern_risk * weights.pattern)
    )
    threat_score = round(max(0.0, min(100.0, weighted * 100)), 2)

    risk_level = _risk_level(threat_score)
    triggered = [p.rule_name for p in intelligence.pattern_matches]
    for urlf in features.urls:
        triggered.extend(urlf.threat_intel_flags)

    explanation = (
        f"Classified as {nlp_result.top_class.value} ({nlp_result.confidence:.2f} confidence), "
        f"with strongest risks from text={text_risk:.2f}, url={url_risk:.2f}, sender={sender_risk:.2f}."
    )

    breakdown = ScoreBreakdown(
        text_risk=text_risk,
        url_risk=url_risk,
        sender_risk=sender_risk,
        behavioral_risk=behavioral_risk,
        pattern_risk=pattern_risk,
        nlp_risk=nlp_risk,
        weights={
            "text": weights.text,
            "url": weights.url,
            "sender": weights.sender,
            "behavioral": weights.behavioral,
            "nlp": weights.nlp,
            "pattern": weights.pattern,
        },
    )

    return ThreatAnalysisResponse(
        threat_score=threat_score,
        risk_level=risk_level,
        classification=nlp_result.top_class,
        confidence=nlp_result.confidence,
        predicted_impact=_impact(risk_level),
        explanation=explanation,
        recommended_action=_action(risk_level),
        score_breakdown=breakdown,
        triggered_indicators=sorted(set(triggered)),
        url_analysis=features.urls,
        pattern_matches=intelligence.pattern_matches,
        processing_time_ms=round(processing_time_ms, 2),
        analysis_id=str(normalized.raw_metadata.get("analysis_id", "")),
        timestamp=datetime.now(timezone.utc),
    )
