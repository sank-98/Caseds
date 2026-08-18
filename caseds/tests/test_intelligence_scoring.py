from datetime import datetime, timezone

from caseds.models.schemas import EmailHeaders, InputType, IntelligenceResult, RawInput
from caseds.pipeline.feature_extraction.extract_bundle import extract_bundle
from caseds.pipeline.input_layer import normalizer
from caseds.pipeline.intelligence import classify, match_patterns, score_threat


def test_intelligence_and_scoring_produce_risk_response():
    raw = RawInput(
        input_type=InputType.EMAIL,
        subject="Final warning",
        body="Urgent! reset your password and wire transfer now",
        sender="CEO Office <finance@amaz0n.com>",
        timestamp=datetime(2026, 1, 1, 3, 0, tzinfo=timezone.utc),
        email_headers=EmailHeaders(spf_result="fail", dkim_result="fail", dmarc_result="fail"),
        session_metadata={"known_senders": [], "sender_reputation": 0.1},
    )

    normalized = normalizer.normalize(raw)
    normalized.raw_metadata.update(raw.session_metadata)
    features = extract_bundle(normalized)
    nlp = classify(normalized, features)
    patterns = match_patterns(normalized, features)

    result = score_threat(
        normalized,
        features,
        IntelligenceResult(nlp_classification=nlp, pattern_matches=patterns),
        processing_time_ms=12.0,
    )

    assert result.threat_score >= 0
    assert result.classification in {"phishing", "impersonation", "scam", "benign"}
    assert result.processing_time_ms == 12.0
    assert result.score_breakdown.url_risk >= 0
