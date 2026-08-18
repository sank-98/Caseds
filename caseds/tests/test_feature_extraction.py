from datetime import datetime, timezone

from caseds.models.schemas import EmailHeaders, InputType, RawInput
from caseds.pipeline.feature_extraction.extract_bundle import extract_bundle
from caseds.pipeline.input_layer import normalizer


def test_feature_bundle_extracts_all_layers():
    raw = RawInput(
        input_type=InputType.EMAIL,
        subject="Urgent account verification",
        body="Verify your account immediately: http://bit.ly/paypa1-login",
        sender="PayPal Security <alerts@paypa1.com>",
        urls=["http://bit.ly/paypa1-login"],
        timestamp=datetime(2026, 1, 1, 2, 0, tzinfo=timezone.utc),
        email_headers=EmailHeaders(spf_result="fail", dkim_result="fail", dmarc_result="fail"),
        session_metadata={
            "redirect_chains": {"http://bit.ly/paypa1-login": ["http://bit.ly/paypa1-login", "http://paypa1-login.xyz"]},
            "known_senders": ["trusted@example.com"],
            "sender_domain_age_days": 10,
        },
    )

    normalized = normalizer.normalize(raw)
    normalized.raw_metadata.update(raw.session_metadata)
    features = extract_bundle(normalized)

    assert features.text.aggregate_text_risk > 0
    assert features.urls and features.urls[0].is_shortened is True
    assert features.sender.lookalike_domain_detected is True
    assert features.behavioral.unusual_send_time is True
