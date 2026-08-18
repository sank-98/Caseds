from caseds.models.schemas import BehavioralFeatures, NormalizedInput


def extract(normalized: NormalizedInput) -> BehavioralFeatures:
    metadata = normalized.raw_metadata or {}
    known_senders = {s.lower() for s in metadata.get("known_senders", [])}

    sender = (normalized.sender or "").lower()
    is_known_sender = sender in known_senders

    sender_message_count = int(metadata.get("sender_message_count_24h", 1))
    baseline_count = int(metadata.get("baseline_sender_message_count_24h", 1))
    sender_frequency_anomaly = sender_message_count > max(3, baseline_count * 3)

    local_hour = normalized.timestamp.hour
    unusual_send_time = local_hour < 6 or local_hour > 22

    style_deviation = float(metadata.get("message_style_deviation", 0.0))
    request_type_unusual = bool(metadata.get("request_type_unusual", False))

    risk = min(
        1.0,
        (0.25 if not is_known_sender else 0.0)
        + (0.25 if sender_frequency_anomaly else 0.0)
        + (0.2 if unusual_send_time else 0.0)
        + (0.15 if request_type_unusual else 0.0)
        + (0.2 * max(0.0, min(1.0, style_deviation))),
    )

    return BehavioralFeatures(
        user_id=normalized.user_id,
        is_known_sender=is_known_sender,
        sender_frequency_anomaly=sender_frequency_anomaly,
        unusual_send_time=unusual_send_time,
        message_style_deviation=max(0.0, min(1.0, style_deviation)),
        request_type_unusual=request_type_unusual,
        behavioral_risk_score=risk,
    )
