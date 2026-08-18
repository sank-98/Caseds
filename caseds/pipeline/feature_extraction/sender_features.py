import re
from email.utils import parseaddr

from caseds.config import settings
from caseds.models.schemas import NormalizedInput, SenderFeatures

LOOKALIKE_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def _result_is_valid(result: str | None) -> bool | None:
    if result is None:
        return None
    lowered = result.strip().lower()
    if not lowered:
        return None
    return lowered in {"pass", "valid", "aligned", "success"}


def _extract_domain(sender: str) -> str:
    _, email = parseaddr(sender)
    if "@" not in email:
        return ""
    return email.split("@", 1)[1].lower()


def _normalize_for_lookalike(domain: str) -> str:
    return domain.lower().translate(LOOKALIKE_MAP)


def extract(normalized: NormalizedInput) -> SenderFeatures:
    headers = normalized.email_headers
    metadata = normalized.raw_metadata or {}

    sender = normalized.sender or ""
    domain = _extract_domain(sender)

    spf = _result_is_valid(headers.spf_result if headers else None)
    dkim = _result_is_valid(headers.dkim_result if headers else None)
    dmarc = _result_is_valid(headers.dmarc_result if headers else None)

    is_free = domain in settings.sender.free_email_providers
    lookalike_target = None
    normalized_domain = _normalize_for_lookalike(domain)

    for target, candidate_domains in settings.sender.impersonation_targets.items():
        normalized_candidates = {_normalize_for_lookalike(item) for item in candidate_domains}
        if domain in candidate_domains or (
            normalized_domain in normalized_candidates and domain != f"{target}.com"
        ):
            lookalike_target = target
            break

    display_name, _ = parseaddr(sender)
    display_name_mismatch = False
    if display_name and domain:
        display_tokens = set(re.findall(r"[a-z]+", display_name.lower()))
        mismatch_targets = set(settings.sender.impersonation_targets.keys())
        if display_tokens & mismatch_targets and not any(t in domain for t in display_tokens & mismatch_targets):
            display_name_mismatch = True

    reputation = float(metadata.get("sender_reputation", 0.5))
    domain_age_days = metadata.get("sender_domain_age_days")

    risk = min(
        1.0,
        (0.25 if spf is False else 0.0)
        + (0.2 if dkim is False else 0.0)
        + (0.2 if dmarc is False else 0.0)
        + (0.1 if is_free else 0.0)
        + (0.25 if lookalike_target else 0.0)
        + (0.1 if display_name_mismatch else 0.0)
        + (0.1 if domain_age_days is not None and domain_age_days < 30 else 0.0)
        + (0.2 * (1.0 - max(0.0, min(1.0, reputation)))),
    )

    return SenderFeatures(
        sender=sender,
        domain=domain,
        spf_valid=spf,
        dkim_valid=dkim,
        dmarc_valid=dmarc,
        domain_age_days=domain_age_days,
        is_free_email_provider=is_free,
        display_name_mismatch=display_name_mismatch,
        lookalike_domain_detected=lookalike_target is not None,
        lookalike_target=lookalike_target,
        reputation_score=max(0.0, min(1.0, reputation)),
        sender_risk_score=risk,
    )
