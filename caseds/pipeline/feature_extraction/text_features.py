import re
from collections import Counter

from caseds.models.schemas import NormalizedInput, TextFeatures

URGENCY_PHRASES = [
    "urgent",
    "immediately",
    "asap",
    "act now",
    "verify now",
    "final warning",
    "suspended",
    "limited time",
]
AUTHORITY_CUES = [
    "ceo",
    "finance team",
    "it support",
    "security team",
    "bank",
    "government",
    "irs",
    "compliance",
]
EMOTIONAL_CUES = [
    "fear",
    "panic",
    "congratulations",
    "reward",
    "lottery",
    "prize",
    "penalty",
    "arrest",
]
OBFUSCATION_RE = re.compile(r"(?:\b[a-z]\s+){3,}[a-z]\b|[\u200b-\u200f\ufeff]")


def _ratio(matches: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return min(1.0, matches / total)


def _keyword_hits(text: str, keywords: list[str]) -> list[str]:
    lowered = text.lower()
    return [k for k in keywords if k in lowered]


def _perplexity_score(text: str) -> float:
    if not text:
        return 0.0

    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return 0.0

    counts = Counter(letters)
    max_ratio = max(counts.values()) / len(letters)
    punctuation_ratio = sum(1 for c in text if c in "!?$") / max(len(text), 1)
    uppercase_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)

    # Higher if the text looks unnatural or aggressively formatted.
    return min(1.0, (max_ratio * 0.35) + (punctuation_ratio * 3.0) + (uppercase_ratio * 2.0))


def extract(normalized: NormalizedInput) -> TextFeatures:
    text = f"{normalized.subject}\n{normalized.body}".strip()
    tokens = re.findall(r"\b\w+\b", text.lower())

    urgency_hits = _keyword_hits(text, URGENCY_PHRASES)
    authority_hits = _keyword_hits(text, AUTHORITY_CUES)
    emotional_hits = _keyword_hits(text, EMOTIONAL_CUES)
    obfuscation = OBFUSCATION_RE.findall(text)

    urgency_score = _ratio(len(urgency_hits), 3)
    authority_score = _ratio(len(authority_hits), 3)
    emotional_score = _ratio(len(emotional_hits), 3)
    perplexity_score = _perplexity_score(text)

    aggregate = min(
        1.0,
        (urgency_score * 0.3)
        + (authority_score * 0.25)
        + (emotional_score * 0.2)
        + (perplexity_score * 0.25),
    )

    language_inconsistencies = []
    if text and tokens:
        non_ascii_ratio = sum(1 for c in text if ord(c) > 127) / len(text)
        if non_ascii_ratio > 0.15:
            language_inconsistencies.append("high_non_ascii_ratio")

    return TextFeatures(
        urgency_score=urgency_score,
        authority_score=authority_score,
        emotional_manipulation_score=emotional_score,
        perplexity_score=perplexity_score,
        urgency_phrases=urgency_hits,
        authority_cues=authority_hits,
        obfuscation_indicators=obfuscation,
        language_inconsistencies=language_inconsistencies,
        aggregate_text_risk=aggregate,
    )
