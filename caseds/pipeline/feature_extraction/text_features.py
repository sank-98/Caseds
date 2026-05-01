"""Text feature extraction for CASEDS.

Produces TextFeatures from NormalizedInput.
Heuristics are intentionally lightweight and dependency-free.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Tuple

from caseds.models.schemas import NormalizedInput, TextFeatures


# --- Lexicons (small starter lists; tune via future config if desired) ---
URGENCY_PHRASES = [
    "urgent",
    "immediately",
    "asap",
    "act now",
    "within 24 hours",
    "account will be closed",
    "verify now",
    "limited time",
]

AUTHORITY_CUES = [
    "support team",
    "security team",
    "administrator",
    "it department",
    "compliance",
    "bank",
    "irs",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "paypal",
]

EMOTIONAL_MANIPULATION = [
    "congratulations",
    "winner",
    "claim",
    "refund",
    "suspended",
    "locked",
    "unauthorized",
    "fraud",
    "problem with your account",
]

# Obfuscation / evasion patterns
OBFUSCATION_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("zero_width_chars", re.compile(r"[\u200B-\u200D\uFEFF]")),
    ("homoglyph_like", re.compile(r"[Il1O0]{3,}")),
    ("excess_punctuation", re.compile(r"[.!?]{3,}")),
    ("spaced_words", re.compile(r"\b(?:[A-Za-z]\s+){4,}[A-Za-z]\b")),
    ("mixed_script", re.compile(r"[A-Za-z].*[\u0400-\u04FF]|[\u0400-\u04FF].*[A-Za-z]")),
]

LANGUAGE_INCONSISTENCY_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("too_many_typos_like", re.compile(r"\b(?:teh|adn|verifcation|securrity)\b", re.IGNORECASE)),
    ("all_caps_words", re.compile(r"\b[A-Z]{6,}\b")),
]

# Basic entity-ish patterns (dependency-free)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
MONEY_RE = re.compile(r"(?:\$|USD\s?)[0-9]+(?:\.[0-9]{2})?", re.IGNORECASE)
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")


def _safe_lower(s: str) -> str:
    return (s or "").lower()


def _phrase_hits(text_l: str, phrases: List[str]) -> List[str]:
    hits: List[str] = []
    for p in phrases:
        if p in text_l:
            hits.append(p)
    return hits


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _perplexity_proxy(text: str) -> float:
    """A cheap proxy for "weirdness".

    We approximate perplexity by (entropy over characters) scaled by average token length.
    It's not true LM perplexity, but works as a heuristic signal.
    """
    t = text.strip()
    if not t:
        return 0.0
    tokens = re.findall(r"\w+", t)
    avg_len = (sum(len(x) for x in tokens) / len(tokens)) if tokens else 0.0
    return _shannon_entropy(t) * (1.0 + min(avg_len, 12.0) / 12.0)


def _bounded(score: float) -> float:
    return max(0.0, min(1.0, score))


class TextFeatureExtractor:
    def extract(self, n: NormalizedInput) -> TextFeatures:
        text = " ".join([n.subject or "", n.body or ""]).strip()
        text_l = text.lower()

        urgency_hits = _phrase_hits(text_l, URGENCY_PHRASES)
        authority_hits = _phrase_hits(text_l, AUTHORITY_CUES)
        emotional_hits = _phrase_hits(text_l, EMOTIONAL_MANIPULATION)

        # Score components (0..1)
        urgency_score = _bounded(len(urgency_hits) / 4.0)
        authority_score = _bounded(len(authority_hits) / 4.0)
        emotional_score = _bounded(len(emotional_hits) / 4.0)

        obfuscation_indicators: List[str] = []
        for name, pat in OBFUSCATION_PATTERNS:
            if pat.search(text):
                obfuscation_indicators.append(name)

        language_inconsistencies: List[str] = []
        for name, pat in LANGUAGE_INCONSISTENCY_PATTERNS:
            if pat.search(text):
                language_inconsistencies.append(name)

        # Named entities (very lightweight; represent as {type, value})
        named_entities = []
        for m in EMAIL_RE.findall(text):
            named_entities.append({"type": "email", "value": m})
        for m in MONEY_RE.findall(text):
            named_entities.append({"type": "money", "value": m})
        for m in PHONE_RE.findall(text):
            named_entities.append({"type": "phone", "value": m})

        perplexity_score = _perplexity_proxy(text)
        # Map proxy (0..~8) to 0..1
        perplexity_norm = _bounded(perplexity_score / 8.0)

        # Aggregate risk (simple weighted avg)
        aggregate = _bounded(
            0.30 * urgency_score
            + 0.25 * authority_score
            + 0.25 * emotional_score
            + 0.10 * (1.0 if obfuscation_indicators else 0.0)
            + 0.10 * perplexity_norm
        )

        return TextFeatures(
            urgency_score=urgency_score,
            authority_score=authority_score,
            emotional_manipulation_score=emotional_score,
            perplexity_score=perplexity_norm,
            named_entities=named_entities,
            urgency_phrases=urgency_hits,
            authority_cues=authority_hits,
            obfuscation_indicators=obfuscation_indicators,
            language_inconsistencies=language_inconsistencies,
            aggregate_text_risk=aggregate,
        )


extractor = TextFeatureExtractor()