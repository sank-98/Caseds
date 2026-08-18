from __future__ import annotations

from typing import Dict

from caseds.config import settings
from caseds.models.schemas import Classification, ClassificationResult, FeatureBundle, NormalizedInput


class _TransformerClassifier:
    def __init__(self) -> None:
        self._pipeline = None

    def _load(self):
        if self._pipeline is not None:
            return self._pipeline

        from transformers import pipeline  # imported lazily

        self._pipeline = pipeline(
            "zero-shot-classification",
            model=settings.nlp.transformer_model,
        )
        return self._pipeline

    def classify(self, text: str) -> Dict[str, float]:
        model = self._load()
        result = model(text, candidate_labels=settings.nlp.candidate_labels, truncation=True)
        raw_scores = dict(zip(result["labels"], result["scores"]))
        return {
            "phishing": float(raw_scores.get("phishing attack", 0.0)),
            "impersonation": float(raw_scores.get("impersonation fraud", 0.0)),
            "scam": float(raw_scores.get("financial scam", 0.0)),
            "benign": float(raw_scores.get("legitimate communication", 0.0)),
        }


_transformer = _TransformerClassifier()


def _heuristic_classify(text: str, features: FeatureBundle) -> Dict[str, float]:
    lowered = text.lower()
    phishing_terms = ["verify", "password", "account", "login", "reset", "suspended"]
    impersonation_terms = ["ceo", "finance", "it support", "security team", "executive"]
    scam_terms = ["lottery", "gift card", "wire transfer", "crypto", "investment", "refund"]

    phishing = sum(1 for t in phishing_terms if t in lowered) * 0.12 + (features.text.urgency_score * 0.2)
    impersonation = sum(1 for t in impersonation_terms if t in lowered) * 0.12 + (
        0.25 if features.sender.lookalike_domain_detected else 0.0
    )
    scam = sum(1 for t in scam_terms if t in lowered) * 0.14 + (features.text.emotional_manipulation_score * 0.15)

    max_non_benign = min(1.0, max(phishing, impersonation, scam))
    benign = max(0.0, 1.0 - (max_non_benign * 0.9))

    return {
        "phishing": min(1.0, phishing),
        "impersonation": min(1.0, impersonation),
        "scam": min(1.0, scam),
        "benign": benign,
    }


def _resolve_top_class(scores: Dict[str, float]) -> tuple[Classification, float]:
    top_label = max(scores.items(), key=lambda item: item[1])[0]
    top_score = float(scores[top_label])
    mapping = {
        "phishing": Classification.PHISHING,
        "impersonation": Classification.IMPERSONATION,
        "scam": Classification.SCAM,
        "benign": Classification.BENIGN,
    }
    return mapping[top_label], max(0.0, min(1.0, top_score))


def classify(normalized: NormalizedInput, features: FeatureBundle) -> ClassificationResult:
    text = f"{normalized.subject}\n{normalized.body}".strip()

    method = "heuristic"
    try:
        if settings.nlp.use_transformer and text:
            scores = _transformer.classify(text)
            method = "transformer"
        else:
            scores = _heuristic_classify(text, features)
    except Exception:
        scores = _heuristic_classify(text, features)

    top_class, confidence = _resolve_top_class(scores)

    return ClassificationResult(
        phishing=scores["phishing"],
        impersonation=scores["impersonation"],
        scam=scores["scam"],
        benign=scores["benign"],
        top_class=top_class,
        confidence=confidence,
        method=method,
    )
