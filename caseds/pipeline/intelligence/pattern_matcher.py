import re

from caseds.models.schemas import FeatureBundle, NormalizedInput, PatternMatch

RULES = [
    {
        "id": "PAT-001",
        "name": "Credential harvesting phrase",
        "pattern": re.compile(r"\b(verify|confirm|reset)\b.{0,30}\b(account|password|credentials?)\b", re.I),
        "severity": 0.8,
        "category": "phishing",
    },
    {
        "id": "PAT-002",
        "name": "Urgent transfer request",
        "pattern": re.compile(r"\b(wire transfer|gift card|crypto)\b", re.I),
        "severity": 0.85,
        "category": "scam",
    },
    {
        "id": "PAT-003",
        "name": "Immediate action pressure",
        "pattern": re.compile(r"\b(urgent|immediately|act now|final warning)\b", re.I),
        "severity": 0.55,
        "category": "social_engineering",
    },
]


def match_patterns(normalized: NormalizedInput, features: FeatureBundle) -> list[PatternMatch]:
    text = f"{normalized.subject}\n{normalized.body}"
    matches: list[PatternMatch] = []

    for rule in RULES:
        found = rule["pattern"].search(text)
        if not found:
            continue
        matches.append(
            PatternMatch(
                rule_id=rule["id"],
                rule_name=rule["name"],
                matched_text=found.group(0),
                severity=rule["severity"],
                category=rule["category"],
            )
        )

    if any(u.has_ip_address for u in features.urls):
        matches.append(
            PatternMatch(
                rule_id="PAT-004",
                rule_name="IP address URL",
                matched_text="ip_address_detected",
                severity=0.65,
                category="url_anomaly",
            )
        )

    return matches
