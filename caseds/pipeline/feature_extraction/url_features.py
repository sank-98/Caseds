import ipaddress
import math
from collections import Counter
from urllib.parse import urlparse

from caseds.config import settings
from caseds.models.schemas import NormalizedInput, URLFeatures


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc.lower()


def _is_ip(domain: str) -> bool:
    host = domain.split(":")[0]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract(normalized: NormalizedInput) -> list[URLFeatures]:
    metadata = normalized.raw_metadata or {}
    redirect_chains = metadata.get("redirect_chains", {})
    vt_scores = metadata.get("virustotal_scores", {})
    domain_ages = metadata.get("domain_age_days", {})

    results: list[URLFeatures] = []
    for original_url in normalized.extracted_urls:
        domain = _extract_domain(original_url)
        lowered = original_url.lower()
        shortener = domain in settings.url.shortener_domains
        entropy = _entropy(domain + lowered)
        suspicious_tld = any(domain.endswith(tld) for tld in settings.url.suspicious_tlds)
        has_ip = _is_ip(domain)

        redirects = redirect_chains.get(original_url, [])
        vt_score = vt_scores.get(original_url)
        domain_age = domain_ages.get(domain)

        flags: list[str] = []
        if shortener:
            flags.append("shortened_url")
        if suspicious_tld:
            flags.append("suspicious_tld")
        if has_ip:
            flags.append("ip_host")
        if entropy > settings.url.high_entropy_threshold:
            flags.append("high_entropy")
        if redirects and len(redirects) > 2:
            flags.append("deep_redirect_chain")
        if vt_score is not None and vt_score >= 0.5:
            flags.append("threat_intel_hit")

        risk = min(
            1.0,
            (0.2 if shortener else 0.0)
            + (0.2 if suspicious_tld else 0.0)
            + (0.2 if has_ip else 0.0)
            + (0.15 if entropy > settings.url.high_entropy_threshold else 0.0)
            + (0.1 if len(redirects) > 2 else 0.0)
            + (float(vt_score) * 0.15 if vt_score is not None else 0.0)
            + (0.1 if domain_age is not None and domain_age < 30 else 0.0),
        )

        results.append(
            URLFeatures(
                url=original_url,
                is_shortened=shortener,
                expanded_url=redirects[-1] if redirects else None,
                domain=domain,
                domain_age_days=domain_age,
                entropy=entropy,
                url_length=len(original_url),
                suspicious_tld=suspicious_tld,
                has_ip_address=has_ip,
                redirect_chain=redirects,
                redirect_depth=len(redirects),
                virustotal_score=vt_score,
                threat_intel_flags=flags,
                url_risk_score=risk,
            )
        )

    return results
