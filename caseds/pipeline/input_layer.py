import re
import uuid
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

from caseds.models.schemas import RawInput, NormalizedInput

URL_PATTERN = re.compile(
    r"(https?:\/\/[^\0-\u0020.,;:')\]]+|ftp:\/\/[^\0-\u0020.,;:')\]]+|www\.[^\0-\u0020.,;:')\]]+)",
    re.IGNORECASE,
)

TRAILING_PUNCTUATION = '.,;:\"')\]]'


class InputNormalizer:
    '''Layer 1: Input normalization.

    - Ensures body is never None
    - Extracts + validates URLs from body/subject/explicit list
    - Deduplicates URLs preserving order
    - Defaults timestamp to UTC now when missing
    - Adds analysis_id (uuid4) into raw_metadata
    '''

    def extract_urls(self, raw: RawInput) -> List[str]:
        candidates: List[str] = []

        if raw.body:
            candidates.extend(URL_PATTERN.findall(raw.body))
        if raw.subject:
            candidates.extend(URL_PATTERN.findall(raw.subject))
        if raw.urls:
            candidates.extend(raw.urls)

        seen: set[str] = set()
        extracted: List[str] = []

        for candidate in candidates:
            if not candidate:
                continue
            u = candidate.rstrip(TRAILING_PUNCTUATION)

            # For bare www.* URLs, urlparse needs a scheme to parse netloc.
            to_parse = u
            if u.lower().startswith("www."):
                to_parse = "http://" + u

            parsed = urlparse(to_parse)
            if not parsed.scheme or not parsed.netloc:
                continue

            # Keep the original form (without the injected scheme).
            final_u = u

            # Deduplicate by a normalized key (lower host + path + query).
            key = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}{('?' + parsed.query) if parsed.query else ''}"
            if key in seen:
                continue
            seen.add(key)
            extracted.append(final_u)

        return extracted

    def normalize(self, raw: RawInput) -> NormalizedInput:
        analysis_id = str(uuid.uuid4())

        return NormalizedInput(
            input_type=raw.input_type,
            body=raw.body or "",
            subject=raw.subject or "",
            sender=raw.sender or "",
            recipient=raw.recipient or "",
            timestamp=raw.timestamp or datetime.now(timezone.utc),
            extracted_urls=self.extract_urls(raw),
            email_headers=raw.email_headers,
            attachments=raw.attachments or [],
            user_id=raw.user_id,
            raw_metadata={
                "analysis_id": analysis_id,
                "input_type": raw.input_type.value,
            },
        )


# Module-level singleton
normalizer = InputNormalizer()