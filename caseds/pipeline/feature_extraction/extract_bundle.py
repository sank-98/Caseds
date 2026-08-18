from caseds.models.schemas import FeatureBundle, NormalizedInput
from caseds.pipeline.feature_extraction import (
    behavioral_features,
    sender_features,
    text_features,
    url_features,
)


def extract_bundle(normalized: NormalizedInput) -> FeatureBundle:
    return FeatureBundle(
        text=text_features.extract(normalized),
        urls=url_features.extract(normalized),
        sender=sender_features.extract(normalized),
        behavioral=behavioral_features.extract(normalized),
    )
