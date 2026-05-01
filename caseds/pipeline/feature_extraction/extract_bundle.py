from features import text_features, url_features, sender_features, behavioral_features

def extract_bundle(normalized: NormalizedInput) -> FeatureBundle:
    # Call each feature extraction method
    text_features_result = text_features.extract(normalized)
    url_features_result = url_features.extract(normalized)
    sender_features_result = sender_features.extract(normalized)
    behavioral_features_result = behavioral_features.extract(normalized)

    # Combine results into a FeatureBundle
    return FeatureBundle(
        text=text_features_result,
        url=url_features_result,
        sender=sender_features_result,
        behavioral=behavioral_features_result
    )