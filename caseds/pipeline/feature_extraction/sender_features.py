class NormalizedInput:
    def __init__(self, data):
        self.data = data


class SenderFeatures:
    def __init__(self, feature_dict):
        self.feature_dict = feature_dict


def extract(normalized: NormalizedInput) -> SenderFeatures:
    # Implementing schema-first feature extraction
    features = {
        'feature_a': normalized.data.get('feature_a', None),
        'feature_b': normalized.data.get('feature_b', None),
        # Add other feature extractions here
    }
    return SenderFeatures(features)