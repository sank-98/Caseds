class NormalizedInput:
    def __init__(self, data):
        self.data = data

class BehavioralFeatures:
    def __init__(self, features):
        self.features = features

    @staticmethod
    def extract(normalized: NormalizedInput) -> 'BehavioralFeatures':
        # Example schema-first extraction process
        extracted_features = {}  # Dictionary to hold extracted features

        # Implement your feature extraction logic here
        # For example:
        extracted_features['feature_1'] = normalized.data.get('input_field_1', 0) * 2
        extracted_features['feature_2'] = normalized.data.get('input_field_2', 0) + 3

        return BehavioralFeatures(features=extracted_features)