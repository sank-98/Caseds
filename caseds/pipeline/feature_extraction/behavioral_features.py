class BehavioralFeatures:
    def __init__(self, normalized_input):
        self.is_known_sender = False
        self.anomalies = False
        self.message_style_deviation = 0.0
        self.request_type_unusual = False
        self.behavioral_risk_score = self.compute_risk_score(normalized_input)

        # Use normalized input to set known sender and anomalies
        self.set_features(normalized_input)

    def set_features(self, normalized_input):
        if 'prior_sender_frequency' in normalized_input:
            self.is_known_sender = True  # or some logic to derive.
        if 'known_senders' in normalized_input:
            self.is_known_sender = True  # or some logic to derive.
        # Logic for anomalies can be added here.

    def compute_risk_score(self, normalized_input):
        # Risk logic based on booleans
        risk_score = (1 if self.is_known_sender else 0) +
                     (1 if self.anomalies else 0) +
                     (1 if self.message_style_deviation > 0.0 else 0) +
                     (1 if self.request_type_unusual else 0)
        return risk_score
