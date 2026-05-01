class SenderFeatures:
    def __init__(self, normalized_input, settings):
        self.email = normalized_input.sender_email
        self.display_name = normalized_input.sender_display_name
        self.headers = normalized_input.email_headers
        self.settings = settings
        self.reputation_score = 0.5
        self.sender_risk_score = self.aggregate_risk_score()
        self.spf_valid = self.heuristic_spf_check()
        self.dkim_valid = self.heuristic_dkim_check()
        self.dmarc_valid = self.heuristic_dmarc_check()
        self.free_email_provider = self.detect_free_email_provider()
        self.display_name_mismatch = self.detect_display_name_mismatch()
        self.lookalike_domain_detected, self.lookalike_target = self.detect_lookalike_domain()

    def heuristic_spf_check(self):
        if 'spf' in self.headers:
            return self.headers['spf'].lower() == 'pass'
        return False

    def heuristic_dkim_check(self):
        if 'dkim' in self.headers:
            return self.headers['dkim'].lower() == 'pass'
        return False

    def heuristic_dmarc_check(self):
        if 'dmarc' in self.headers:
            return self.headers['dmarc'].lower() == 'pass'
        return False

    def detect_free_email_provider(self):
        domain = self.email.split('@')[-1]
        return domain in self.settings.sender.free_email_providers

    def detect_display_name_mismatch(self):
        # Logic to detect display name mismatch
        if self.display_name:
            name_domain = self.display_name.split()[-1]
            email_domain = self.email.split('@')[-1]
            return name_domain.lower() != email_domain.lower()
        return False

    def detect_lookalike_domain(self):
        email_domain = self.email.split('@')[-1]
        for target in self.settings.sender.impersonation_targets:
            if email_domain == target:
                return True, target
        return False, None

    def aggregate_risk_score(self):
        # Logic to compute aggregate risk score
        return self.reputation_score  # Replace with real aggregation logic