from caseds.config import settings
from caseds.models.schemas import URLFeatureExtraction

class URLFeatures:
    def __init__(self):
        self.extracted_urls = []  # Placeholder for normalized input URLs

    def extract_features(self, url):
        # Constants
        shortener_domains = settings.url.shortener_domains
        suspicious_tlds = settings.url.suspicious_tlds

        # Extract hostname and path from URL
        parsed_url = self.parse_url(url)
        hostname = parsed_url['hostname']
        path = parsed_url['path']

        # Feature extraction
        features = {
            'url_length': len(url),
            'has_ip_address': self.has_ip_address(hostname),
            'redirect_chain': [],  # No call due to external dependency
            'redirect_depth': 0,
            'virustotal_score': None,
            'threat_intel_flags': [],
            'impact_severity': self.impact_severity_heuristic(url),
            'url_risk_score': self.calculate_url_risk(),
            'suspicious_tld': self.is_suspicious_tld(hostname, suspicious_tlds),
            'is_shortener': self.is_url_shortener(url, shortener_domains),
            'entropy': self.calculate_entropy(hostname, path)
        }
        return features

    def parse_url(self, url):
        # Dummy parsing method
        return {'hostname': 'example.com', 'path': '/path'}

    def has_ip_address(self, hostname):
        # Dummy check for IP address
        return False

    def is_suspicious_tld(self, hostname, suspicious_tlds):
        # Dummy TLD check
        return False

    def is_url_shortener(self, url, shortener_domains):
        # Dummy shortener check
        return False

    def calculate_entropy(self, hostname, path):
        # Dummy entropy calculation
        return 0.5

    def impact_severity_heuristic(self, url):
        # Dummy heuristic
        return 'low'

    def calculate_url_risk(self):
        # Dummy aggregation for risk score
        return 0.1
