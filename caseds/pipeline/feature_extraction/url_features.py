from typing import List

class NormalizedInput:
    def __init__(self, url: str):
        self.url = url

class URLFeatures:
    def __init__(self, url: str):
        self.url = url
        self.is_secure = url.startswith('https://')
        self.domain = url.split('/')[2] if len(url.split('/')) > 2 else ''
        self.path = '/'.join(url.split('/')[3:])

    def __repr__(self):
        return f"URLFeatures(url={self.url}, is_secure={self.is_secure}, domain={self.domain}, path={self.path})"


def extract(normalized: NormalizedInput) -> List[URLFeatures]:
    url_features = URLFeatures(normalized.url)
    return [url_features]