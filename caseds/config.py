from dataclasses import dataclass

@dataclass
class NLPConfig:
    # Define the parameters for NLPConfig
    param: str
    
@dataclass
class URLConfig:
    # Define the parameters for URLConfig
    url: str
    
@dataclass
class SenderConfig:
    # Define the parameters for SenderConfig
    sender_email: str
    
@dataclass
class Settings:
    nlp: NLPConfig
    url: URLConfig
    sender: SenderConfig