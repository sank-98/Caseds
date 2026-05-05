from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# CORS configurations
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Pydantic models
class RawInput(BaseModel):
    # Define attributes according to caseds.models.schemas.RawInput
    pass

class HealthResponse(BaseModel):
    status: str = "OK"

class ThreatAnalysisResponse(BaseModel):
    threat_score: int
    risk_level: str
    classification: str
    recommended_action: str
    predicted_impact: str
    score_breakdown: dict
    triggered_indicators: list
    url_analysis: dict
    pattern_matches: list
    analysis_id: str
    processing_time_ms: int

@app.post("/analyze", response_model=ThreatAnalysisResponse)
def analyze(raw: RawInput):
    from caseds.pipeline.input_layer.normalizer import normalize
    from caseds.pipeline.feature_extraction import extract_bundle
    from caseds.pipeline.scoring import score
    
    # Normalize input
    normalized = normalize(raw)
    # Extract features
    features = extract_bundle(normalized)
    # Score the analysis
    analysis_result = score(normalized)
    return analysis_result

@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse()